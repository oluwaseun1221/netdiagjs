#!/usr/bin/env node
/**
 * netdiag.mjs - first-line network troubleshooting for staff computers (INTECU).
 *
 * Runs layered checks (local address -> gateway -> DNS -> destination -> quality),
 * prints a plain-English verdict for staff and saves a technical report
 * (text + JSON) for IT.
 *
 * Requires Node.js 20+ and nothing else (built-in modules only, no npm install).
 *
 *   node netdiag.mjs                  staff view
 *   node netdiag.mjs -v               IT view: details + raw command output
 *   node netdiag.mjs --ui             local web dashboard (opens your browser)
 *   node netdiag.mjs --init-config    write a sample netdiag.config.json
 *   node netdiag.mjs --selftest       verify the parsers (works on any OS)
 *
 * Exit codes: 0 healthy, 1 warnings, 2 failure, 3 internal error.
 */
import { execFile } from 'node:child_process';
import { randomBytes, randomInt } from 'node:crypto';
import dgram from 'node:dgram';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import readline from 'node:readline/promises';
import { domainToASCII, fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import assert from 'node:assert/strict';

const VERSION = '1.0.0';
const IS_WIN = process.platform === 'win32';
const IS_MAC = process.platform === 'darwin';
const IPV4 = String.raw`\d{1,3}(?:\.\d{1,3}){3}`;
const IPV4_RE = new RegExp(IPV4, 'g');

export const Status = Object.freeze({ PASS: 'pass', WARN: 'warn', FAIL: 'fail', INFO: 'info', SKIP: 'skip' });

// --------------------------------------------------------------------------- //
// Configuration
// --------------------------------------------------------------------------- //
const DEFAULT_CONFIG = Object.freeze({
  destinationHost: 'example.com', // something staff are always allowed to reach
  destinationPort: 443,
  dnsTestHostname: '', // blank = use destinationHost
  publicResolvers: ['1.1.1.1', '8.8.8.8'],
  pingCount: 10,
  gatewayPingCount: 4,
  lossWarnPct: 5,
  lossFailPct: 50,
  latencyWarnMs: 150,
  gatewayLatencyWarnMs: 30,
  tcpTimeout: 4, // seconds
  dnsTimeout: 3, // seconds
  httpProbe: true,
  traceOnFailure: true,
  traceMaxHops: 15,
  reportDir: 'reports',
});

const appDir = () => path.dirname(fileURLToPath(import.meta.url));

function loadConfig(explicitPath) {
  const cfg = structuredClone(DEFAULT_CONFIG);
  const candidates = explicitPath
    ? [explicitPath]
    : [path.join(appDir(), 'netdiag.config.json'), path.join(process.cwd(), 'netdiag.config.json')];
  for (const p of candidates) {
    if (!fs.existsSync(p)) continue;
    const data = JSON.parse(fs.readFileSync(p, 'utf8'));
    for (const [key, value] of Object.entries(data)) {
      if (key.startsWith('_')) continue; // comments
      if (!(key in cfg)) {
        console.error(`warning: unknown setting '${key}' in ${p}`);
        continue;
      }
      const t = typeof cfg[key];
      cfg[key] = t === 'number' ? Number(value) : t === 'boolean' ? Boolean(value) : value;
    }
    return [cfg, p];
  }
  if (explicitPath) throw new Error(`config file not found: ${explicitPath}`);
  return [cfg, 'built-in defaults'];
}

const sampleConfig = () =>
  JSON.stringify(
    {
      _help: 'netdiag settings - all optional. Set destinationHost to an address staff are always allowed to reach.',
      ...DEFAULT_CONFIG,
    },
    null,
    2,
  ) + '\n';

// --------------------------------------------------------------------------- //
// Small helpers
// --------------------------------------------------------------------------- //
const ms = (t0) => Math.round((performance.now() - t0) * 10) / 10;
const sleep = (n) => new Promise((r) => setTimeout(r, n));
const round1 = (n) => Math.round(n * 10) / 10;
const mean = (a) => a.reduce((s, x) => s + x, 0) / a.length;
const pstdev = (a) => Math.sqrt(mean(a.map((x) => (x - mean(a)) ** 2)));

function withTimeout(promise, timeoutMs) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timed out')), timeoutMs);
    promise.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e); },
    );
  });
}

/** Run a command (argument array, never a shell). Never rejects. */
function runCmd(file, args, timeoutMs = 15000) {
  return new Promise((resolve) => {
    execFile(
      file,
      args,
      { timeout: timeoutMs, windowsHide: true, maxBuffer: 8 * 1024 * 1024, encoding: 'utf8' },
      (err, stdout, stderr) => {
        const out = `${stdout ?? ''}${stderr ?? ''}`;
        if (!err) return resolve({ code: 0, output: out });
        if (err.code === 'ENOENT') return resolve({ code: -2, output: `[command not found: ${file}]` });
        if (err.killed) {
          return resolve({ code: -1, output: `${out}\n[timed out after ${Math.round(timeoutMs / 1000)}s: ${file} ${args.join(' ')}]` });
        }
        resolve({ code: typeof err.code === 'number' ? err.code : -3, output: out || `[could not run ${file}: ${err.message}]` });
      },
    );
  });
}

const make = (id, title, status, summary, t0, details = {}, raw = '') => ({
  id, title, status, summary, details, raw, durationMs: t0 === undefined ? 0 : ms(t0),
});
const skipped = (id, title, reason) => make(id, title, Status.SKIP, reason);

// --------------------------------------------------------------------------- //
// Parsers (pure functions - covered by --selftest)
// --------------------------------------------------------------------------- //
/** `route print -4 0.0.0.0` - locale-proof, only numbers matter. */
export function parseRoutesWindows(text) {
  const re = new RegExp(String.raw`^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(${IPV4})\s+(${IPV4})\s+(\d+)`, 'gm');
  return [...text.matchAll(re)]
    .map((m) => ({ gateway: m[1], interfaceIp: m[2], metric: Number(m[3]), iface: '' }))
    .sort((a, b) => a.metric - b.metric);
}

export function parseRoutesLinux(text) {
  const routes = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(new RegExp(String.raw`^\s*default via (${IPV4}) dev (\S+)`));
    if (m) routes.push({ gateway: m[1], interfaceIp: '', metric: Number(line.match(/metric (\d+)/)?.[1] ?? 0), iface: m[2] });
  }
  return routes.sort((a, b) => a.metric - b.metric);
}

export function parseRouteMacos(text) {
  const gw = text.match(new RegExp(String.raw`gateway:\s*(${IPV4})`));
  const ifc = text.match(/interface:\s*(\S+)/);
  return gw ? [{ gateway: gw[1], interfaceIp: '', metric: 0, iface: ifc?.[1] ?? '' }] : [];
}

/** Parse `ipconfig /all`. Labels are localised, so only 'ipv4' / 'dns' keywords are used. */
export function parseIpconfig(text) {
  const adapters = [];
  let cur = null;
  let collectingDns = false;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    if (!/^[ \t]/.test(line) && line.trimEnd().endsWith(':')) {
      cur = { name: line.trim().replace(/:$/, ''), ipv4: [], dns: [] };
      adapters.push(cur);
      collectingDns = false;
      continue;
    }
    if (!cur) continue;
    if (/\s:(?:\s|$)/.test(line)) {
      const idx = line.indexOf(' :');
      const label = line.slice(0, idx).toLowerCase();
      const ips = line.slice(idx + 2).match(IPV4_RE) ?? [];
      collectingDns = false;
      if (label.includes('dns')) {
        cur.dns.push(...ips);
        collectingDns = true;
      } else if (label.includes('ipv4')) {
        cur.ipv4.push(...ips);
      }
    } else if (collectingDns && new RegExp(`^${IPV4}$`).test(line.trim())) {
      cur.dns.push(line.trim());
    }
  }
  return adapters;
}

/** Count real replies by their 'TTL=' field (not localised) and read 'time=Xms'. */
export function parsePing(text, sent) {
  const times = [];
  let received = 0;
  for (const line of text.split(/\r?\n/)) {
    if (/\bttl[=:]\s*\d+/i.test(line)) {
      received++;
      const m = line.match(/[=<]\s*(\d+(?:[.,]\d+)?)\s*ms/);
      if (m) times.push(parseFloat(m[1].replace(',', '.')));
    }
  }
  return { sent, received: Math.min(received, sent), times };
}

export function pingSummary(p) {
  const t = p.times;
  return {
    lossPct: p.sent ? round1((100 * (p.sent - p.received)) / p.sent) : 100,
    min: t.length ? Math.min(...t) : null,
    avg: t.length ? round1(mean(t)) : null,
    max: t.length ? Math.max(...t) : null,
    jitter: t.length > 1 ? round1(pstdev(t)) : null,
  };
}

export function parseTrace(text) {
  const hops = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*(\d{1,2})\s+(.*)$/);
    if (m) hops.push({ n: Number(m[1]), ip: m[2].match(IPV4_RE)?.[0] ?? null });
  }
  return hops;
}

// --------------------------------------------------------------------------- //
// DNS over raw UDP (lets us test each DNS server separately, in any language)
// --------------------------------------------------------------------------- //
const RCODES = { 1: 'format error', 2: 'server failure', 3: 'name does not exist', 5: 'refused' };

export function buildDnsQuery(name) {
  const qid = randomInt(65536);
  const ascii = domainToASCII(name.replace(/\.$/, ''));
  if (!ascii) throw new Error('invalid host name');
  const parts = [];
  for (const label of ascii.split('.')) {
    const b = Buffer.from(label, 'ascii');
    parts.push(Buffer.from([b.length]), b);
  }
  parts.push(Buffer.from([0]));
  const header = Buffer.alloc(12);
  header.writeUInt16BE(qid, 0);
  header.writeUInt16BE(0x0100, 2); // recursion desired
  header.writeUInt16BE(1, 4); // one question
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(1, 0); // type A
  tail.writeUInt16BE(1, 2); // class IN
  return { qid, packet: Buffer.concat([header, ...parts, tail]) };
}

function skipName(buf, pos) {
  for (;;) {
    const len = buf[pos];
    if (len === undefined) throw new RangeError('truncated reply');
    if (len === 0) return pos + 1;
    if ((len & 0xc0) === 0xc0) return pos + 2;
    pos += len + 1;
  }
}

export function parseDnsResponse(buf, qid) {
  if (buf.length < 12) throw new Error('reply too short');
  if (buf.readUInt16BE(0) !== qid) throw new Error('reply id mismatch');
  const flags = buf.readUInt16BE(2);
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  let pos = 12;
  for (let i = 0; i < qd; i++) pos = skipName(buf, pos) + 4;
  const ips = [];
  for (let i = 0; i < an; i++) {
    pos = skipName(buf, pos);
    const type = buf.readUInt16BE(pos);
    const rdlen = buf.readUInt16BE(pos + 8);
    pos += 10;
    if (type === 1 && rdlen === 4) ips.push([...buf.subarray(pos, pos + 4)].join('.'));
    pos += rdlen;
  }
  return { rcode: flags & 0xf, ips };
}

function dnsQuery(server, name, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = performance.now();
    let built;
    try {
      built = buildDnsQuery(name);
    } catch (e) {
      return resolve({ responded: false, ips: [], ms: 0, error: e.message });
    }
    let done = false;
    let timer;
    const sock = dgram.createSocket('udp4');
    const finish = (r) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.close(); } catch { /* already closed */ }
      resolve(r);
    };
    timer = setTimeout(() => finish({ responded: false, ips: [], ms: ms(t0), error: 'no answer (timed out)' }), timeoutMs);
    sock.on('error', (e) => finish({ responded: false, ips: [], ms: ms(t0), error: e.message }));
    sock.on('message', (msg) => {
      try {
        const { rcode, ips } = parseDnsResponse(msg, built.qid);
        finish({ responded: true, ips, ms: ms(t0), error: ips.length ? '' : RCODES[rcode] ?? `no address returned (rcode ${rcode})` });
      } catch (e) {
        finish({ responded: false, ips: [], ms: ms(t0), error: e.message });
      }
    });
    sock.send(built.packet, 53, server, (err) => {
      if (err) finish({ responded: false, ips: [], ms: ms(t0), error: err.message });
    });
  });
}

/** What applications really use (OS resolver, hosts file, DNS suffixes...). */
async function resolveSystem(host) {
  const r = await dns.lookup(host, { family: 4, all: true });
  return [...new Set(r.map((x) => x.address))].sort();
}

// --------------------------------------------------------------------------- //
// Network state (collected once, analysed by the checks)
// --------------------------------------------------------------------------- //
function udpLocalIp() {
  /* Ask the OS which address it would use to reach the internet (sends nothing). */
  return new Promise((resolve) => {
    const s = dgram.createSocket('udp4');
    s.once('error', () => { try { s.close(); } catch { /* ignore */ } resolve(null); });
    s.connect(9, '203.0.113.1', () => {
      try {
        const a = s.address().address;
        s.close();
        resolve(a);
      } catch {
        resolve(null);
      }
    });
  });
}

function resolvConf() {
  try {
    const text = fs.readFileSync('/etc/resolv.conf', 'utf8');
    return [...text.matchAll(new RegExp(String.raw`^\s*nameserver\s+(${IPV4})`, 'gm'))].map((m) => m[1]);
  } catch {
    return [];
  }
}

async function collectState() {
  const st = { localIp: null, gateway: null, adapter: '', dnsServers: [], apipa: [], routeCount: 0, raw: '' };
  const raw = [];
  let routes = [];
  let adapters = [];

  if (IS_WIN) {
    const [ipc, rt] = await Promise.all([runCmd('ipconfig', ['/all']), runCmd('route', ['print', '-4', '0.0.0.0'])]);
    raw.push(`$ ipconfig /all\n${ipc.output}`, `$ route print -4 0.0.0.0\n${rt.output}`);
    adapters = parseIpconfig(ipc.output);
    routes = parseRoutesWindows(rt.output);
    if (routes.length) st.localIp = routes[0].interfaceIp;
  } else if (IS_MAC) {
    const rt = await runCmd('route', ['-n', 'get', 'default']);
    raw.push(`$ route -n get default\n${rt.output}`);
    routes = parseRouteMacos(rt.output);
    if (routes[0]?.iface) {
      const ip = (await runCmd('ipconfig', ['getifaddr', routes[0].iface])).output.trim();
      if (new RegExp(`^${IPV4}$`).test(ip)) st.localIp = ip;
      st.adapter = routes[0].iface;
    }
    st.dnsServers = resolvConf();
  } else {
    const rt = await runCmd('ip', ['-4', 'route', 'show', 'default']);
    raw.push(`$ ip -4 route show default\n${rt.output}`);
    routes = parseRoutesLinux(rt.output);
    if (routes.length) {
      const addr = await runCmd('ip', ['-4', '-o', 'addr', 'show', 'dev', routes[0].iface]);
      raw.push(`$ ip -4 -o addr show dev ${routes[0].iface}\n${addr.output}`);
      st.localIp = addr.output.match(new RegExp(String.raw`inet (${IPV4})/`))?.[1] ?? null;
      st.adapter = routes[0].iface;
    }
    st.dnsServers = resolvConf();
  }

  st.routeCount = routes.length;
  if (routes.length) st.gateway = routes[0].gateway;
  if (!st.localIp && routes.length) st.localIp = await udpLocalIp();

  if (adapters.length) {
    st.apipa = adapters.flatMap((a) => a.ipv4).filter((ip) => ip.startsWith('169.254.'));
    const mine = adapters.find((a) => st.localIp && a.ipv4.includes(st.localIp));
    if (mine) {
      st.adapter = mine.name;
      st.dnsServers = [...new Set(mine.dns)];
    } else if (!st.dnsServers.length) {
      st.dnsServers = [...new Set(adapters.flatMap((a) => a.dns))];
    }
  }
  st.raw = raw.join('\n\n');
  return st;
}

// --------------------------------------------------------------------------- //
// Probes
// --------------------------------------------------------------------------- //
function tcpProbe(host, port, timeoutSec) {
  return new Promise((resolve) => {
    const t0 = performance.now();
    let settled = false;
    let timer;
    const sock = net.createConnection({ host, port });
    const end = (ok, error = '') => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      resolve({ ok, ms: ms(t0), error });
    };
    timer = setTimeout(() => end(false, 'timed out'), timeoutSec * 1000);
    sock.once('connect', () => end(true));
    sock.once('error', (e) => end(false, e.message || e.code));
  });
}

async function pingHost(host, count, waitS = 1) {
  let args;
  if (IS_WIN) args = ['-n', String(count), '-w', String(waitS * 1000), host];
  else if (IS_MAC) args = ['-c', String(count), '-W', String(waitS * 1000), host];
  else args = ['-c', String(count), '-W', String(waitS), host];
  const res = await runCmd('ping', args, (count * (waitS + 1) + 10) * 1000);
  return { stats: parsePing(res.output, count), raw: res.output };
}

function httpProbe(host, port, timeoutSec) {
  return new Promise((resolve) => {
    if (port !== 443 && port !== 80) return resolve({ skipped: true });
    const t0 = performance.now();
    const lib = port === 443 ? https : http;
    const req = lib.request(
      { host, port, method: 'HEAD', path: '/', timeout: timeoutSec * 1000, headers: { 'User-Agent': `netdiag/${VERSION}`, Connection: 'close' } },
      (res) => {
        res.resume();
        resolve({ status: res.statusCode, location: res.headers.location ?? '', ms: ms(t0) });
      },
    );
    req.on('timeout', () => req.destroy(new Error('timed out')));
    req.on('error', (e) => {
      if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ALTNAME/i.test(e.code ?? '')) {
        resolve({ error: `certificate not trusted (${e.code})`, cert: true });
      } else {
        resolve({ error: e.message || e.code || 'request failed' });
      }
    });
    req.end();
  });
}

// --------------------------------------------------------------------------- //
// Checks
// --------------------------------------------------------------------------- //
function proxySettings() {
  const env = {};
  for (const k of ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']) if (process.env[k]) env[k] = process.env[k];
  return Object.keys(env).length ? env : 'none';
}

function checkSystem() {
  const t0 = performance.now();
  const details = {
    hostname: os.hostname(),
    user: os.userInfo().username,
    os: `${os.type()} ${os.release()} (${os.arch()})`,
    node: process.version,
    proxySettings: proxySettings(),
  };
  return make('system', 'System', Status.INFO, `${details.hostname} - ${os.type()} ${os.release()}`, t0, details);
}

function checkLocalIp(st) {
  const t0 = performance.now();
  const details = { ip: st.localIp, adapter: st.adapter, apipaAddresses: st.apipa };
  if (st.localIp?.startsWith('169.254.')) {
    details.apipa = true;
    return make('local_ip', 'Local IP address', Status.FAIL,
      `${st.localIp} is a self-assigned address - the network did not give this PC an address (DHCP failed)`, t0, details, st.raw);
  }
  if (!st.localIp) {
    if (st.apipa.length) {
      details.apipa = true;
      return make('local_ip', 'Local IP address', Status.FAIL,
        `Only a self-assigned address (${st.apipa[0]}) - DHCP failed`, t0, details, st.raw);
    }
    return make('local_ip', 'Local IP address', Status.FAIL, 'No active network connection (no IPv4 address)', t0, details, st.raw);
  }
  return make('local_ip', 'Local IP address', Status.PASS, `${st.localIp}${st.adapter ? ` on ${st.adapter}` : ''}`, t0, details);
}

function checkGatewayConfig(st) {
  const t0 = performance.now();
  const details = { gateway: st.gateway, defaultRoutes: st.routeCount };
  if (!st.gateway) {
    return make('gateway', 'Default gateway', Status.FAIL,
      'No default gateway configured - this PC has no route to other networks', t0, details);
  }
  return make('gateway', 'Default gateway', Status.PASS, st.gateway, t0, details);
}

async function checkWifi() {
  if (!IS_WIN) return null;
  const t0 = performance.now();
  const res = await runCmd('netsh', ['wlan', 'show', 'interfaces']);
  const ssid = res.output.match(/^\s*SSID\s*:\s*(.+?)\s*$/m);
  if (!ssid) return make('wifi', 'Wi-Fi signal', Status.SKIP, 'Not connected over Wi-Fi', t0, {}, res.output);
  const sig = res.output.match(/(\d{1,3})\s*%/);
  const signal = sig ? Number(sig[1]) : null;
  const details = { ssid: ssid[1], signalPct: signal };
  if (signal !== null && signal < 40) {
    return make('wifi', 'Wi-Fi signal', Status.WARN, `Weak signal (${signal}%) on '${ssid[1]}'`, t0, details, res.output);
  }
  return make('wifi', 'Wi-Fi signal', Status.PASS, `'${ssid[1]}'${signal !== null ? `, signal ${signal}%` : ''}`, t0, details, res.output);
}

async function checkGatewayPing(cfg, st) {
  const t0 = performance.now();
  const { stats, raw } = await pingHost(st.gateway ?? '', cfg.gatewayPingCount);
  const s = pingSummary(stats);
  const details = { lossPct: s.lossPct, avgMs: s.avg, maxMs: s.max };
  if (stats.received === 0) {
    return make('gateway_ping', 'Gateway reachable', Status.FAIL, `No reply from ${st.gateway} (0 of ${stats.sent} pings)`, t0, details, raw);
  }
  const note = `${stats.received}/${stats.sent} replies, avg ${s.avg} ms`;
  if (s.lossPct > 0 || (s.avg ?? 0) > cfg.gatewayLatencyWarnMs) {
    return make('gateway_ping', 'Gateway reachable', Status.WARN, `${note} - local link is unstable or slow`, t0, details, raw);
  }
  return make('gateway_ping', 'Gateway reachable', Status.PASS, note, t0, details, raw);
}

async function checkDns(cfg, st) {
  const t0 = performance.now();
  const host = cfg.dnsTestHostname || cfg.destinationHost;

  const system = async () => {
    try {
      return { ips: await withTimeout(resolveSystem(host), (cfg.dnsTimeout + 2) * 1000), err: '' };
    } catch (e) {
      return { ips: [], err: e.code ?? e.message };
    }
  };
  const query = (server) => dnsQuery(server, host, cfg.dnsTimeout * 1000);

  const configured = st.dnsServers.slice(0, 4);
  const [sys, cfgReplies, pubReplies] = await Promise.all([
    system(),
    Promise.all(configured.map(query)),
    Promise.all(cfg.publicResolvers.map(query)),
  ]);
  const zip = (keys, vals, f) => Object.fromEntries(keys.map((k, i) => [k, f(vals[i])]));
  const details = {
    host,
    systemOk: sys.ips.length > 0, systemIps: sys.ips, systemError: sys.err,
    configured: zip(configured, cfgReplies, (r) => r.responded),
    configuredDetail: zip(configured, cfgReplies, (r) => r),
    public: zip(cfg.publicResolvers, pubReplies, (r) => r.ips.length > 0),
    publicDetail: zip(cfg.publicResolvers, pubReplies, (r) => r),
    publicOk: pubReplies.some((r) => r.ips.length > 0),
  };
  const silent = configured.filter((_, i) => !cfgReplies[i].responded);
  if (sys.ips.length) {
    if (silent.length) {
      return make('dns', 'DNS resolution', Status.WARN, `${host} resolves, but DNS server ${silent.join(', ')} did not answer`, t0, details);
    }
    return make('dns', 'DNS resolution', Status.PASS, `${host} -> ${sys.ips.slice(0, 3).join(', ')}`, t0, details);
  }
  const extra = details.publicOk
    ? "public DNS answers, so the problem is with this network's DNS"
    : 'public DNS did not answer either';
  return make('dns', 'DNS resolution', Status.FAIL, `Cannot resolve ${host} (${sys.err || 'no address returned'}); ${extra}`, t0, details);
}

async function checkDestination(cfg) {
  const t0 = performance.now();
  const { destinationHost: host, destinationPort: port } = cfg;
  const [main, ...ipProbes] = await Promise.all([
    tcpProbe(host, port, cfg.tcpTimeout),
    ...cfg.publicResolvers.map((ip) => tcpProbe(ip, 443, cfg.tcpTimeout)),
  ]);
  const details = {
    host, port, hostOk: main.ok, hostError: main.error, connectMs: main.ms,
    ipProbes: Object.fromEntries(cfg.publicResolvers.map((ip, i) => [ip, ipProbes[i].ok])),
    ipProbeOk: ipProbes.some((p) => p.ok),
  };
  if (main.ok) return make('destination', 'Approved destination', Status.PASS, `Connected to ${host}:${port} in ${main.ms} ms`, t0, details);
  return make('destination', 'Approved destination', Status.FAIL, `Cannot connect to ${host}:${port} (${main.error})`, t0, details);
}

async function checkHttp(cfg) {
  const t0 = performance.now();
  const { destinationHost: host, destinationPort: port } = cfg;
  const out = await httpProbe(host, port, cfg.tcpTimeout + 2);
  const title = 'Web response';
  if (out.skipped) return make('http', title, Status.SKIP, 'Only checked for ports 80 and 443', t0);
  if (out.error) {
    const hint = out.cert ? ' - a sign-in page, proxy or web filter may be intercepting traffic' : '';
    return make('http', title, Status.WARN, `Connected, but the web request failed: ${out.error}${hint}`, t0, out);
  }
  const strip = (h) => (h ?? '').toLowerCase().replace(/^www\./, '');
  let target = null;
  try { target = out.location ? new URL(out.location, `https://${host}`).hostname : null; } catch { /* bad Location */ }
  if (out.status === 511 || (out.status >= 300 && out.status < 400 && target && strip(target) !== strip(host))) {
    return make('http', title, Status.WARN, `HTTP ${out.status}, redirected to ${target ?? 'another site'} - the network may require a sign-in`, t0, out);
  }
  return make('http', title, Status.PASS, `HTTP ${out.status} in ${out.ms} ms`, t0, out);
}

async function checkQuality(cfg) {
  const t0 = performance.now();
  const host = cfg.destinationHost;
  const { stats, raw } = await pingHost(host, cfg.pingCount);
  if (stats.received === 0) { // ICMP may be blocked: time TCP connects instead
    const probes = [];
    for (let i = 0; i < 5; i++) probes.push(await tcpProbe(host, cfg.destinationPort, cfg.tcpTimeout));
    const times = probes.filter((p) => p.ok).map((p) => p.ms);
    const details = { method: 'tcp', samples: probes.length, failed: probes.length - times.length };
    if (!times.length) return make('quality', 'Speed and stability', Status.FAIL, 'No replies to ping or TCP connections', t0, details, raw);
    const avg = round1(mean(times));
    details.avgMs = avg;
    const status = avg >= cfg.latencyWarnMs || details.failed ? Status.WARN : Status.PASS;
    return make('quality', 'Speed and stability', status,
      `Ping is blocked; TCP connect time avg ${avg} ms (${details.failed} of 5 failed)`, t0, details, raw);
  }
  const s = pingSummary(stats);
  const details = { method: 'icmp', lossPct: s.lossPct, minMs: s.min, avgMs: s.avg, maxMs: s.max, jitterMs: s.jitter };
  const text = `loss ${s.lossPct}%, avg ${s.avg} ms (min ${s.min}, max ${s.max}, jitter ${s.jitter})`;
  let status = Status.PASS;
  if (s.lossPct >= cfg.lossFailPct) status = Status.FAIL;
  else if (s.lossPct >= cfg.lossWarnPct || (s.avg ?? 0) >= cfg.latencyWarnMs) status = Status.WARN;
  return make('quality', 'Speed and stability', status, text, t0, details, raw);
}

async function checkRoute(cfg, target) {
  const t0 = performance.now();
  const n = cfg.traceMaxHops;
  const [cmd, args] = IS_WIN
    ? ['tracert', ['-d', '-h', String(n), '-w', '800', target]]
    : ['traceroute', ['-n', '-m', String(n), '-w', '1', target]];
  const res = await runCmd(cmd, args, (n * 3 + 20) * 1000);
  if (res.code === -2) return make('route', 'Route to destination', Status.SKIP, 'Trace tool not available', t0, {}, res.output);
  const hops = parseTrace(res.output);
  const answered = hops.filter((h) => h.ip);
  const details = { target, hops, lastRespondingHop: answered.at(-1) ?? null };
  if (!answered.length) return make('route', 'Route to destination', Status.INFO, `No hop answered on the way to ${target}`, t0, details, res.output);
  const last = answered.at(-1);
  return make('route', 'Route to destination', Status.INFO,
    `Path stops answering after hop ${last.n} (${last.ip}); ${hops.length} hops probed`, t0, details, res.output);
}

// --------------------------------------------------------------------------- //
// Diagnosis (pure function: results in, verdict out)
// --------------------------------------------------------------------------- //
export function diagnose(r) {
  const { FAIL: F, WARN: W, PASS: P } = Status;
  const bad = Object.values(r).filter((c) => c.status === F || c.status === W);
  const technical = bad.map((c) => `${c.title}: ${c.summary}`).join('; ') || 'All checks passed.';
  const D = (verdict, severity, explanation, nextAction) => ({ verdict, severity, explanation, nextAction, technical });

  const { local_ip: ip, gateway: gw, gateway_ping: gping, dns, destination: dst, http, quality, wifi } = r;
  const wifiWeak = wifi?.status === W;

  if (ip?.status === F) {
    if (ip.details.apipa) {
      return D('No network address (DHCP failure)', F,
        'This computer is connected but the network never gave it an address, so it cannot talk to anything.',
        'Reconnect the network cable or Wi-Fi, wait a minute and run this check again. If it still fails, send the report to IT and mention a 169.254 address.');
    }
    return D('Not connected to a network', F, 'This computer has no active network connection.',
      'Check that the network cable is plugged in or that Wi-Fi is switched on and connected, then run this again.');
  }
  if (gw?.status === F) {
    return D('No route out of this network', F,
      'The computer has an address but no gateway, so it cannot reach other networks or the internet.',
      'Disconnect and reconnect to the network, then run this again. If it persists, send the report to IT.');
  }
  if (!dst) return D('Test incomplete', W, 'The connection tests could not be completed.', 'Run the check again.');

  const internetByIp = Boolean(dst.details.ipProbeOk || dns?.details.publicOk);

  if (dst.status === P || dst.status === W) {
    if (http?.status === W) {
      return D('Connected, but web traffic is being intercepted', W,
        'The connection works, but web requests are redirected or blocked - often a network sign-in page or web filter.',
        'Open a web browser and look for a login page. Sign in with your network credentials, then retry. If none appears, send the report to IT.');
    }
    if (quality && (quality.status === W || quality.status === F)) {
      const tip = wifiWeak ? ' The Wi-Fi signal is weak, so move closer to an access point.' : '';
      return D('Connected, but slow or unstable', W,
        `The network works but is losing packets or responding slowly, which causes freezing and failed uploads.${tip}`,
        'Try a wired connection or move closer to an access point, then run again. If it stays slow, send the report to IT.');
    }
    if (wifiWeak) {
      return D('Connected, but the Wi-Fi signal is weak', W,
        'Everything responds, but the Wi-Fi signal is low and may drop out.', 'Move closer to an access point and run the check again.');
    }
    return D('Everything looks healthy', P,
      'The computer has an address, reaches the router, resolves names and connects to the approved destination.',
      'If one website or app still fails, tell IT which one - the network itself is working.');
  }

  // approved destination unreachable
  if (gping?.status === F && !internetByIp) {
    return D("Cannot reach the network's router", F,
      `The computer cannot reach the network's router, so the problem is on the local connection.${wifiWeak ? ' The Wi-Fi signal is also weak.' : ''}`,
      'Check the network cable or Wi-Fi connection, try another network port or move closer to an access point, then run again. If it still fails, send the report to IT.');
  }
  if (dns?.status === F) {
    const configured = dns.details.configured ?? {};
    const values = Object.values(configured);
    if (internetByIp && values.length && !values.some(Boolean)) {
      return D('DNS server not responding', F,
        "The internet works, but this network's DNS servers are not answering, so website names cannot be looked up.",
        'Send the report to IT and tell them the DNS servers are not responding.');
    }
    if (internetByIp) {
      return D('DNS problem', F, 'The internet is reachable, but website names are not being translated to addresses.',
        'Send the report to IT and mention a DNS problem. Restarting the computer sometimes helps.');
    }
    return D('No internet access beyond the router', F,
      'The computer reaches its router, but nothing beyond it answers - not even name lookups.',
      'This usually means a fault upstream of your building or a firewall block. Send the report to IT.');
  }
  if (internetByIp) {
    return D('Approved destination unreachable', F,
      'The internet works, but the approved destination does not answer - it may be down or blocked by a firewall.',
      'Send the report to IT with the name of the destination you could not reach.');
  }
  return D('No internet access beyond the router', F, 'The computer reaches its router, but nothing beyond it answers.',
    'This usually means a fault upstream of your building or a firewall block. Send the report to IT.');
}

// --------------------------------------------------------------------------- //
// Console + reports
// --------------------------------------------------------------------------- //
const LABEL = { pass: '[PASS]', warn: '[WARN]', fail: '[FAIL]', info: '[INFO]', skip: '[SKIP]' };
const COLOR = { pass: '32', warn: '33', fail: '31', info: '36', skip: '90' };

function wrap(text, width, first, rest) {
  const lines = [];
  let line = first;
  for (const word of text.split(/\s+/)) {
    if (line.trim() && (line + ' ' + word).length > width) {
      lines.push(line);
      line = rest + word;
    } else {
      line += (line.trim() ? ' ' : '') + word;
    }
  }
  lines.push(line);
  return lines.join('\n');
}

class Console_ {
  constructor({ color, quiet, verbose }) {
    Object.assign(this, { color, quiet, verbose });
  }
  paint(text, code) { return this.color ? `\x1b[${code}m${text}\x1b[0m` : text; }
  out(text = '') { if (!this.quiet) console.log(text); }
  header(host) {
    const d = new Date();
    const stamp = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${d.toTimeString().slice(0, 8)}`;
    this.out(this.paint(`\n netdiag ${VERSION} - network check for ${host}`, '1'));
    this.out(` ${stamp}\n ${'-'.repeat(72)}`);
  }
  note(text) { this.out(this.paint(`  ...${text}`, '90')); }
  show(res) {
    this.out(` ${this.paint(LABEL[res.status], COLOR[res.status])} ${res.title.padEnd(22)} ${res.summary}`);
    if (!this.verbose) return;
    for (const [k, v] of Object.entries(res.details)) this.out(this.paint(`          ${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`, '90'));
    if (res.raw.trim()) for (const line of res.raw.trimEnd().split(/\r?\n/)) this.out(this.paint(`          | ${line}`, '90'));
  }
  verdict(d, files) {
    this.out(` ${'-'.repeat(72)}`);
    this.out(` RESULT: ${this.paint(d.verdict, `${COLOR[d.severity]};1`)}`);
    this.out(wrap(d.explanation, 76, ' What it means:', '    '));
    this.out(wrap(d.nextAction, 76, ' What to do:', '    '));
    for (const f of files) this.out(` Report saved: ${f}`);
    this.out();
  }
}

function renderTextReport(results, d, cfg, cfgSource, when) {
  const sys = results.system?.details ?? {};
  const lines = [
    `netdiag ${VERSION} report`, '='.repeat(72),
    `Generated : ${when.toString()}`,
    `Computer  : ${sys.hostname ?? '?'} (user ${sys.user ?? '?'})`,
    `System    : ${sys.os ?? '?'} / Node ${sys.node ?? '?'}`,
    `Config    : ${cfgSource}`,
    `Target    : ${cfg.destinationHost}:${cfg.destinationPort}`, '',
    `RESULT    : ${d.verdict}  [${d.severity.toUpperCase()}]`,
    `Meaning   : ${d.explanation}`,
    `Action    : ${d.nextAction}`,
    `Technical : ${d.technical}`, '', 'CHECKS', '-'.repeat(72),
  ];
  for (const res of Object.values(results)) {
    lines.push(`${LABEL[res.status]} ${res.title}: ${res.summary}  (${res.durationMs} ms)`);
    for (const [k, v] of Object.entries(res.details)) lines.push(`        ${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`);
    if (res.raw.trim()) {
      lines.push('        --- raw output ---');
      lines.push(...res.raw.trimEnd().split(/\r?\n/).map((l) => `        ${l}`));
    }
    lines.push('');
  }
  return lines.join('\n');
}

const buildJson = (results, d, cfg, cfgSource, when) => ({
  tool: 'netdiag', version: VERSION, generatedAt: when.toISOString(), configSource: cfgSource, config: cfg,
  diagnosis: d, checks: Object.values(results),
});

// --------------------------------------------------------------------------- //
// HTML report + shared styles
// --------------------------------------------------------------------------- //
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const BADGE = { pass: 'OK', warn: 'Warning', fail: 'Problem', info: 'Info', skip: 'Skipped' };

const BASE_CSS = String.raw`
:root{color-scheme:light dark;--bg:#f4f6f8;--card:#ffffff;--text:#1b2127;--muted:#5b6672;--border:#dde2e8;--accent:#1d4ed8;--accent-text:#ffffff;
--pass:#13703c;--pass-bg:#e5f5ec;--warn:#8a5300;--warn-bg:#fff3d6;--fail:#a82217;--fail-bg:#fde8e6;--info:#0b5f94;--info-bg:#e4f1f9;--skip:#5b6672;--skip-bg:#edf0f3}
@media (prefers-color-scheme:dark){:root{--bg:#0e1217;--card:#161b22;--text:#e7ebf0;--muted:#9aa5b1;--border:#29313b;--accent:#5b8def;--accent-text:#0b1220;
--pass:#4ade80;--pass-bg:#0f2a1a;--warn:#fbbf24;--warn-bg:#2c2208;--fail:#fb8f86;--fail-bg:#33150f;--info:#7ab8ee;--info-bg:#0f2234;--skip:#9aa5b1;--skip-bg:#1d232b}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}
.wrap{max-width:780px;margin:0 auto;padding:28px 18px 56px}
header h1{margin:0;font-size:1.6rem;letter-spacing:-.01em}
h3{margin:26px 0 10px;font-size:1.05rem}
.sub{margin:.25rem 0 0;color:var(--muted)}
.hero{margin:22px 0;padding:22px;background:var(--card);border:1px solid var(--border);border-radius:14px;text-align:center}
.hero p{margin:0 0 14px;color:var(--muted)}
.btn{display:inline-flex;align-items:center;gap:8px;padding:10px 16px;border-radius:10px;border:1px solid var(--border);background:var(--card);color:var(--text);font:inherit;font-weight:600;cursor:pointer;text-decoration:none}
.btn:hover{border-color:var(--accent)}
.btn:focus-visible,summary:focus-visible,input:focus-visible,footer button:focus-visible,.verdict:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.btn.primary{background:var(--accent);color:var(--accent-text);border-color:var(--accent);padding:14px 28px;font-size:1.1rem}
.btn[disabled]{opacity:.7;cursor:progress}
.spinner{width:16px;height:16px;border:3px solid currentColor;border-right-color:transparent;border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.spinner{animation-duration:2.6s}}
.status{min-height:1.5em;margin:6px 2px 14px;color:var(--muted);font-size:.95rem}
.verdict{margin:0 0 18px;padding:18px 20px;border-radius:14px;border:1px solid var(--border);border-left-width:8px;background:var(--card)}
.verdict h2{margin:0 0 6px;font-size:1.3rem}
.verdict p{margin:.35rem 0}
.verdict.pass{background:var(--pass-bg);border-color:var(--pass)}
.verdict.warn{background:var(--warn-bg);border-color:var(--warn)}
.verdict.fail{background:var(--fail-bg);border-color:var(--fail)}
.verdict .saved{color:var(--muted);font-size:.85rem;word-break:break-all}
.checks{list-style:none;margin:0;padding:0;display:grid;gap:10px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:12px 14px}
.row{display:flex;gap:12px;align-items:flex-start}
.badge{flex:none;min-width:88px;text-align:center;font-size:.78rem;font-weight:700;letter-spacing:.02em;padding:4px 8px;border-radius:999px;margin-top:2px}
.badge.pass{color:var(--pass);background:var(--pass-bg)}
.badge.warn{color:var(--warn);background:var(--warn-bg)}
.badge.fail{color:var(--fail);background:var(--fail-bg)}
.badge.info{color:var(--info);background:var(--info-bg)}
.badge.skip,.badge.wait{color:var(--skip);background:var(--skip-bg)}
.title{font-weight:650}
.summary{color:var(--muted);word-break:break-word}
details.tech{margin-top:8px}
details.tech summary{cursor:pointer;color:var(--accent);font-size:.9rem}
pre{margin:8px 0 0;padding:10px;background:var(--bg);border:1px solid var(--border);border-radius:8px;overflow:auto;font:12.5px/1.45 ui-monospace,SFMono-Regular,Consolas,Menlo,monospace;white-space:pre-wrap;word-break:break-word;max-height:360px}
.actions{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:18px 0}
.actions label{display:flex;gap:8px;align-items:center;color:var(--muted);cursor:pointer}
footer{margin-top:28px;color:var(--muted);font-size:.85rem;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
footer button{background:none;border:0;color:var(--accent);font:inherit;cursor:pointer;padding:0;text-decoration:underline}
[hidden]{display:none!important}
@media print{body{background:#fff}.actions,.hero,footer{display:none}pre{max-height:none}}
`;

function renderHtmlReport(results, d, cfg, cfgSource, when) {
  const sys = results.system?.details ?? {};
  const cards = Object.values(results).map((r) => {
    const lines = Object.entries(r.details).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`);
    if (r.raw.trim()) lines.push('', '--- raw output ---', r.raw.trimEnd());
    const more = lines.length ? `<details class="tech"><summary>Technical details</summary><pre>${esc(lines.join('\n'))}</pre></details>` : '';
    return `<li class="card"><div class="row"><span class="badge ${r.status}">${BADGE[r.status]}</span><div><div class="title">${esc(r.title)}</div><div class="summary">${esc(r.summary)}</div></div></div>${more}</li>`;
  }).join('\n');
  const forIt = [
    `Technical : ${d.technical}`,
    `Target    : ${cfg.destinationHost}:${cfg.destinationPort}`,
    `Config    : ${cfgSource}`,
    `Tool      : netdiag ${VERSION} (Node ${sys.node ?? '?'})`,
  ].join('\n');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network report - ${esc(sys.hostname ?? '')}</title><style>${BASE_CSS}</style></head>
<body><div class="wrap">
<header><h1>Network check report</h1>
<p class="sub">${esc(sys.hostname ?? '?')} &middot; user ${esc(sys.user ?? '?')} &middot; ${esc(sys.os ?? '?')} &middot; ${esc(when.toLocaleString())}</p></header>
<section class="verdict ${d.severity}" style="margin-top:20px"><h2>${esc(d.verdict)}</h2><p>${esc(d.explanation)}</p><p><strong>What to do:</strong> ${esc(d.nextAction)}</p></section>
<h3>Checks</h3><ol class="checks">
${cards}
</ol>
<h3>For IT</h3><pre>${esc(forIt)}</pre>
</div></body></html>
`;
}

function saveReports(bodies, cfg, host, when) {
  const base = path.isAbsolute(cfg.reportDir) ? cfg.reportDir : path.join(appDir(), cfg.reportDir);
  const p2 = (n) => String(n).padStart(2, '0');
  const stamp = `${when.getFullYear()}${p2(when.getMonth() + 1)}${p2(when.getDate())}-${p2(when.getHours())}${p2(when.getMinutes())}${p2(when.getSeconds())}`;
  const stem = `${host.replace(/[^A-Za-z0-9_.-]/g, '_')}_${stamp}`;
  for (const folder of [base, path.join(os.tmpdir(), 'netdiag_reports')]) {
    try {
      fs.mkdirSync(folder, { recursive: true });
      const written = [];
      for (const [ext, body] of Object.entries(bodies)) {
        const file = path.join(folder, `${stem}.${ext}`);
        fs.writeFileSync(file, body, 'utf8');
        written.push(file);
      }
      return written;
    } catch { /* try the next folder */ }
  }
  return [];
}

// --------------------------------------------------------------------------- //
// Orchestration
// --------------------------------------------------------------------------- //
export async function runDiagnostics(cfg, ui, { trace = true, collect = collectState } = {}) {
  const results = {};
  const add = (res) => {
    if (res) {
      results[res.id] = res;
      ui.show(res);
    }
    return res;
  };

  add(checkSystem());
  const state = await collect();
  const ip = add(checkLocalIp(state));
  const gw = add(checkGatewayConfig(state));
  add(await checkWifi());

  if (ip.status === Status.FAIL || gw.status === Status.FAIL) {
    for (const [id, title] of [['gateway_ping', 'Gateway reachable'], ['dns', 'DNS resolution'], ['destination', 'Approved destination'],
      ['http', 'Web response'], ['quality', 'Speed and stability']]) {
      add(skipped(id, title, 'Skipped - fix the local connection first'));
    }
    return results;
  }

  ui.note('testing router, DNS and destination in parallel');
  const [gping, dnsRes, dst] = await Promise.all([checkGatewayPing(cfg, state), checkDns(cfg, state), checkDestination(cfg)]);
  if (gping.status === Status.FAIL && dst.status === Status.PASS) {
    gping.status = Status.WARN;
    gping.summary += ' - but the internet works, so the router probably just ignores ping';
  }
  [gping, dnsRes, dst].forEach(add);

  if (dst.status === Status.PASS) {
    ui.note(`measuring speed and stability (about ${cfg.pingCount} seconds)`);
    const [http_, quality] = await Promise.all([
      cfg.httpProbe ? checkHttp(cfg) : skipped('http', 'Web response', 'Disabled in settings'),
      checkQuality(cfg),
    ]);
    add(http_);
    add(quality);
  } else {
    add(skipped('http', 'Web response', 'Skipped - destination not reachable'));
    add(skipped('quality', 'Speed and stability', 'Skipped - destination not reachable'));
    if (trace && cfg.traceOnFailure && gping.status !== Status.FAIL) {
      ui.note('tracing the route (can take up to a minute)');
      add(await checkRoute(cfg, dnsRes.status === Status.FAIL ? cfg.publicResolvers[0] : cfg.destinationHost));
    }
  }
  return results;
}

const exitCode = (d) => ({ pass: 0, warn: 1 })[d.severity] ?? 2;

/** Build the verdict and all report formats; optionally save them to disk. */
function finalize(results, cfg, cfgSource, { save = true } = {}) {
  const diagnosis = diagnose(results);
  const when = new Date();
  const host = os.hostname();
  const data = buildJson(results, diagnosis, cfg, cfgSource, when);
  const out = {
    host, when, diagnosis, data, files: [],
    json: JSON.stringify(data, null, 2),
    text: renderTextReport(results, diagnosis, cfg, cfgSource, when),
    html: renderHtmlReport(results, diagnosis, cfg, cfgSource, when),
  };
  if (save) out.files = saveReports({ html: out.html, txt: out.text, json: out.json }, cfg, host, when);
  return out;
}

// --------------------------------------------------------------------------- //
// Self-test (no network needed)
// --------------------------------------------------------------------------- //
export function selftest() {
  let n = 0;
  const ok = (fn) => { fn(); n++; };

  const ipconfig = [
    'Windows IP Configuration', '', '   Host Name . . . . . . . . . . . . : PC-01', '',
    'Ethernet adapter Ethernet:', '', '   Media State . . . . . . . . . . . : Media disconnected', '',
    'Wireless LAN adapter Wi-Fi:', '',
    '   Connection-specific DNS Suffix  . : lan',
    '   IPv4 Address. . . . . . . . . . . : 10.19.4.57(Preferred)',
    '   Subnet Mask . . . . . . . . . . . : 255.255.0.0',
    '   Default Gateway . . . . . . . . . : 10.19.0.1',
    '   DNS Servers . . . . . . . . . . . : 10.19.0.2',
    '                                       10.19.0.3',
    '   NetBIOS over Tcpip. . . . . . . . : Enabled',
  ].join('\r\n');
  const ad = parseIpconfig(ipconfig);
  ok(() => { assert.equal(ad.length, 2); assert.deepEqual(ad[1].ipv4, ['10.19.4.57']); });
  ok(() => assert.deepEqual(ad[1].dns, ['10.19.0.2', '10.19.0.3']));

  const route = [
    'Network Destination        Netmask          Gateway       Interface  Metric',
    '          0.0.0.0          0.0.0.0     192.168.56.1   192.168.56.10    291',
    '          0.0.0.0          0.0.0.0        10.19.0.1      10.19.4.57     45',
  ].join('\n');
  const routes = parseRoutesWindows(route);
  ok(() => { assert.equal(routes[0].gateway, '10.19.0.1'); assert.equal(routes[0].interfaceIp, '10.19.4.57'); });
  ok(() => assert.equal(parseRoutesLinux('default via 192.168.1.1 dev wlan0 proto dhcp metric 600')[0].iface, 'wlan0'));
  ok(() => assert.equal(parseRouteMacos('   gateway: 192.168.0.1\n  interface: en0')[0].gateway, '192.168.0.1'));

  const winPing = [
    'Pinging 10.19.0.1 with 32 bytes of data:',
    'Reply from 10.19.0.1: bytes=32 time=2ms TTL=64',
    'Reply from 10.19.0.1: bytes=32 time<1ms TTL=64',
    'Request timed out.',
    'Reply from 10.19.4.57: Destination host unreachable.',
  ].join('\n');
  let p = parsePing(winPing, 4);
  ok(() => { assert.equal(p.received, 2); assert.equal(pingSummary(p).lossPct, 50); assert.deepEqual(p.times, [2, 1]); });
  p = parsePing('64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms', 1);
  ok(() => { assert.equal(p.received, 1); assert.equal(pingSummary(p).avg, 12.3); });

  const hops = parseTrace(['Tracing route to x [1.2.3.4]', 'over a maximum of 15 hops:', '',
    '  1    <1 ms    <1 ms    <1 ms  10.19.0.1', '  2     *        *        *     Request timed out.'].join('\n'));
  ok(() => { assert.equal(hops.length, 2); assert.equal(hops[0].ip, '10.19.0.1'); assert.equal(hops[1].ip, null); });

  const { qid, packet } = buildDnsQuery('example.com');
  const answer = Buffer.alloc(16);
  answer.writeUInt16BE(1, 2); answer.writeUInt16BE(1, 4); answer.writeUInt32BE(60, 6); answer.writeUInt16BE(4, 10);
  Buffer.from([93, 184, 216, 34]).copy(answer, 12);
  answer.writeUInt16BE(0xc00c, 0);
  const hdr = Buffer.from(packet.subarray(0, 12));
  hdr.writeUInt16BE(0x8180, 2); hdr.writeUInt16BE(1, 6);
  const reply = Buffer.concat([hdr, packet.subarray(12), answer]);
  ok(() => assert.deepEqual(parseDnsResponse(reply, qid), { rcode: 0, ips: ['93.184.216.34'] }));

  const res = (id, status, details = {}) => ({ id, title: id, status, summary: id, details });
  const good = {
    local_ip: res('local_ip', 'pass'), gateway: res('gateway', 'pass'), gateway_ping: res('gateway_ping', 'pass'),
    dns: res('dns', 'pass', { publicOk: true }), destination: res('destination', 'pass', { ipProbeOk: true }),
    quality: res('quality', 'pass'),
  };
  ok(() => assert.equal(diagnose(good).severity, 'pass'));
  ok(() => assert.equal(diagnose({ ...good, dns: res('dns', 'fail', { publicOk: true, configured: { '10.0.0.2': false } }),
    destination: res('destination', 'fail', { ipProbeOk: true }) }).verdict, 'DNS server not responding'));
  ok(() => assert.match(diagnose({ ...good, local_ip: res('local_ip', 'fail', { apipa: true }) }).verdict, /DHCP/));
  ok(() => assert.equal(diagnose({ ...good, gateway_ping: res('gateway_ping', 'fail'), dns: res('dns', 'fail', { publicOk: false }),
    destination: res('destination', 'fail', { ipProbeOk: false }) }).verdict, "Cannot reach the network's router"));
  ok(() => assert.match(diagnose({ ...good, quality: res('quality', 'warn') }).verdict, /^Connected, but slow/));

  console.log(`selftest passed (${n} checks)`);
  return 0;
}

// --------------------------------------------------------------------------- //
// Local web dashboard (--ui)
// --------------------------------------------------------------------------- //
const KEEP_RUNNING = Symbol('keep-running');

const PAGE = String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network check</title><style>/*__CSS__*/</style></head>
<body><div class="wrap">
<header><h1>Network check</h1><p class="sub"><span>__HOST__</span> &rarr; <span>__TARGET__</span></p></header>

<section class="hero" id="hero">
  <p>Runs a series of tests to find out why this computer cannot connect. It takes about 15 seconds.</p>
  <button class="btn primary" id="run" type="button">Run diagnostics</button>
</section>

<div class="status" id="status" role="status" aria-live="polite"></div>

<section class="verdict" id="verdict" tabindex="-1" hidden>
  <h2 id="v-title"></h2>
  <p id="v-why"></p>
  <p><strong>What to do:</strong> <span id="v-do"></span></p>
  <p class="saved" id="files"></p>
</section>

<ol class="checks" id="checks"></ol>

<div class="actions" id="actions" hidden>
  <a class="btn" id="dl" href="#" download>Download report</a>
  <button class="btn" id="copy" type="button">Copy summary for IT</button>
  <label><input type="checkbox" id="tech"> Show technical details</label>
</div>

<footer><span>netdiag __VERSION__</span><button id="quit" type="button">Close this tool</button></footer>
</div>
<script>
(function () {
  'use strict';
  var HOST = __HOSTJSON__;
  var TOKEN = new URLSearchParams(location.search).get('t') || '';
  var ORDER = ['system', 'local_ip', 'gateway', 'wifi', 'gateway_ping', 'dns', 'destination', 'http', 'quality', 'route'];
  var EXPECTED = ['system', 'local_ip', 'gateway', 'gateway_ping', 'dns', 'destination', 'http', 'quality'];
  var TITLES = { system: 'System', local_ip: 'Local IP address', gateway: 'Default gateway', wifi: 'Wi-Fi signal',
    gateway_ping: 'Gateway reachable', dns: 'DNS resolution', destination: 'Approved destination', http: 'Web response',
    quality: 'Speed and stability', route: 'Route to destination' };
  var BADGE = { pass: 'OK', warn: 'Warning', fail: 'Problem', info: 'Info', skip: 'Skipped', wait: 'Waiting' };
  var results = {}, diagnosis = null, ranOnce = false;

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function fmt(v) { return (typeof v === 'object' && v !== null) ? JSON.stringify(v) : String(v); }
  function qs(extra) { return '?t=' + encodeURIComponent(TOKEN) + (extra || ''); }

  function cardFor(id) {
    var existing = document.querySelector('[data-id="' + id + '"]');
    if (existing) return existing;
    var li = el('li', 'card');
    li.setAttribute('data-id', id);
    var row = el('div', 'row');
    row.appendChild(el('span', 'badge wait', BADGE.wait));
    var body = el('div');
    body.appendChild(el('div', 'title', TITLES[id] || id));
    body.appendChild(el('div', 'summary', 'Waiting...'));
    row.appendChild(body);
    li.appendChild(row);
    var pos = ORDER.indexOf(id), ref = null, items = $('checks').children;
    for (var i = 0; i < items.length; i++) {
      if (ORDER.indexOf(items[i].getAttribute('data-id')) > pos) { ref = items[i]; break; }
    }
    $('checks').insertBefore(li, ref);
    return li;
  }

  function setCard(r) {
    var li = cardFor(r.id);
    var badge = li.querySelector('.badge');
    badge.className = 'badge ' + r.status;
    badge.textContent = BADGE[r.status] || r.status;
    li.querySelector('.title').textContent = r.title;
    li.querySelector('.summary').textContent = r.summary;
    var old = li.querySelector('details');
    if (old) li.removeChild(old);
    var lines = [];
    Object.keys(r.details || {}).forEach(function (k) { lines.push(k + ': ' + fmt(r.details[k])); });
    if (r.raw && r.raw.trim()) lines.push('', '--- raw output ---', r.raw.replace(/\s+$/, ''));
    if (lines.length) {
      var d = el('details', 'tech');
      d.open = $('tech').checked;
      d.appendChild(el('summary', null, 'Technical details'));
      d.appendChild(el('pre', null, lines.join('\n')));
      li.appendChild(d);
    }
  }

  function setBusy(busy) {
    var btn = $('run');
    btn.disabled = busy;
    btn.textContent = '';
    if (busy) {
      btn.appendChild(el('span', 'spinner'));
      btn.appendChild(document.createTextNode(' Testing...'));
    } else {
      btn.textContent = ranOnce ? 'Run again' : 'Run diagnostics';
    }
  }

  function reset() {
    results = {};
    diagnosis = null;
    $('checks').textContent = '';
    EXPECTED.forEach(function (id) { cardFor(id); });
    $('verdict').hidden = true;
    $('actions').hidden = true;
    $('status').textContent = 'Starting...';
  }

  function finish(payload) {
    diagnosis = payload.diagnosis;
    var cards = $('checks').children;
    for (var i = 0; i < cards.length; i++) {
      var b = cards[i].querySelector('.badge');
      if (b.classList.contains('wait')) {
        b.className = 'badge skip';
        b.textContent = BADGE.skip;
        cards[i].querySelector('.summary').textContent = 'Not run';
      }
    }
    var v = $('verdict');
    v.className = 'verdict ' + diagnosis.severity;
    v.hidden = false;
    $('v-title').textContent = diagnosis.verdict;
    $('v-why').textContent = diagnosis.explanation;
    $('v-do').textContent = diagnosis.nextAction;
    $('files').textContent = (payload.files && payload.files.length) ? 'Saved on this computer: ' + payload.files[0] : '';
    $('dl').href = '/api/report' + qs('&format=html');
    $('actions').hidden = false;
    $('status').textContent = 'Finished.';
    ranOnce = true;
    setBusy(false);
    v.focus();
  }

  function problem(message) {
    $('status').textContent = message;
    setBusy(false);
  }

  function summaryText() {
    var lines = ['Network check - ' + HOST + ' - ' + new Date().toLocaleString(),
      'RESULT: ' + diagnosis.verdict, 'Meaning: ' + diagnosis.explanation, 'Technical: ' + diagnosis.technical, ''];
    ORDER.forEach(function (id) {
      var r = results[id];
      if (r) lines.push('[' + r.status.toUpperCase() + '] ' + r.title + ': ' + r.summary);
    });
    return lines.join('\n');
  }

  $('run').addEventListener('click', function () {
    reset();
    setBusy(true);
    var es = new EventSource('/api/run' + qs());
    var over = false;
    es.addEventListener('note', function (e) { $('status').textContent = JSON.parse(e.data).text + '...'; });
    es.addEventListener('result', function (e) {
      var r = JSON.parse(e.data);
      results[r.id] = r;
      setCard(r);
    });
    es.addEventListener('done', function (e) { over = true; es.close(); finish(JSON.parse(e.data)); });
    es.addEventListener('problem', function (e) { over = true; es.close(); problem(JSON.parse(e.data).message); });
    es.onerror = function () {
      if (over) return;
      over = true;
      es.close();
      problem('The test could not be completed. Close this tab, start the tool again and retry.');
    };
  });

  $('tech').addEventListener('change', function () {
    var open = $('tech').checked;
    Array.prototype.forEach.call(document.querySelectorAll('details.tech'), function (d) { d.open = open; });
  });

  $('copy').addEventListener('click', function () {
    var text = summaryText();
    function done() {
      $('copy').textContent = 'Copied';
      setTimeout(function () { $('copy').textContent = 'Copy summary for IT'; }, 1800);
    }
    function fallback() {
      var t = document.createElement('textarea');
      t.value = text;
      document.body.appendChild(t);
      t.select();
      try { document.execCommand('copy'); done(); } catch (e) { /* ignore */ }
      document.body.removeChild(t);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, fallback);
    else fallback();
  });

  $('quit').addEventListener('click', function () {
    var bye = function () { document.body.textContent = 'netdiag has stopped. You can close this tab.'; };
    fetch('/api/quit' + qs(), { method: 'POST' }).then(bye, bye);
  });
})();
</script></body></html>
`;

function listen(server, port) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', reject);
      resolve(server.address().port);
    });
  });
}

function openBrowser(url) {
  const [cmd, args] = IS_WIN ? ['cmd', ['/c', 'start', '', url]] : IS_MAC ? ['open', [url]] : ['xdg-open', [url]];
  execFile(cmd, args, { windowsHide: true }, () => {});
}

async function startUi(cfg, cfgSource, args) {
  const token = randomBytes(16).toString('hex'); // keeps other web pages from driving this server
  const host = os.hostname();
  let busy = false;
  let last = null;
  const idle = setTimeout(() => process.exit(0), 30 * 60 * 1000);
  const FORMATS = {
    html: ['text/html; charset=utf-8', 'html'],
    json: ['application/json; charset=utf-8', 'json'],
    txt: ['text/plain; charset=utf-8', 'text'],
  };

  const page = PAGE
    .replace('/*__CSS__*/', () => BASE_CSS)
    .replaceAll('__VERSION__', VERSION)
    .replace('__HOST__', () => esc(host))
    .replace('__TARGET__', () => esc(`${cfg.destinationHost}:${cfg.destinationPort}`))
    .replace('__HOSTJSON__', () => JSON.stringify(host).replace(/</g, '\\u003c'));

  const server = http.createServer(async (req, res) => {
    idle.refresh();
    const base = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };
    const reply = (code, type, body, extra = {}) => {
      res.writeHead(code, { ...base, 'Content-Type': type, ...extra });
      res.end(body);
    };
    try {
      if (!/^(127\.0\.0\.1|localhost)(:\d+)?$/.test(req.headers.host ?? '')) return reply(403, 'text/plain', 'Forbidden');
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (url.pathname === '/favicon.ico') return reply(204, 'text/plain', '');
      if (url.searchParams.get('t') !== token) {
        return reply(403, 'text/plain; charset=utf-8', 'Open the link shown in the netdiag window - it contains a private access code.');
      }

      if (url.pathname === '/' && req.method === 'GET') {
        return reply(200, 'text/html; charset=utf-8', page, {
          'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        });
      }

      if (url.pathname === '/api/run' && req.method === 'GET') {
        if (busy) return reply(409, 'text/plain', 'A test is already running');
        busy = true;
        res.writeHead(200, { ...base, 'Content-Type': 'text/event-stream; charset=utf-8', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
        const send = (event, data) => {
          if (!res.writableEnded && !res.destroyed) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
        };
        try {
          const ui = { show: (r) => send('result', r), note: (text) => send('note', { text }) };
          const results = await runDiagnostics(cfg, ui, { trace: !args['no-trace'] });
          last = finalize(results, cfg, cfgSource, { save: !args['no-report'] });
          send('done', { diagnosis: last.diagnosis, files: last.files });
        } catch (e) {
          send('problem', { message: `Unexpected error: ${e.message}` });
        } finally {
          busy = false;
          res.end();
        }
        return undefined;
      }

      if (url.pathname === '/api/report' && req.method === 'GET') {
        const [type, ext] = FORMATS[url.searchParams.get('format') ?? 'html'] ?? [];
        if (!last || !type) return reply(404, 'text/plain', 'No report yet - run the diagnostics first.');
        const stamp = last.when.toISOString().slice(0, 19).replace(/[:T]/g, '-');
        return reply(200, type, last[ext === 'text' ? 'text' : ext], {
          'Content-Disposition': `attachment; filename="netdiag_${host.replace(/[^A-Za-z0-9_.-]/g, '_')}_${stamp}.${ext === 'text' ? 'txt' : ext}"`,
        });
      }

      if (url.pathname === '/api/quit' && req.method === 'POST') {
        reply(204, 'text/plain', '');
        setTimeout(() => process.exit(0), 100);
        return undefined;
      }
      return reply(404, 'text/plain', 'Not found');
    } catch (e) {
      if (!res.headersSent) return reply(500, 'text/plain', `Error: ${e.message}`);
      res.end();
      return undefined;
    }
  });

  const basePort = Number(args['ui-port'] ?? 8765);
  let port = null;
  for (let p = basePort; p < basePort + 20 && port === null; p++) {
    try {
      port = await listen(server, p);
    } catch (e) {
      if (e.code !== 'EADDRINUSE') throw e;
    }
  }
  port ??= await listen(server, 0);

  const url = `http://127.0.0.1:${port}/?t=${token}`;
  console.log(`\n netdiag ${VERSION} dashboard\n Open this link in your browser if it does not open by itself:\n   ${url}\n Press Ctrl+C (or use "Close this tool" in the page) to stop.\n`);
  if (!args['no-open']) openBrowser(url);
  return KEEP_RUNNING;
}

// --------------------------------------------------------------------------- //
// Entry point
// --------------------------------------------------------------------------- //
const OPTIONS = {
  verbose: { type: 'boolean', short: 'v' },
  json: { type: 'boolean' },
  config: { type: 'string' },
  host: { type: 'string' },
  port: { type: 'string' },
  'report-dir': { type: 'string' },
  'no-report': { type: 'boolean' },
  'no-trace': { type: 'boolean' },
  'no-pause': { type: 'boolean' },
  'init-config': { type: 'boolean' },
  selftest: { type: 'boolean' },
  version: { type: 'boolean' },
  ui: { type: 'boolean' },
  'ui-port': { type: 'string' },
  'no-open': { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
};

const USAGE = `netdiag ${VERSION} - first-line network troubleshooting

  node netdiag.mjs [options]

  -v, --verbose        show details and raw command output (for IT)
      --json           print the full report as JSON and nothing else
      --config PATH    settings file (default: netdiag.config.json next to this script)
      --host HOST      approved destination host (overrides settings)
      --port PORT      approved destination port (overrides settings)
      --report-dir DIR folder for saved reports
      --no-report      do not save report files
      --no-trace       never run tracert/traceroute
      --no-pause       do not wait for Enter at the end (packaged .exe only)
      --init-config    write a sample netdiag.config.json and exit
      --ui             start the local web dashboard and open it in your browser
      --ui-port PORT   dashboard port (default 8765)
      --no-open        with --ui: do not open the browser automatically
      --selftest       run built-in parser tests and exit
`;

function ansiSupported() {
  return Boolean(process.stdout.isTTY) && !process.env.NO_COLOR && process.env.TERM !== 'dumb';
}

async function isPackaged() {
  try {
    const sea = await import('node:sea');
    return Boolean((sea.isSea ?? sea.default?.isSea)?.());
  } catch {
    return Boolean(process.pkg);
  }
}

async function main(argv) {
  let args;
  try {
    args = parseArgs({ args: argv, options: OPTIONS, allowPositionals: false }).values;
  } catch (e) {
    console.error(`${e.message}\n\n${USAGE}`);
    return 3;
  }
  if (args.help) { console.log(USAGE); return 0; }
  if (args.version) { console.log(`netdiag ${VERSION}`); return 0; }
  if (args.selftest) return selftest();
  if (args['init-config']) {
    const target = 'netdiag.config.json';
    if (fs.existsSync(target)) { console.error(`${target} already exists - not overwriting.`); return 3; }
    fs.writeFileSync(target, sampleConfig(), 'utf8');
    console.log(`Wrote ${target}`);
    return 0;
  }

  let cfg, cfgSource;
  try {
    [cfg, cfgSource] = loadConfig(args.config);
  } catch (e) {
    console.error(`Could not read settings: ${e.message}`);
    return 3;
  }
  if (args.host) cfg.destinationHost = args.host;
  if (args.port) cfg.destinationPort = Number(args.port);
  if (args['report-dir']) cfg.reportDir = args['report-dir'];

  if (args.ui || (argv.length === 0 && (await isPackaged()))) return startUi(cfg, cfgSource, args);

  const ui = new Console_({ color: ansiSupported(), quiet: Boolean(args.json), verbose: Boolean(args.verbose) });
  const host = os.hostname();
  ui.header(host);

  let results;
  try {
    results = await runDiagnostics(cfg, ui, { trace: !args['no-trace'] });
  } catch (e) { // last resort - never leave staff with a stack trace
    console.error(`netdiag failed unexpectedly: ${e.name}: ${e.message}`);
    return 3;
  }

  const out = finalize(results, cfg, cfgSource, { save: !args['no-report'] });
  if (args.json) console.log(out.json);
  else ui.verdict(out.diagnosis, out.files);
  return exitCode(out.diagnosis);
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain || (await isPackaged())) {
  const argv = process.argv.slice(2);
  const code = await main(argv);
  if (code !== KEEP_RUNNING) {
    if (argv.length === 0 && (await isPackaged()) && process.stdin.isTTY) {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      await rl.question('Press Enter to close...');
      rl.close();
    }
    // Exit explicitly: a resolver thread stuck on a dead DNS server must not delay exit.
    process.stdout.write('', () => process.stderr.write('', () => process.exit(code)));
  }
}
