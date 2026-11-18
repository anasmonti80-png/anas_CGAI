// CG-072 External attack surface management for registered and authorized assets only. A scope names the authorization,
// the owner, the domains (ownership proven by a DNS TXT token or declared with a reference) and the address ranges the
// organisation controls. Only addresses inside those ranges are ever connected to; a domain that resolves elsewhere
// (a CDN or another party) is recorded as not probed. Checks: DNS records, mail authentication, TLS certificates and
// protocol, reachable services (TCP connect, or nmap service detection when installed and requested) and HTTP security
// headers. Nothing is exploited and no credentials are tried.
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns/promises';
import { X509Certificate } from 'node:crypto';
import { execFile } from 'node:child_process';
import { ipInCidr } from './vulnerability-intel.js';

export const ADMIN_PORTS = { 22: 'ssh', 23: 'telnet', 445: 'smb', 1433: 'mssql', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 5985: 'winrm', 5986: 'winrm-https', 6379: 'redis', 9200: 'elasticsearch', 27017: 'mongodb' };
export const DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9200, 27017];
const TLS_PORTS = new Set([443, 465, 636, 853, 993, 995, 5986, 8443]);

export function validateScope(scope, now = Date.now()) {
  const fail = m => { throw new Error(m); };
  if (!scope || typeof scope !== 'object') fail('scope file required');
  if (typeof scope.authorization_ref !== 'string' || scope.authorization_ref.trim().length < 6) fail('authorization_ref required (at least 6 characters)');
  if (typeof scope.owner !== 'string' || !scope.owner.trim()) fail('owner required');
  if (!scope.window_end || Number.isNaN(Date.parse(scope.window_end)) || Date.parse(scope.window_end) < now) fail('authorization window has ended or is missing (window_end)');
  const networks = scope.networks || [], domains = scope.domains || [];
  if (!Array.isArray(networks) || !networks.every(n => /^[0-9a-f.:]+\/\d{1,3}$/i.test(n))) fail('networks must be CIDR ranges');
  for (const n of networks) { const bits = Number(n.split('/')[1]); if ((n.includes(':') && bits < 112) || (!n.includes(':') && bits < 22)) fail(`range ${n} is too wide; split it into ranges of /22 (IPv4) or /112 (IPv6) or smaller`); }
  if (!Array.isArray(domains) || !domains.every(d => d && /^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i.test(d.name) && ['dns-txt', 'declared'].includes(d.verification))) fail('domains need a name and verification dns-txt or declared');
  for (const d of domains) if (d.verification === 'declared' && !(typeof d.reference === 'string' && d.reference.length >= 6)) fail(`domain ${d.name} declared without an ownership reference`);
  if (!networks.length && !domains.length) fail('scope has no targets');
  const ports = scope.ports || DEFAULT_PORTS; if (!Array.isArray(ports) || ports.length > 200 || !ports.every(p => Number.isInteger(p) && p > 0 && p < 65536)) fail('ports must be up to 200 TCP ports');
  const tls_ports = scope.tls_ports || []; if (!Array.isArray(tls_ports) || !tls_ports.every(p => ports.includes(p))) fail('tls_ports must be listed in ports');
  return { ...scope, networks, domains, ports, tls_ports, rate_per_second: Math.min(Math.max(Number(scope.rate_per_second) || 20, 1), 100) };
}
export const inScope = (ip, networks) => networks.some(n => ipInCidr(ip, n));
export function hostsOf(networks, max = 1024) { const out = []; for (const n of networks) { if (n.includes(':')) { const [base] = n.split('/'); out.push(base); continue; } const [base, bits] = n.split('/'), size = 2 ** (32 - Number(bits)), start = base.split('.').reduce((a, p) => a * 256 + Number(p), 0); for (let i = 0; i < size && out.length < max; i++) { const v = start + i; out.push([v >>> 24 & 255, v >>> 16 & 255, v >>> 8 & 255, v & 255].join('.')); } } return out; }

export function tcpConnect(host, port, timeout = 1500) {
  return new Promise(resolve => { const s = net.connect({ host, port }); const done = state => { s.destroy(); resolve(state); }; s.setTimeout(timeout, () => done('filtered')); s.once('connect', () => done('open')); s.once('error', e => done(e.code === 'ECONNREFUSED' ? 'closed' : 'filtered')); });
}
export function tlsInspect(host, port, servername, timeout = 3000) {
  return new Promise(resolve => {
    const s = tls.connect({ host, port, servername: net.isIP(servername) ? undefined : servername, rejectUnauthorized: false, timeout }, () => {
      const raw = s.getPeerCertificate(false), protocol = s.getProtocol(); s.end();
      if (!raw || !raw.raw) return resolve(null);
      const x = new X509Certificate(raw.raw), validTo = new Date(x.validTo).toISOString();
      resolve({ port, protocol, subject: x.subject.replace(/\n/g, ', '), issuer: x.issuer.replace(/\n/g, ', '), valid_from: new Date(x.validFrom).toISOString(), valid_to: validTo, self_signed: x.subject === x.issuer, name_match: Boolean(net.isIP(servername) ? x.checkIP(servername) : x.checkHost(servername)), key_type: x.publicKey.asymmetricKeyType, fingerprint256: x.fingerprint256, authorized: s.authorized });
    });
    s.once('error', () => resolve(null)); s.once('timeout', () => { s.destroy(); resolve(null); });
  });
}
export function httpHeaders(host, port, servername, useTls, timeout = 3000) {
  return new Promise(resolve => {
    const opts = { host, port, servername: net.isIP(servername) ? undefined : servername, rejectUnauthorized: false, timeout };
    const s = useTls ? tls.connect(opts) : net.connect(opts); let data = '';
    s.once(useTls ? 'secureConnect' : 'connect', () => s.write(`HEAD / HTTP/1.1\r\nHost: ${servername}\r\nUser-Agent: CyberGuard-EASM\r\nConnection: close\r\n\r\n`));
    s.on('data', d => { data += d; if (data.length > 16384) s.destroy(); }); s.once('error', () => resolve(null)); s.once('timeout', () => { s.destroy(); resolve(null); });
    s.once('close', () => { const [status, ...lines] = data.split('\r\n\r\n')[0].split('\r\n'); if (!/^HTTP\/\d/.test(status || '')) return resolve(null); const h = Object.fromEntries(lines.map(l => [l.split(':')[0].toLowerCase(), l.slice(l.indexOf(':') + 1).trim()])); resolve({ port, status: status.slice(0, 40), hsts: Boolean(h['strict-transport-security']), server: h.server ? h.server.slice(0, 100) : null }); });
  });
}
export function parseNmapXml(xml) {
  const ports = []; for (const m of String(xml).matchAll(/<port protocol="(tcp|udp)" portid="(\d+)">([\s\S]*?)<\/port>/g)) {
    const state = /<state state="([a-z|]+)"/.exec(m[3])?.[1], svc = /<service ([^>]*)\/?>/.exec(m[3])?.[1] || '', attr = k => new RegExp(`${k}="([^"]*)"`).exec(svc)?.[1] || null;
    if (state === 'open') ports.push({ port: Number(m[2]), transport: m[1], state, service: attr('name'), product: attr('product'), version: attr('version'), via: 'nmap' }); }
  return ports;
}
export function runNmap(ip, ports, rate) {
  return new Promise((resolve, reject) => execFile('nmap', ['-Pn', '-sV', '--version-light', '--max-rate', String(rate), '-p', ports.join(','), '-oX', '-', ip], { timeout: 600000, maxBuffer: 8 * 1024 * 1024 }, (e, out) => e ? reject(e) : resolve(parseNmapXml(out))));
}
export const nmapAvailable = () => new Promise(r => execFile('nmap', ['--version'], { timeout: 10000 }, (e, out) => r(e ? null : (/Nmap version ([\d.]+)/.exec(out)?.[1] || 'unknown'))));

export function findingsFor(o, now = Date.now()) {
  const f = [], add = (id, severity, title, title_ar) => f.push({ id, severity, title, title_ar });
  for (const c of o.tls || []) {
    const days = Math.floor((Date.parse(c.valid_to) - now) / 86400000);
    if (days < 0) add(`tls-expired:${c.port}`, 'high', `TLS certificate on port ${c.port} expired ${-days} days ago`, `شهادة TLS على المنفذ ${c.port} منتهية منذ ${-days} يومًا`);
    else if (days <= 30) add(`tls-expiring:${c.port}`, 'medium', `TLS certificate on port ${c.port} expires in ${days} days`, `شهادة TLS على المنفذ ${c.port} تنتهي خلال ${days} يومًا`);
    if (c.self_signed) add(`tls-self-signed:${c.port}`, 'medium', `Self-signed TLS certificate on port ${c.port}`, `شهادة TLS موقعة ذاتيًا على المنفذ ${c.port}`);
    if (!c.name_match) add(`tls-name-mismatch:${c.port}`, 'high', `TLS certificate on port ${c.port} does not cover ${o.target}`, `شهادة TLS على المنفذ ${c.port} لا تغطي ${o.target}`);
    if (['TLSv1', 'TLSv1.1', 'SSLv3'].includes(c.protocol)) add(`tls-legacy:${c.port}`, 'medium', `Legacy protocol ${c.protocol} accepted on port ${c.port}`, `بروتوكول قديم ${c.protocol} مقبول على المنفذ ${c.port}`);
  }
  for (const s of o.services || []) if (ADMIN_PORTS[s.port]) add(`exposed-admin:${s.port}`, s.port === 23 || s.port === 445 ? 'critical' : 'high', `Administrative or database service ${ADMIN_PORTS[s.port]} reachable on port ${s.port}`, `خدمة إدارة أو قاعدة بيانات ${ADMIN_PORTS[s.port]} يمكن الوصول إليها على المنفذ ${s.port}`);
  for (const h of o.http || []) if (h.port !== 80 && !h.hsts) add(`http-no-hsts:${h.port}`, 'low', `HTTPS on port ${h.port} does not send Strict-Transport-Security`, `HTTPS على المنفذ ${h.port} لا يرسل Strict-Transport-Security`);
  if (o.dns) {
    if (o.dns.mx.length && !o.dns.spf) add('mail-no-spf', 'medium', `Domain ${o.target} receives mail but publishes no SPF record`, `النطاق ${o.target} يستقبل البريد بلا سجل SPF`);
    if (o.dns.mx.length && !o.dns.dmarc) add('mail-no-dmarc', 'medium', `Domain ${o.target} receives mail but publishes no DMARC policy`, `النطاق ${o.target} يستقبل البريد بلا سياسة DMARC`);
    if (!o.dns.caa) add('dns-no-caa', 'low', `Domain ${o.target} publishes no CAA record limiting certificate issuers`, `النطاق ${o.target} بلا سجل CAA يحدد جهات إصدار الشهادات`);
  }
  return f;
}

// Collect one scope. Dependencies are injectable so the same code runs against real hosts and in tests.
export async function collect(scopeInput, { resolver = dns, connect = tcpConnect, inspect = tlsInspect, headers = httpHeaders, nmap = null, now = Date.now(), log = () => {} } = {}) {
  const scope = validateScope(scopeInput, now), observations = [], delay = 1000 / scope.rate_per_second, wait = () => new Promise(r => setTimeout(r, delay));
  const safe = async (fn, fallback) => { try { return await fn(); } catch { return fallback; } };
  const probe = async (ip, name) => {
    const services = [], tlsCerts = [], http = [];
    if (nmap) { for (const s of await nmap(ip, scope.ports, scope.rate_per_second)) services.push(s); }
    else for (const port of scope.ports) { await wait(); if (await connect(ip, port) === 'open') services.push({ port, transport: 'tcp', state: 'open', service: ADMIN_PORTS[port] || null, product: null, version: null, via: 'tcp-connect' }); }
    for (const s of services) {
      const isTls = TLS_PORTS.has(s.port) || scope.tls_ports.includes(s.port) || s.service === 'https' || s.service === 'ssl/http';
      if (isTls) { const c = await inspect(ip, s.port, name); if (c) tlsCerts.push(c); }
      if ([80, 443, 8080, 8443].includes(s.port) || scope.tls_ports.includes(s.port)) { const r = await headers(ip, s.port, name, isTls); if (r) http.push(r); }
    }
    return { services, tls: tlsCerts, http };
  };
  for (const d of scope.domains) {
    log(`domain ${d.name}`);
    const txt = (await safe(() => resolver.resolveTxt(d.name), [])).map(r => r.join(''));
    const ownership = d.verification === 'dns-txt' ? (txt.includes(`cyberguard-verify=${d.token}`) ? 'verified-dns-txt' : 'unverified') : 'declared';
    if (ownership === 'unverified') { observations.push({ target: d.name, target_type: 'domain', ownership, dns: null, services: [], tls: [], http: [], not_probed: [{ address: d.name, reason: 'ownership-not-verified' }] }); continue; }
    const a = await safe(() => resolver.resolve4(d.name), []), aaaa = await safe(() => resolver.resolve6(d.name), []), mx = (await safe(() => resolver.resolveMx(d.name), [])).map(m => m.exchange);
    const caa = (await safe(() => resolver.resolveCaa(d.name), [])).length > 0, dmarc = (await safe(() => resolver.resolveTxt(`_dmarc.${d.name}`), [])).some(r => r.join('').startsWith('v=DMARC1'));
    const o = { target: d.name, target_type: 'domain', ownership, dns: { a, aaaa, mx, caa, spf: txt.some(t => t.startsWith('v=spf1')), dmarc }, services: [], tls: [], http: [], not_probed: [] };
    for (const ip of [...a, ...aaaa]) {
      if (!inScope(ip, scope.networks)) { o.not_probed.push({ address: ip, reason: 'outside-authorized-networks' }); continue; }
      const r = await probe(ip, d.name); o.services.push(...r.services.map(s => ({ ...s, address: ip }))); o.tls.push(...r.tls); o.http.push(...r.http);
    }
    observations.push(o);
  }
  for (const ip of hostsOf(scope.networks)) {
    log(`address ${ip}`); const r = await probe(ip, ip);
    if (r.services.length) observations.push({ target: ip, target_type: 'address', ownership: 'declared-network', dns: null, services: r.services.map(s => ({ ...s, address: ip })), tls: r.tls, http: r.http, not_probed: [] });
  }
  return { scope, observations: observations.map(o => ({ ...o, findings: findingsFor(o, now) })) };
}

export function toTelemetry({ scope, observations }, { collector = 'cyberguard-easm/1', tool = 'tcp-connect', now = Date.now() } = {}) {
  const at = new Date(now).toISOString();
  return { schema_version: 'cg.telemetry/1', events: observations.map((o, i) => ({ event_id: `easm:${scope.authorization_ref}:${o.target}:${at}`.slice(0, 200), kind: 'easm.observation', observed_at: at,
    asset: { external_id: o.target_type === 'domain' ? `domain:${o.target}` : o.target, hostname: o.target, os_family: 'unknown', device_type: 'unknown', addresses: o.target_type === 'address' ? [o.target] : (o.dns?.a || []).filter(ip => inScope(ip, scope.networks)).slice(0, 20) },
    details: { authorization_ref: scope.authorization_ref, owner: scope.owner, target: o.target, target_type: o.target_type, ownership: o.ownership, dns: o.dns, services: o.services.slice(0, 200), tls: o.tls.slice(0, 50), http: o.http.slice(0, 50), not_probed: o.not_probed.slice(0, 100), findings: o.findings.slice(0, 200), tool, collector, index: i } })) };
}
