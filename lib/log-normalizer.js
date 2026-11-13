// CG-018 log normalisation: raw lines from syslog/journald, NetFlow/IPFIX exports, IDS/IPS, DNS, DHCP,
// VPN and firewall logs become one common event model. Unparseable lines are rejected with a reason.
import { isIP } from 'node:net';
import { redact } from './common.js';

export const logFormats = {
  syslog: 'syslog', journal: 'syslog', 'nfdump-csv': 'flow', 'goflow-json': 'flow', 'suricata-eve': 'ids',
  'bind-query': 'dns', 'isc-dhcpd': 'dhcp', openvpn: 'vpn', iptables: 'firewall', 'windows-firewall': 'firewall', 'pfsense-filterlog': 'firewall',
};
const months = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
const ip = value => (value && isIP(String(value).replace(/^\[|\]$/g, '')) ? String(value).replace(/^\[|\]$/g, '') : null);
const port = value => { const n = Number(value); return Number.isInteger(n) && n >= 0 && n <= 65535 ? n : null; };
const proto = value => { if (value === undefined || value === null || value === '') return null; const v = String(value).toLowerCase(); return { 6: 'tcp', 17: 'udp', 1: 'icmp', 58: 'icmpv6' }[v] || v.slice(0, 16); };
const iso = value => { const t = Date.parse(value); return Number.isFinite(t) ? new Date(t).toISOString() : null; };
const message = value => (value ? redact(String(value)).slice(0, 500) : null);
const base = (category, time) => ({ category, time, action: null, outcome: null, src_ip: null, dst_ip: null, src_port: null, dst_port: null, protocol: null, user: null, host: null, mac: null, query: null, signature: null, severity: null, bytes: null, packets: null, message: null });

function syslogLine(line, year) {
  let m = line.match(/^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (?:-|\[.*?\])\s?(.*)$/);
  if (m) { const r = base('syslog', iso(m[2])); const pri = Number(m[1]); return { ...r, severity: pri % 8, host: m[3] === '-' ? null : m[3], user: null, signature: m[4] === '-' ? null : m[4], message: message(m[7]) }; }
  m = line.match(/^(?:<(\d{1,3})>)?([A-Z][a-z]{2})\s+(\d{1,2}) (\d\d):(\d\d):(\d\d) (\S+) ([^:\[]+)(?:\[(\d+)\])?: (.*)$/);
  if (m && m[2] in months) { const t = new Date(Date.UTC(year, months[m[2]], Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]))).toISOString(); return { ...base('syslog', t), severity: m[1] ? Number(m[1]) % 8 : null, host: m[7], signature: m[8].trim(), message: message(m[10]) }; }
  m = line.match(/^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)) (\S+) ([^:\[]+)(?:\[(\d+)\])?: (.*)$/);
  if (m) { const tz = m[1].replace(/([+-]\d\d)(\d\d)$/, '$1:$2'); return { ...base('syslog', iso(tz)), host: m[2], signature: m[3].trim(), message: message(m[5]) }; }
  return null;
}

const parsers = {
  syslog: (line, ctx) => syslogLine(line, ctx.year),
  journal: (line, ctx) => syslogLine(line, ctx.year),
  'nfdump-csv': (line, ctx) => {
    const cols = line.split(',').map(c => c.trim());
    if (!ctx.header) { if (cols.includes('sa') && cols.includes('da')) { ctx.header = cols; return 'header'; } return null; }
    const v = Object.fromEntries(ctx.header.map((h, i) => [h, cols[i]]));
    const t = iso(String(v.ts || '').replace(' ', 'T') + (String(v.ts || '').includes('Z') ? '' : 'Z'));
    if (!t || !ip(v.sa) || !ip(v.da)) return null;
    return { ...base('flow', t), src_ip: ip(v.sa), dst_ip: ip(v.da), src_port: port(v.sp), dst_port: port(v.dp), protocol: proto(v.pr), bytes: Number(v.ibyt) || 0, packets: Number(v.ipkt) || 0, action: 'observed' };
  },
  'goflow-json': line => {
    const v = JSON.parse(line); const t = v.TimeFlowStart ? new Date(Number(v.TimeFlowStart) * 1000).toISOString() : iso(v.TimeReceived ? new Date(Number(v.TimeReceived) * 1000) : null);
    if (!t || !ip(v.SrcAddr) || !ip(v.DstAddr)) return null;
    return { ...base('flow', t), src_ip: ip(v.SrcAddr), dst_ip: ip(v.DstAddr), src_port: port(v.SrcPort), dst_port: port(v.DstPort), protocol: proto(v.Proto), bytes: Number(v.Bytes) || 0, packets: Number(v.Packets) || 0, action: 'observed' };
  },
  'suricata-eve': line => {
    const v = JSON.parse(line); const t = iso(v.timestamp); if (!t) return null;
    const common = { src_ip: ip(v.src_ip), dst_ip: ip(v.dest_ip), src_port: port(v.src_port), dst_port: port(v.dest_port), protocol: proto(v.proto) };
    if (v.event_type === 'alert' && v.alert) return { ...base('ids', t), ...common, signature: message(v.alert.signature), severity: Number(v.alert.severity) || null, action: v.alert.action === 'blocked' ? 'blocked' : 'alerted', outcome: v.alert.category ? message(v.alert.category) : null };
    if (v.event_type === 'dns' && v.dns) return { ...base('dns', t), ...common, query: message(v.dns.rrname || v.dns.queries?.[0]?.rrname), action: v.dns.type === 'answer' ? 'answer' : 'query', outcome: v.dns.rcode || null };
    if (v.event_type === 'flow' && v.flow) return { ...base('flow', t), ...common, bytes: (Number(v.flow.bytes_toserver) || 0) + (Number(v.flow.bytes_toclient) || 0), packets: (Number(v.flow.pkts_toserver) || 0) + (Number(v.flow.pkts_toclient) || 0), action: 'observed' };
    return null;
  },
  'bind-query': (line, ctx) => {
    const m = line.match(/^(\d\d-[A-Z][a-z]{2}-\d{4} \d\d:\d\d:\d\d(?:\.\d+)?) .*?client (?:@\S+ )?([0-9a-fA-F:.]+)#(\d+) \(([^)]+)\): query: (\S+) IN (\S+)/);
    if (!m) return null; const [d, mon, y] = m[1].split(' ')[0].split('-'); const t = new Date(Date.UTC(Number(y), months[mon], Number(d), ...m[1].split(' ')[1].split(':').map(Number))).toISOString();
    return { ...base('dns', t), src_ip: ip(m[2]), src_port: port(m[3]), query: m[5].toLowerCase(), action: 'query', outcome: m[6] };
  },
  'isc-dhcpd': (line, ctx) => {
    const s = syslogLine(line, ctx.year); const text = s ? s.message || '' : line; const t = s?.time || null; if (!t) return null;
    const m = text.match(/(DHCPACK|DHCPOFFER|DHCPREQUEST|DHCPDISCOVER|DHCPNAK|DHCPRELEASE|DHCPDECLINE)\s+(?:on|for|of)?\s*([0-9.]+)?\s*(?:\((\S+)\))?\s*(?:to|from)?\s*([0-9a-fA-F:]{17})?\s*(?:\(([^)]*)\))?/);
    if (!m) return null; return { ...base('dhcp', t), action: m[1].toLowerCase(), src_ip: ip(m[2]), mac: m[4] ? m[4].toLowerCase() : null, host: m[5] || s.host, message: message(text) };
  },
  openvpn: (line, ctx) => {
    const s = syslogLine(line, ctx.year); const text = s ? s.message || '' : line; const t = s?.time || iso(line.slice(0, 24)); if (!t) return null;
    let m = text.match(/Username\/Password authentication (succeeded|failed) for username '([^']+)'/); if (m) return { ...base('vpn', t), action: 'authenticate', outcome: m[1] === 'succeeded' ? 'success' : 'failure', user: m[2], src_ip: ip(text.match(/(\d+\.\d+\.\d+\.\d+):\d+/)?.[1]), message: message(text) };
    m = text.match(/Peer Connection Initiated with \[AF_INET6?\]([0-9a-fA-F.:]+):(\d+)/); if (m) return { ...base('vpn', t), action: 'connect', outcome: 'success', src_ip: ip(m[1]), src_port: port(m[2]), message: message(text) };
    m = text.match(/(\S+)\/([0-9.]+):\d+ .*(SIGTERM|client-instance exiting|Inactivity timeout)/); if (m) return { ...base('vpn', t), action: 'disconnect', user: m[1], src_ip: ip(m[2]), message: message(text) };
    return null;
  },
  iptables: (line, ctx) => {
    const s = syslogLine(line, ctx.year); const text = s ? s.message || '' : line; if (!/SRC=/.test(text) || !s?.time) return null;
    const kv = Object.fromEntries([...text.matchAll(/\b([A-Z]+)=(\S*)/g)].map(m => [m[1], m[2]])); const prefix = text.split('IN=')[0].replace(/^\[[^\]]*\]\s*/, '').trim().toLowerCase();
    return { ...base('firewall', s.time), action: /drop|reject|block|deny/.test(prefix) ? 'blocked' : /accept|allow/.test(prefix) ? 'allowed' : 'logged', src_ip: ip(kv.SRC), dst_ip: ip(kv.DST), src_port: port(kv.SPT), dst_port: port(kv.DPT), protocol: proto(kv.PROTO), host: s.host, signature: prefix || null };
  },
  'windows-firewall': line => {
    if (line.startsWith('#')) return 'header';
    const c = line.trim().split(/\s+/); if (c.length < 8) return null; const t = iso(`${c[0]}T${c[1]}Z`); if (!t) return null;
    return { ...base('firewall', t), action: c[2] === 'DROP' ? 'blocked' : c[2] === 'ALLOW' ? 'allowed' : 'logged', protocol: proto(c[3]), src_ip: ip(c[4]), dst_ip: ip(c[5]), src_port: port(c[6]), dst_port: port(c[7]), outcome: c[16] || null };
  },
  'pfsense-filterlog': (line, ctx) => {
    const s = syslogLine(line, ctx.year); const csv = (s ? s.message : line).split(','); if (!s?.time || csv.length < 20) return null;
    const ver = csv[8], offset = ver === '4' ? 0 : null; if (offset === null) return null;
    const protoName = csv[16], src = csv[18], dst = csv[19], hasPorts = ['tcp', 'udp'].includes(String(protoName).toLowerCase());
    return { ...base('firewall', s.time), action: csv[6] === 'block' ? 'blocked' : csv[6] === 'pass' ? 'allowed' : 'logged', protocol: proto(protoName), src_ip: ip(src), dst_ip: ip(dst), src_port: hasPorts ? port(csv[20]) : null, dst_port: hasPorts ? port(csv[21]) : null, host: s.host, signature: `rule ${csv[0]} ${csv[4]} ${csv[7]}` };
  },
};

export function normalizeLogLines(format, lines, { year = new Date().getUTCFullYear() } = {}) {
  const parser = parsers[format]; if (!parser) throw new Error(`unsupported_log_format_${format}`);
  const ctx = { year, header: null }, records = [], rejected = [];
  lines.forEach((line, index) => {
    if (!line.trim()) return;
    let result = null; try { result = parser(line, ctx); } catch { result = null; }
    if (result === 'header') return;
    if (!result || !result.time) { rejected.push({ line: index + 1, reason: 'unparsed' }); return; }
    records.push({ ...result, line: index + 1 });
  });
  return { records, rejected };
}
