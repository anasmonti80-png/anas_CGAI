// CG-018 log normalisation: raw lines from syslog/journald, NetFlow/IPFIX exports, IDS/IPS, DNS, DHCP,
// VPN and firewall logs become one common event model. Unparseable lines are rejected with a reason.
import { isIP } from 'node:net';
import { redact } from './common.js';

export const logFormats = {
  syslog: 'syslog', journal: 'syslog', 'nfdump-csv': 'flow', 'goflow-json': 'flow', 'suricata-eve': 'ids',
  'bind-query': 'dns', 'isc-dhcpd': 'dhcp', openvpn: 'vpn', iptables: 'firewall', 'windows-firewall': 'firewall', 'pfsense-filterlog': 'firewall',
  'modsecurity-json': 'waf', 'aws-waf-json': 'waf', dnsmasq: 'dns', 'zeek-conn': 'flow', freeradius: 'nac', 'cloudflare-access-json': 'ztna',
  'aws-cloudtrail-json': 'cloud-audit', 'aws-vpc-flow': 'flow', 'aws-network-firewall-json': 'ids',
  'azure-activity-json': 'cloud-audit', 'azure-vnet-flow-json': 'flow', 'azure-firewall-json': 'firewall',
  'gcp-audit-json': 'cloud-audit', 'gcp-vpc-flow-json': 'flow', 'gcp-firewall-json': 'firewall', 'gcp-armor-json': 'waf',
  'azure-nsg-flow-json': 'flow',
};
export const formatControl = { 'suricata-eve': 'ids-ips', 'modsecurity-json': 'waf', 'aws-waf-json': 'waf', dnsmasq: 'dns-security', 'zeek-conn': 'ndr', freeradius: 'nac', 'cloudflare-access-json': 'ztna', 'aws-network-firewall-json': 'ids-ips', 'azure-firewall-json': 'ids-ips', 'gcp-armor-json': 'waf' };
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
    if (v.event_type === 'dns' && v.dns) return { ...base('dns', t), ...common, query: message(v.dns.rrname || v.dns.queries?.[0]?.rrname), action: v.dns.type === 'answer' ? 'answer' : 'query', outcome: v.dns.rcode || v.dns.rrtype || null };
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
  'modsecurity-json': line => {
    const t = JSON.parse(line).transaction; if (!t) return null;
    const stamp = String(t.time_stamp || ''), legacy = stamp.match(/^\w{3} (\w{3}) +(\d+) (\d\d):(\d\d):(\d\d) (\d{4})$/);
    const time = legacy && legacy[1] in months ? new Date(Date.UTC(Number(legacy[6]), months[legacy[1]], Number(legacy[2]), Number(legacy[3]), Number(legacy[4]), Number(legacy[5]))).toISOString() : iso(stamp); if (!time) return null;
    const msg = (t.messages || [])[0] || {}; const code = Number(t.response?.http_code) || null;
    return { ...base('waf', time), action: code === 403 || code === 406 ? 'blocked' : (t.messages || []).length ? 'alerted' : 'allowed', outcome: code ? String(code) : null, src_ip: ip(t.client_ip), src_port: port(t.client_port), dst_ip: ip(t.host_ip), dst_port: port(t.host_port), protocol: 'http', signature: message(msg.message || null), severity: Number(msg.details?.severity) || null, query: message(`${t.request?.method || ''} ${t.request?.uri || ''}`.trim()) };
  },
  'aws-waf-json': line => {
    const v = JSON.parse(line); const time = Number.isFinite(Number(v.timestamp)) ? new Date(Number(v.timestamp)).toISOString() : null; if (!time || !v.httpRequest) return null;
    return { ...base('waf', time), action: v.action === 'BLOCK' ? 'blocked' : v.action === 'COUNT' ? 'alerted' : 'allowed', src_ip: ip(v.httpRequest.clientIp), protocol: 'http', signature: message(v.terminatingRuleId || null), outcome: v.httpRequest.country || null, query: message(`${v.httpRequest.httpMethod || ''} ${v.httpRequest.uri || ''}`.trim()) };
  },
  dnsmasq: (line, ctx) => {
    const s = syslogLine(line, ctx.year); if (!s?.time) return null; const text = s.message || '';
    let m = text.match(/^query\[(\w+)\] (\S+) from (\S+)/); if (m) return { ...base('dns', s.time), action: 'query', outcome: m[1], query: m[2].toLowerCase(), src_ip: ip(m[3]), host: s.host };
    m = text.match(/^(?:gravity blocked|blacklisted|regex blacklisted|config|special domain|exactly blocked) (\S+) is (\S+)/); if (m) return { ...base('dns', s.time), action: 'blocked', outcome: 'blocked', query: m[1].toLowerCase(), host: s.host, signature: text.split(' ').slice(0, 2).join(' ') };
    m = text.match(/^(?:reply|cached) (\S+) is (\S+)/); if (m) return { ...base('dns', s.time), action: 'answer', query: m[1].toLowerCase(), outcome: m[2].slice(0, 60), host: s.host };
    return null;
  },
  'zeek-conn': (line, ctx) => {
    if (line.startsWith('#fields')) { ctx.header = line.split('\t').slice(1); return 'header'; }
    if (line.startsWith('#')) return 'header';
    if (!ctx.header) return null; const c = line.split('\t'), v = Object.fromEntries(ctx.header.map((h, i) => [h, c[i]]));
    const time = Number.isFinite(Number(v.ts)) ? new Date(Number(v.ts) * 1000).toISOString() : null; if (!time || !ip(v['id.orig_h']) || !ip(v['id.resp_h'])) return null;
    const num = x => (x && x !== '-' ? Number(x) || 0 : 0);
    return { ...base('flow', time), action: 'observed', src_ip: ip(v['id.orig_h']), src_port: port(v['id.orig_p']), dst_ip: ip(v['id.resp_h']), dst_port: port(v['id.resp_p']), protocol: proto(v.proto), bytes: num(v.orig_bytes) + num(v.resp_bytes), outcome: v.conn_state && v.conn_state !== '-' ? v.conn_state : null, signature: v.service && v.service !== '-' ? v.service : null };
  },
  freeradius: (line, ctx) => {
    const m = line.match(/^\w{3} (\w{3}) +(\d+) (\d\d):(\d\d):(\d\d) (\d{4}) : Auth: (?:\(\d+\) )?(Login OK|Login incorrect|Invalid user)(?: \([^)]*\))?: \[([^\]\/]*)[^\]]*\] \(from client (\S+) port (\S+)(?: cli (\S+))?\)/);
    if (!m || !(m[1] in months)) return null; const time = new Date(Date.UTC(Number(m[6]), months[m[1]], Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]))).toISOString();
    const mac = m[11] ? m[11].toLowerCase().replace(/[^0-9a-f]/g, '').replace(/(..)(?!$)/g, '$1:') : null;
    return { ...base('nac', time), action: 'authenticate', outcome: m[7] === 'Login OK' ? 'success' : 'failure', user: m[8] || null, host: m[9], signature: `port ${m[10]}`, mac: mac && /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac) ? mac : null };
  },
  'cloudflare-access-json': line => {
    const v = JSON.parse(line); const time = iso(v.CreatedAt || v.Datetime); if (!time) return null;
    return { ...base('ztna', time), action: String(v.Action || 'login').toLowerCase(), outcome: v.Allowed === true ? 'success' : v.Allowed === false ? 'failure' : null, user: v.UserEmail || v.Email || null, src_ip: ip(v.IPAddress || v.ClientIP), query: message(v.AppDomain || v.Application || null), signature: message(v.Country ? `country ${v.Country}` : null) };
  },
  // CG-046 CloudTrail record (one JSON record per line; scripts/aws-connector.js splits {"Records":[...]} files).
  'aws-cloudtrail-json': line => {
    const v = JSON.parse(line); const time = iso(v.eventTime); if (!time || !v.eventSource || !v.eventName) return null;
    const who = v.userIdentity || {}, svc = String(v.eventSource).replace(/\.amazonaws\.com$/, ''), failed = Boolean(v.errorCode) || v.responseElements?.ConsoleLogin === 'Failure';
    return { ...base('cloud-audit', time), action: message(v.eventName), outcome: failed ? 'failure' : 'success', src_ip: ip(v.sourceIPAddress), user: message(who.type === 'Root' ? 'root' : who.arn || who.principalId || who.type || null), host: message(v.recipientAccountId || who.accountId || null), signature: message(`${svc}:${v.eventName}`), query: message(v.awsRegion || null), message: message(v.errorCode ? `${v.errorCode} ${v.errorMessage || ''}`.trim() : null) };
  },
  // CG-046 VPC Flow Logs: default v2 fields, or the field order from the header line that S3 deliveries carry.
  'aws-vpc-flow': (line, ctx) => {
    const c = line.trim().split(/\s+/);
    if (c[0] === 'version' || c.includes('srcaddr')) { ctx.header = c; return 'header'; }
    const fields = ctx.header || ['version', 'account-id', 'interface-id', 'srcaddr', 'dstaddr', 'srcport', 'dstport', 'protocol', 'packets', 'bytes', 'start', 'end', 'action', 'log-status'];
    const v = Object.fromEntries(fields.map((f, i) => [f, c[i]])); if (v['log-status'] === 'NODATA' || v['log-status'] === 'SKIPDATA') return null;
    const start = Number(v.start); if (!Number.isFinite(start) || !ip(v.srcaddr) || !ip(v.dstaddr)) return null;
    const n = x => (x !== undefined && x !== '-' && Number.isFinite(Number(x)) ? Number(x) : null);
    return { ...base('flow', new Date(start * 1000).toISOString()), action: v.action === 'REJECT' ? 'blocked' : v.action === 'ACCEPT' ? 'allowed' : 'observed', src_ip: ip(v.srcaddr), dst_ip: ip(v.dstaddr), src_port: port(v.srcport), dst_port: port(v.dstport), protocol: proto(v.protocol), bytes: n(v.bytes), packets: n(v.packets), host: message(v['interface-id'] || null), signature: message(v['account-id'] ? `account ${v['account-id']}` : null) };
  },
  // CG-046 AWS Network Firewall alert and flow logs (Suricata EVE inside the "event" member).
  'aws-network-firewall-json': line => {
    const v = JSON.parse(line), e = v.event; if (!e) return null; const time = iso(String(e.timestamp || '').replace(/([+-]\d\d)(\d\d)$/, '$1:$2')) || (Number(v.event_timestamp) ? new Date(Number(v.event_timestamp) * 1000).toISOString() : null); if (!time) return null;
    const common = { src_ip: ip(e.src_ip), dst_ip: ip(e.dest_ip), src_port: port(e.src_port), dst_port: port(e.dest_port), protocol: proto(e.proto), host: message(v.firewall_name || null) };
    if (e.event_type === 'alert' && e.alert) return { ...base('ids', time), ...common, action: e.alert.action === 'blocked' ? 'blocked' : 'alerted', signature: message(e.alert.signature || `sid ${e.alert.signature_id}`), severity: Number.isInteger(e.alert.severity) ? e.alert.severity : null };
    if (e.event_type === 'netflow' || e.event_type === 'flow') return { ...base('flow', time), ...common, action: 'observed', bytes: (e.netflow?.bytes ?? e.flow?.bytes_toserver ?? null), packets: (e.netflow?.pkts ?? e.flow?.pkts_toserver ?? null) };
    return null;
  },
  // CG-047 Azure Monitor activity log: storage/Event Hub export records or "az monitor activity-log list" entries.
  'azure-activity-json': line => {
    const v = JSON.parse(line), op = v.operationName?.value || v.operationName, time = iso(v.time || v.eventTimestamp); if (!time || !op) return null;
    const result = String(v.resultType || v.status?.value || v.status || '').toLowerCase(), claims = v.identity?.claims || v.claims || {};
    const who = v.caller || claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn'] || claims.upn || claims.appid || null, sub = String(v.resourceId || v.subscriptionId || '').match(/subscriptions\/([0-9a-f-]{36})/i)?.[1] || v.subscriptionId || null;
    return { ...base('cloud-audit', time), action: message(String(op).split('/').pop()), outcome: /fail/.test(result) ? 'failure' : /succe|start|accept/.test(result) ? 'success' : null, src_ip: ip(v.callerIpAddress || v.httpRequest?.clientIpAddress), user: message(who), host: message(sub ? String(sub).toLowerCase() : null), signature: message(String(op).toLowerCase()), query: message(v.resourceId || null), message: message(v.category?.value || v.category || null) };
  },
  // CG-047 VNet flow log tuple (version 4): time,src,dst,sport,dport,proto,direction,state,encryption,pkts,bytes,pkts,bytes
  'azure-vnet-flow-json': line => {
    const v = JSON.parse(line), c = String(v.tuple || '').split(','); if (c.length < 8) return null; const ms = Number(c[0]); if (!Number.isFinite(ms) || !ip(c[1]) || !ip(c[2])) return null;
    const n = x => (x !== undefined && x !== '' && Number.isFinite(Number(x)) ? Number(x) : null), sum = (a, b) => (n(a) === null && n(b) === null ? null : (n(a) || 0) + (n(b) || 0));
    return { ...base('flow', new Date(ms > 1e12 ? ms : ms * 1000).toISOString()), action: c[7] === 'D' ? 'blocked' : 'allowed', outcome: { B: 'begin', C: 'continuing', E: 'end', D: 'denied' }[c[7]] || null, src_ip: ip(c[1]), dst_ip: ip(c[2]), src_port: port(c[3]), dst_port: port(c[4]), protocol: proto(c[5] === 'T' ? 6 : c[5] === 'U' ? 17 : c[5]), packets: sum(c[9], c[11]), bytes: sum(c[10], c[12]), signature: message(v.rule || null), host: message(v.target ? String(v.target).split('/').pop() : null), message: message(c[6] === 'I' ? 'inbound' : c[6] === 'O' ? 'outbound' : null) };
  },
  // CG-047 Azure Firewall structured logs (AZFWNetworkRule, AZFWApplicationRule, AZFWNatRule, AZFWIdpsSignature, AZFWThreatIntel).
  'azure-firewall-json': line => {
    const v = JSON.parse(line), p = v.properties || v, cat = String(v.category || v.Type || ''), time = iso(v.time || v.TimeGenerated); if (!time || !/^AZFW/.test(cat)) return null;
    const common = { src_ip: ip(p.SourceIp), dst_ip: ip(p.DestinationIp), src_port: port(p.SourcePort), dst_port: port(p.DestinationPort), protocol: proto(p.Protocol), host: message(String(v.resourceId || v._ResourceId || '').split('/').pop() || null) };
    if (cat === 'AZFWIdpsSignature' || cat === 'AZFWThreatIntel') return { ...base('ids', time), ...common, action: /deny|drop/i.test(p.Action) ? 'blocked' : 'alerted', signature: message(p.Description || p.ThreatDescription || `sid ${p.SignatureId}`), severity: Number.isInteger(p.Severity) ? p.Severity : cat === 'AZFWThreatIntel' ? 1 : null };
    return { ...base('firewall', time), ...common, action: /deny|drop/i.test(p.Action) ? 'blocked' : 'allowed', signature: message([p.RuleCollectionGroup, p.RuleCollection, p.Rule].filter(Boolean).join('/') || p.Policy || null), query: message(p.Fqdn || p.TargetUrl || null) };
  },
  // CG-051 NSG flow log tuple: v1 time,src,dst,sport,dport,proto,direction,decision ; v2 adds state,pkts,bytes,pkts,bytes
  'azure-nsg-flow-json': line => {
    const v = JSON.parse(line), c = String(v.tuple || '').split(','); if (c.length < 8) return null; const sec = Number(c[0]); if (!Number.isFinite(sec) || !ip(c[1]) || !ip(c[2])) return null;
    const n = x => (x !== undefined && x !== '' && Number.isFinite(Number(x)) ? Number(x) : null), sum = (a, b) => (n(a) === null && n(b) === null ? null : (n(a) || 0) + (n(b) || 0));
    return { ...base('flow', new Date(sec * 1000).toISOString()), action: c[7] === 'D' ? 'blocked' : 'allowed', outcome: { B: 'begin', C: 'continuing', E: 'end' }[c[8]] || null, src_ip: ip(c[1]), dst_ip: ip(c[2]), src_port: port(c[3]), dst_port: port(c[4]), protocol: proto(c[5] === 'T' ? 6 : c[5] === 'U' ? 17 : c[5]), packets: sum(c[9], c[11]), bytes: sum(c[10], c[12]), signature: message(v.rule || null), host: message(v.nsg || null), message: message(`NSG flow log v${v.version ?? '?'} (retiring 2027-09-30)`) };
  },
  // CG-048 Cloud Audit Logs (LogEntry with an AuditLog protoPayload).
  'gcp-audit-json': line => {
    const v = JSON.parse(line), a = v.protoPayload; const time = iso(v.timestamp || v.receiveTimestamp); if (!time || !a?.methodName) return null;
    const code = a.status?.code;
    return { ...base('cloud-audit', time), action: message(String(a.methodName).split('.').pop()), outcome: code ? 'failure' : 'success', src_ip: ip(a.requestMetadata?.callerIp), user: message(a.authenticationInfo?.principalEmail || null), host: message(v.resource?.labels?.project_id || null), signature: message(a.methodName), query: message(a.resourceName || null), message: message(code ? `${code} ${a.status?.message || ''}`.trim() : String(v.logName || '').split('%2F').pop() || null) };
  },
  // CG-048 VPC Flow Logs (LogEntry jsonPayload with connection, bytes_sent, packets_sent, start_time).
  'gcp-vpc-flow-json': line => {
    const v = JSON.parse(line), p = v.jsonPayload || {}, c = p.connection; const time = iso(p.start_time || v.timestamp); if (!time || !c || !ip(c.src_ip) || !ip(c.dest_ip)) return null;
    return { ...base('flow', time), action: 'observed', src_ip: ip(c.src_ip), dst_ip: ip(c.dest_ip), src_port: port(c.src_port), dst_port: port(c.dest_port), protocol: proto(c.protocol), bytes: Number.isFinite(Number(p.bytes_sent)) ? Number(p.bytes_sent) : null, packets: Number.isFinite(Number(p.packets_sent)) ? Number(p.packets_sent) : null, host: message(p.src_instance?.vm_name || p.dest_instance?.vm_name || v.resource?.labels?.subnetwork_name || null), signature: message(p.reporter ? `reporter ${p.reporter}` : null) };
  },
  // CG-048 Firewall Rules Logging (LogEntry jsonPayload with connection, disposition and rule_details).
  'gcp-firewall-json': line => {
    const v = JSON.parse(line), p = v.jsonPayload || {}, c = p.connection; const time = iso(v.timestamp); if (!time || !c || !p.disposition) return null;
    return { ...base('firewall', time), action: p.disposition === 'DENIED' ? 'blocked' : 'allowed', src_ip: ip(c.src_ip), dst_ip: ip(c.dest_ip), src_port: port(c.src_port), dst_port: port(c.dest_port), protocol: proto(c.protocol), host: message(p.instance?.vm_name || null), signature: message(p.rule_details?.reference || null) };
  },
  // CG-048 Cloud Armor: external Application Load Balancer request logs with enforcedSecurityPolicy.
  'gcp-armor-json': line => {
    const v = JSON.parse(line), p = v.jsonPayload || {}, sp = p.enforcedSecurityPolicy, r = v.httpRequest || {}; const time = iso(v.timestamp); if (!time || !sp) return null;
    const expr = (sp.preconfiguredExprIds || [])[0] || null;
    return { ...base('waf', time), action: sp.outcome === 'DENY' ? 'blocked' : sp.configuredAction === 'DENY' ? 'alerted' : 'allowed', src_ip: ip(r.remoteIp), protocol: 'http', signature: message(expr || `${sp.name} priority ${sp.priority}`), severity: expr ? 2 : null, outcome: message(r.status ? String(r.status) : null), query: message(`${r.requestMethod || ''} ${r.requestUrl || ''}`.trim() || null) };
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
