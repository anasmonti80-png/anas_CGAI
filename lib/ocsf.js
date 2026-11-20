// CG-103 OCSF normalization layer. CyberGuard's normalized log records are converted to OCSF 1.3.0 event classes
// with the schema version, the original source and format, the fields each class needs that are missing, and the
// meaning lost in conversion stated per record, so a downstream SIEM never receives a silently degraded event.
export const OCSF_VERSION = '1.3.0';
const C = { auth: [3002, 3, 'Authentication'], network: [4001, 4, 'Network Activity'], http: [4002, 4, 'HTTP Activity'], dns: [4003, 4, 'DNS Activity'], dhcp: [4004, 4, 'DHCP Activity'], finding: [2004, 2, 'Detection Finding'], api: [6003, 6, 'API Activity'], base: [0, 0, 'Base Event'] };
const byCategory = { nac: 'auth', ztna: 'auth', vpn: 'auth', flow: 'network', firewall: 'network', tls: 'network', proxy: 'http', dns: 'dns', dhcp: 'dhcp', ids: 'finding', waf: 'finding', 'cloud-audit': 'api', syslog: 'base' };
const REQUIRED = { auth: ['user', 'src_endpoint'], network: ['src_endpoint', 'dst_endpoint'], http: ['src_endpoint', 'http_request'], dns: ['query'], dhcp: ['src_endpoint'], finding: ['finding_info'], api: ['api', 'actor'], base: [] };
const endpoint = (ip, port, host) => ip || host ? Object.fromEntries(Object.entries({ ip: ip || undefined, port: port ?? undefined, hostname: host || undefined }).filter(([, v]) => v !== undefined)) : undefined;
const sev = r => r.severity == null ? { id: 0, lost: false } : r.category === 'syslog' ? { id: [6, 6, 5, 4, 3, 2, 1, 1][r.severity] ?? 0, lost: true } : { id: { 1: 4, 2: 3, 3: 2, 4: 1 }[r.severity] ?? 0, lost: true };
export function toOcsf(r, { format, source_name, product }) {
  const kind = byCategory[r.category] || 'base', [class_uid, category_uid, class_name] = C[kind], lost = [], s = sev(r);
  const success = r.outcome === 'success' || r.outcome === 'established' || /^2\d\d$/.test(String(r.outcome || '')), failure = r.outcome === 'failure' || r.outcome === 'failed';
  const activity_id = kind === 'auth' ? 1 : kind === 'dns' ? 1 : kind === 'http' ? ({ GET: 3, POST: 6, PUT: 7, DELETE: 2, CONNECT: 1 }[r.message] ?? 99) : kind === 'network' ? (r.action === 'blocked' ? 5 : 6) : kind === 'finding' ? 1 : kind === 'api' ? 99 : 0;
  const o = { class_uid, class_name, category_uid, activity_id, type_uid: class_uid * 100 + activity_id, severity_id: s.id, time: Date.parse(r.time), status_id: success ? 1 : failure ? 2 : 0,
    metadata: { version: OCSF_VERSION, product: { name: product || source_name, vendor_name: format }, log_name: source_name, original_time: r.time },
    src_endpoint: endpoint(r.src_ip, r.src_port, kind === 'auth' ? r.host : undefined), dst_endpoint: endpoint(r.dst_ip, r.dst_port, kind === 'http' ? r.query : undefined), message: kind === 'http' ? undefined : r.message || undefined };
  if (r.protocol) o.connection_info = { protocol_name: r.protocol };
  if (kind === 'auth' && r.user) o.user = { name: r.user };
  if (kind === 'auth' && r.mac) o.src_endpoint = { ...(o.src_endpoint || {}), mac: r.mac };
  if (kind === 'dns' && r.query) o.query = { hostname: r.query };
  if (kind === 'network' && r.category === 'tls') o.tls = { sni: r.query || undefined, version: r.signature || undefined };
  if (kind === 'network' && (r.bytes != null || r.packets != null)) o.traffic = { bytes: r.bytes ?? undefined, packets: r.packets ?? undefined };
  if (kind === 'http') { o.http_request = r.query ? { url: { hostname: r.query } } : undefined; o.http_response = r.outcome ? { code: Number(r.outcome) || undefined } : undefined; if (r.query) lost.push('URL path and query string are not kept (privacy)'); }
  if (kind === 'finding') o.finding_info = r.signature ? { title: r.signature, uid: `${format}:${r.line ?? ''}` } : undefined;
  if (kind === 'api') { o.api = r.signature ? { operation: r.signature } : undefined; o.actor = r.user ? { user: { name: r.user } } : undefined; }
  if (kind === 'http' && r.action) o.disposition_id = r.action === 'blocked' ? 2 : 1;
  if (r.category === 'firewall' || (kind === 'network' && r.action)) o.disposition_id = r.action === 'blocked' || r.action === 'deny' ? 2 : r.action === 'allowed' || r.action === 'allow' || r.action === 'observed' ? 1 : 0;
  if (s.lost) lost.push(`source severity ${r.severity} mapped to OCSF severity_id ${s.id} (scales differ)`);
  if (kind === 'base') lost.push('no specific OCSF class for this source; kept as Base Event with the message only');
  if (r.category === 'tls') lost.push('TLS certificate details are not in the source record');
  const missing = REQUIRED[kind].filter(f => o[f] === undefined);
  const clean = JSON.parse(JSON.stringify(o));
  return { event: clean, mapping: { class_name, format, missing_fields: missing, meaning_lost: lost } };
}
export function exportOcsf(batches, { limit = 1000 } = {}) {
  const events = [], quality = new Map();
  for (const b of batches) for (const r of b.records) {
    const x = toOcsf(r, b), key = `${b.format}|${x.mapping.class_name}`, q = quality.get(key) || { format: b.format, class_name: x.mapping.class_name, records: 0, missing: {}, lossy: 0 };
    q.records++; for (const f of x.mapping.missing_fields) q.missing[f] = (q.missing[f] || 0) + 1; if (x.mapping.meaning_lost.length) q.lossy++; quality.set(key, q);
    if (events.length < limit) events.push({ ...x.event, unmapped: { cyberguard_mapping: x.mapping } });
  }
  return { ocsf_version: OCSF_VERSION, events, quality: [...quality.values()].map(q => ({ ...q, complete: Object.keys(q.missing).length === 0 })) };
}
