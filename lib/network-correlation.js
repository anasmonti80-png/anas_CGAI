// CG-099 Network threat correlation across DNS, TLS metadata, HTTP proxy, flow logs and network IDS. A finding is
// raised only when an anchor (IDS alert, algorithm-like domain, proxy block, TLS without a server name to an external
// address) is supported by at least one other independent source for the same internal host within the window.
// Limits are explicit: payloads are never decrypted or stored, and encryption hides parts of the picture.
const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fc|fd|fe80)/i;
export const isExternal = ip => Boolean(ip) && !PRIVATE.test(ip);
export function entropy(s) { const m = new Map(); for (const c of s) m.set(c, (m.get(c) || 0) + 1); return [...m.values()].reduce((h, n) => h - (n / s.length) * Math.log2(n / s.length), 0); }
export function algorithmLike(domain) {
  if (!domain) return false; const labels = domain.toLowerCase().replace(/\.$/, '').split('.'); if (labels.length < 2) return false;
  const label = labels.at(-2).length >= 4 ? labels.at(-2) : labels[0]; return label.length >= 12 && entropy(label) >= 3.5 && /\d/.test(label) && !/^(xn--)/.test(label);
}
export const LIMITS = [
  ['Payloads are not decrypted or stored; only connection metadata is used.', 'لا تُفك المحتويات المشفرة ولا تُخزن؛ تُستخدم بيانات الاتصال الوصفية فقط.'],
  ['TLS 1.3 with Encrypted Client Hello hides the server name; QUIC and DNS over HTTPS or TLS bypass classic DNS and proxy logs.', 'TLS 1.3 مع Encrypted Client Hello يخفي اسم الخادم؛ وQUIC وDNS عبر HTTPS أو TLS تتجاوز سجلات DNS والوكيل التقليدية.'],
  ['Proxy URLs are reduced to the host name: paths and query strings are dropped for privacy.', 'تُختصر روابط الوكيل إلى اسم المضيف: تُحذف المسارات ومعاملات الاستعلام حفاظًا على الخصوصية.'],
  ['Flow logs show who talked to whom and how much, not what was said.', 'سجلات التدفق تبين من تحدث مع من وكم، لا ماذا قيل.'],
];
export function correlate(records, { windowMinutes = 15 } = {}) {
  const win = windowMinutes * 60000, rs = records.filter(r => r.time && ['dns', 'tls', 'proxy', 'flow', 'ids'].includes(r.category)).map(r => ({ ...r, t: Date.parse(r.time) }));
  const bySrc = new Map(); for (const r of rs) { if (!r.src_ip) continue; if (!bySrc.has(r.src_ip)) bySrc.set(r.src_ip, []); bySrc.get(r.src_ip).push(r); }
  const anchors = [];
  for (const r of rs) {
    if (r.category === 'ids' && ['alerted', 'blocked'].includes(r.action)) anchors.push({ r, type: 'ids-alert', severity: r.severity === 1 ? 'high' : r.severity === 2 ? 'medium' : 'low', label: r.signature });
    else if (r.category === 'dns' && algorithmLike(r.query)) anchors.push({ r, type: 'algorithm-like-domain', severity: 'medium', label: r.query });
    else if (r.category === 'proxy' && r.action === 'blocked') anchors.push({ r, type: 'proxy-blocked', severity: 'medium', label: r.query });
    else if (r.category === 'tls' && !r.query && isExternal(r.dst_ip) && r.outcome === 'established') anchors.push({ r, type: 'tls-without-server-name', severity: 'low', label: r.dst_ip });
  }
  const out = new Map();
  for (const a of anchors) {
    const near = (bySrc.get(a.r.src_ip) || []).filter(x => x !== a.r && Math.abs(x.t - a.r.t) <= win);
    // For a DNS anchor the destination address is the resolver, not the contacted server.
    const domain = a.r.query || null, dst = a.r.category === 'dns' ? null : a.r.dst_ip || null;
    const dstOf = new Set([dst, ...near.filter(x => x.category === 'tls' && domain && x.query === domain).map(x => x.dst_ip), ...near.filter(x => x.category === 'proxy' && domain && x.query === domain).map(x => x.dst_ip)].filter(Boolean));
    const related = near.filter(x => (domain && x.query === domain) || (x.dst_ip && dstOf.has(x.dst_ip)));
    const sources = [...new Set([a.r.category, ...related.map(x => x.category)])];
    if (sources.length < 2) continue;
    const all = [a.r, ...related], key = `${a.r.src_ip}|${domain || [...dstOf][0] || ''}|${a.type}`, prev = out.get(key);
    const item = { key, src_ip: a.r.src_ip, domain, dst_ips: [...dstOf].slice(0, 10), anchor: a.type, label: String(a.label || '').slice(0, 200), sources: sources.sort(), events: all.length, bytes: all.reduce((n, x) => n + (x.category === 'flow' ? x.bytes || 0 : 0), 0), first_seen: new Date(Math.min(...all.map(x => x.t))).toISOString(), last_seen: new Date(Math.max(...all.map(x => x.t))).toISOString(), severity: sources.length >= 3 && a.severity === 'medium' ? 'high' : a.severity, confidence: sources.length >= 3 ? 'high' : 'medium' };
    if (!prev || prev.sources.length < item.sources.length) out.set(key, item);
  }
  const present = new Set(rs.map(r => r.category));
  return { findings: [...out.values()].sort((a, b) => ({ high: 0, medium: 1, low: 2 })[a.severity] - ({ high: 0, medium: 1, low: 2 })[b.severity]), sources_present: ['dns', 'tls', 'proxy', 'flow', 'ids'].map(c => ({ source: c, present: present.has(c), records: rs.filter(r => r.category === c).length })), limits: LIMITS.map(([en, ar]) => ({ en, ar })) };
}

// CG-113 Cross-domain signal correlation. Existing alerts remain the source of truth:
// this view groups noisy copies but never changes, suppresses or resolves an alert.
const SIGNAL_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export const SIGNAL_FAMILIES = ['endpoint', 'identity', 'network', 'cloud'];
export function signalFamily({ rule_id = '', evidence_kinds = [] } = {}) {
  const rule = String(rule_id).toUpperCase(), kinds = evidence_kinds.map(String);
  if (rule.includes('CLOUD') || kinds.some(k => k.startsWith('cloud.'))) return 'cloud';
  if (rule.includes('IDENT') || rule.includes('ACCESS') || kinds.some(k => k.startsWith('identity.') || k === 'auth.failed')) return 'identity';
  if (/CG-(NET|FW|LOG-IDS|WAF|NAC|ZTNA)/.test(rule) || kinds.some(k => k.startsWith('network.') || k === 'firewall.ruleset' || k === 'log.batch')) return 'network';
  if (/CG-(DET|ENDPOINT|TAMPER|RANSOM|FILE|AGENT)/.test(rule) || kinds.some(k => k.startsWith('endpoint.') || ['agent.inventory_report', 'change.sensitive', 'file.triage'].includes(k))) return 'endpoint';
  return null;
}
const signalKey = alert => `${alert.family}|${alert.rule_id}|${alert.asset_id}|${String(alert.title || '').trim().toLowerCase().replace(/\s+/g, ' ')}`;
export function correlateSignals(alerts, { windowMinutes = 30 } = {}) {
  const windowMs = windowMinutes * 60000, eligible = alerts.filter(a => a.asset_id && SIGNAL_FAMILIES.includes(a.family) && Number.isFinite(Date.parse(a.first_seen))).sort((a, b) => Date.parse(a.first_seen) - Date.parse(b.first_seen) || String(a.id).localeCompare(String(b.id)));
  const byAsset = new Map(); for (const alert of eligible) { if (!byAsset.has(alert.asset_id)) byAsset.set(alert.asset_id, []); byAsset.get(alert.asset_id).push(alert); }
  const correlations = [];
  for (const [assetId, rows] of byAsset) {
    const buckets = [];
    for (const row of rows) { let bucket = buckets.at(-1); if (!bucket || Date.parse(row.first_seen) - bucket.last > windowMs) { bucket = { first: Date.parse(row.first_seen), last: Date.parse(row.last_seen || row.first_seen), rows: [] }; buckets.push(bucket); } bucket.rows.push(row); bucket.last = Math.max(bucket.last, Date.parse(row.last_seen || row.first_seen)); }
    for (const bucket of buckets) {
      const families = [...new Set(bucket.rows.map(r => r.family))].sort(); if (families.length < 2) continue;
      const compact = new Map();
      for (const row of bucket.rows) { const key = signalKey(row), item = compact.get(key) || { key, family: row.family, rule_id: row.rule_id, severity: row.severity, title: row.title, alert_ids: [], occurrences: 0, evidence_ids: [], first_seen: row.first_seen, last_seen: row.last_seen || row.first_seen }; item.alert_ids.push(row.id); item.occurrences += Number(row.occurrences || 1); item.evidence_ids.push(...(row.evidence_ids || [])); if ((SIGNAL_ORDER[row.severity] ?? 99) < (SIGNAL_ORDER[item.severity] ?? 99)) item.severity = row.severity; if (row.first_seen < item.first_seen) item.first_seen = row.first_seen; if ((row.last_seen || row.first_seen) > item.last_seen) item.last_seen = row.last_seen || row.first_seen; item.evidence_ids = [...new Set(item.evidence_ids)]; compact.set(key, item); }
      const signals = [...compact.values()].sort((a, b) => (SIGNAL_ORDER[a.severity] ?? 99) - (SIGNAL_ORDER[b.severity] ?? 99) || a.family.localeCompare(b.family));
      const important = bucket.rows.filter(r => ['critical', 'high'].includes(r.severity)).map(r => ({ id: r.id, family: r.family, rule_id: r.rule_id, severity: r.severity, title: r.title }));
      correlations.push({ key: `${assetId}|${new Date(bucket.first).toISOString()}`, asset_id: assetId, families, first_seen: new Date(bucket.first).toISOString(), last_seen: new Date(bucket.last).toISOString(), severity: signals[0].severity, raw_alerts: bucket.rows.length, deduplicated_signals: signals.length, reduced_noise: bucket.rows.length - signals.length, signals, important_alerts: important, important_alerts_preserved: important.length, suppressed_alerts: 0 });
    }
  }
  return { correlations: correlations.sort((a, b) => (SIGNAL_ORDER[a.severity] ?? 99) - (SIGNAL_ORDER[b.severity] ?? 99) || b.last_seen.localeCompare(a.last_seen)), raw_alerts: eligible.length, correlated_alerts: correlations.reduce((n, c) => n + c.raw_alerts, 0), deduplicated_signals: correlations.reduce((n, c) => n + c.deduplicated_signals, 0), suppressed_alerts: 0, window_minutes: windowMinutes };
}
