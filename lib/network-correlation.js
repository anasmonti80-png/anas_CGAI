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
