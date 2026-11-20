// CG-109 Data security posture and DLP signals. Data stores are declared with classification, owner, location,
// encryption, exposure, personal data and legal basis; CyberGuard checks the posture and watches for unusually large
// outbound transfers from flow metadata against each host's own baseline. Content is never inspected: a store may be
// marked as approved for content inspection only with a legal reference, a privacy reviewer and a scope.
const RANK = { public: 0, internal: 1, confidential: 2, restricted: 3 }, AR = { public: 'عام', internal: 'داخلي', confidential: 'سري', restricted: 'مقيد' };
export function storeFindings(s, { allowedRegions = [] } = {}) {
  const f = [], add = (id, severity, en, ar) => f.push({ id, severity, title: en, title_ar: ar }), sensitive = RANK[s.classification] >= 2;
  if (s.public_access && sensitive) add('sensitive-public', 'critical', `${s.classification} store ${s.store_id} is publicly accessible`, `مخزن ${s.store_id} بتصنيف ${AR[s.classification]} متاح للعامة`);
  else if (s.public_access && s.classification === 'internal') add('internal-public', 'high', `Internal store ${s.store_id} is publicly accessible`, `المخزن الداخلي ${s.store_id} متاح للعامة`);
  if (sensitive && s.encryption_at_rest !== 'enabled') add('unencrypted-sensitive', 'high', `${s.classification} store ${s.store_id} is not encrypted at rest`, `مخزن ${s.store_id} الحساس غير مشفر`);
  if (!s.owner) add('no-owner', 'medium', `Store ${s.store_id} has no accountable owner`, `المخزن ${s.store_id} بلا مالك مسؤول`);
  if (s.contains_personal_data && !s.legal_basis) add('no-legal-basis', 'medium', `Store ${s.store_id} holds personal data without a recorded legal basis`, `المخزن ${s.store_id} يحوي بيانات شخصية دون أساس قانوني مسجل`);
  if (s.contains_personal_data && !s.retention_days) add('no-retention', 'low', `Store ${s.store_id} holds personal data without a retention period`, `المخزن ${s.store_id} يحوي بيانات شخصية دون مدة احتفاظ`);
  if (allowedRegions.length && s.location && !allowedRegions.includes(s.location) && sensitive) add('outside-allowed-region', 'high', `${s.classification} store ${s.store_id} is located in ${s.location}, outside the allowed regions`, `مخزن ${s.store_id} الحساس موجود في ${s.location} خارج المناطق المسموحة`);
  return f;
}
const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fc|fd|fe80)/i;
// Unusual egress: last 24 hours versus the host's median daily outbound volume over the previous days.
export function egressAnomalies(records, now, { minBytes = 500 * 1048576, factor = 5, baselineDays = 14 } = {}) {
  const day = 86400000, perHost = new Map();
  for (const r of records) { if (r.category !== 'flow' || !r.src_ip || !r.dst_ip || !PRIVATE.test(r.src_ip) || PRIVATE.test(r.dst_ip) || !r.bytes) continue; const t = Date.parse(r.time); if (!Number.isFinite(t) || now - t > (baselineDays + 1) * day) continue;
    const h = perHost.get(r.src_ip) || { recent: 0, daily: new Map(), destinations: new Map() }; if (now - t <= day) { h.recent += r.bytes; h.destinations.set(r.dst_ip, (h.destinations.get(r.dst_ip) || 0) + r.bytes); } else { const k = Math.floor((now - t) / day); h.daily.set(k, (h.daily.get(k) || 0) + r.bytes); } perHost.set(r.src_ip, h); }
  const out = [];
  for (const [ip, h] of perHost) { const days = [...h.daily.values()].sort((a, b) => a - b), median = days.length ? days[Math.floor(days.length / 2)] : 0;
    if (h.recent >= minBytes && (median === 0 ? days.length >= 3 : h.recent >= median * factor)) out.push({ host_ip: ip, bytes_24h: h.recent, baseline_daily_median: median, baseline_days: days.length, ratio: median ? Math.round(h.recent / median * 10) / 10 : null, top_destinations: [...h.destinations.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([dst, bytes]) => ({ dst, bytes })) }); }
  return out.sort((a, b) => b.bytes_24h - a.bytes_24h);
}
