// CG-135 Routing security for organisations that run BGP. From an authorized, read-only router export (running
// configuration, "show ip bgp" and the routes advertised to each neighbour) and a validated ROA payload export
// (Routinator or rpki-client JSON) it reports: whether route origin validation (RFC 6811) is configured and invalid
// routes are dropped, inbound and outbound prefix filters per external neighbour, ROA coverage and maxLength of the
// organisation's own prefixes (RFC 9319), changes in announcements between snapshots, and possible hijacks (an own
// prefix or a more specific one originated by another AS) and leaks (routes advertised to a neighbour that are not the
// organisation's). It does not apply to a network without BGP and says so.
const ip4 = s => s.split('.').reduce((n, o) => n * 256 + Number(o), 0);
export function parsePrefix(p) { const m = String(p).match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/); if (!m) return null; const len = Number(m[2]); if (len > 32) return null; const size = 2 ** (32 - len), start = Math.floor(ip4(m[1]) / size) * size; return { text: `${m[1]}/${len}`, len, start, end: start + size - 1 }; }
const covers = (a, b) => a.start <= b.start && a.end >= b.end && a.len <= b.len;
const maskLen = m => m.split('.').reduce((n, o) => n + Number(o).toString(2).split('1').length - 1, 0);

export function parseBgpConfig(textIn) {
  const out = { asn: null, neighbors: [], networks: [], rpki_servers: [], invalid_dropped: false, hostname: null }; let inBgp = false, rm = null; const rms = new Map();
  for (const raw of String(textIn).split(/\r?\n/)) {
    const l = raw.replace(/\s+$/, ''), t = l.trim(); let m;
    if (/^\S/.test(l)) { inBgp = false; rm = null; }
    if ((m = l.match(/^hostname (\S+)/))) out.hostname = m[1];
    if ((m = l.match(/^router bgp (\d+)/))) { out.asn = Number(m[1]); inBgp = true; continue; }
    if ((m = l.match(/^route-map (\S+) (permit|deny) (\d+)/))) { rm = { name: m[1], action: m[2], rpkiInvalid: false }; rms.set(m[1], [...(rms.get(m[1]) || []), rm]); continue; }
    if (rm && /^match rpki invalid$/.test(t)) rm.rpkiInvalid = true;
    if (!inBgp) continue;
    const nb = ip => { let n = out.neighbors.find(x => x.ip === ip); if (!n) { n = { ip, remote_as: null, in: [], out: [] }; out.neighbors.push(n); } return n; };
    if ((m = t.match(/^neighbor (\S+) remote-as (\d+)/))) nb(m[1]).remote_as = Number(m[2]);
    else if ((m = t.match(/^neighbor (\S+) (prefix-list|route-map|filter-list|distribute-list) (\S+) (in|out)$/))) nb(m[1])[m[4]].push({ type: m[2], name: m[3] });
    else if ((m = t.match(/^network (\d+\.\d+\.\d+\.\d+) mask (\d+\.\d+\.\d+\.\d+)/))) out.networks.push(`${m[1]}/${maskLen(m[2])}`);
    else if ((m = t.match(/^network (\d+\.\d+\.\d+\.\d+\/\d+)/))) out.networks.push(m[1]);
    else if ((m = t.match(/^bgp rpki server tcp (\S+)/))) out.rpki_servers.push(m[1]);
  }
  out.ebgp = out.neighbors.filter(n => n.remote_as !== null && n.remote_as !== out.asn);
  // Invalid routes are dropped when an inbound route-map of every external neighbour denies "match rpki invalid".
  const dropsInvalid = n => n.in.some(f => f.type === 'route-map' && (rms.get(f.name) || []).some(e => e.action === 'deny' && e.rpkiInvalid));
  out.invalid_dropped = out.ebgp.length > 0 && out.ebgp.every(dropsInvalid); out.neighbors_dropping_invalid = out.ebgp.filter(dropsInvalid).map(n => n.ip);
  return out;
}

// "show ip bgp" (fixed-width): the path starts at the column of the "Path" header.
export function parseBgpTable(textIn) {
  const lines = String(textIn).split(/\r?\n/), h = lines.find(l => /Network\s+Next Hop/.test(l)); if (!h) return [];
  const col = h.indexOf('Path'), out = []; let last = null;
  for (const l of lines.slice(lines.indexOf(h) + 1)) {
    const m = l.match(/^\s*([VIN])?\s*([*sdhrSmbfxac]?)\s*(>?)\s*(\d+\.\d+\.\d+\.\d+\/\d+)?\s+(\d+\.\d+\.\d+\.\d+)/); if (!m || !(m[2] || m[3] || m[1])) continue;
    const prefix = m[4] || last; if (!prefix) continue; last = prefix;
    const tail = col > 0 ? l.slice(col).trim() : '', parts = tail.split(/\s+/).filter(Boolean), code = parts.at(-1), path = parts.slice(0, -1).filter(x => /^\d+$/.test(x)).map(Number);
    out.push({ prefix, next_hop: m[5], best: m[3] === '>', rpki: { V: 'valid', I: 'invalid', N: 'not-found' }[m[1]] || null, path, origin_as: path.at(-1) ?? null, origin_code: code || null });
  }
  return out;
}

// Validated ROA payloads from Routinator ("asn": "AS64500") or rpki-client ("asn": 64500).
export function parseVrps(json) { const list = json?.roas || json?.vrps || []; return list.map(r => ({ asn: Number(String(r.asn).replace(/^AS/i, '')), prefix: parsePrefix(r.prefix), max_length: Number(r.maxLength ?? r.max_length) })).filter(r => r.prefix && Number.isInteger(r.asn) && Number.isInteger(r.max_length)); }

// RFC 6811: valid when a covering VRP matches the origin AS and the length is within maxLength; invalid when covered
// but none matches; not-found when no VRP covers the prefix.
export function originValidation(vrps, prefixText, originAs) {
  const p = parsePrefix(prefixText); if (!p) return 'not-found'; const cov = vrps.filter(v => covers(v.prefix, p)); if (!cov.length) return 'not-found';
  return cov.some(v => v.asn === originAs && p.len <= v.max_length && originAs !== 0) ? 'valid' : 'invalid';
}

const DETAIL_AR = {
  'bgp-rov-not-configured': () => 'لا يوجد "bgp rpki server" في عملية BGP',
  'bgp-rov-invalid-accepted': d => d.replace('Dropping on: ', 'الإسقاط مفعّل على: ').replace('none', 'لا شيء'),
  'bgp-no-inbound-filter': () => 'تُقبل أي بادئة يرسلها الجار',
  'bgp-no-outbound-filter': () => 'يمكن إعادة إعلان كل مسار متعلَّم لهذا الجار',
  'bgp-no-vrp-export': () => 'صدّر VRP عبر Routinator أو rpki-client',
  'bgp-roa-missing': () => 'الشبكات التي تطبق التحقق من الأصل لا تميز الاختطاف من الإعلان الحقيقي',
  'bgp-roa-mismatch': () => 'الشبكات التي تطبق التحقق من الأصل ستُسقط هذا الإعلان',
  'bgp-roa-loose-maxlength': () => 'RFC 9319: قيمة maxLength الفضفاضة تتيح اختطاف بادئات فرعية بأصل مزيف',
  'bgp-possible-hijack': d => d.replace('Path ', 'المسار ').replace('; RPKI ', '؛ حالة RPKI: ').replace('invalid', 'غير صالح').replace('not-found', 'بلا ROA').replace(/valid$/, 'صالح').replace('unknown', 'غير معروف'),
};
export function assessRouting({ config, table = [], advertised = {}, vrps = [], ownPrefixes = [], previous = null }) {
  if (!config?.asn) return { applicable: false, reason: 'No BGP process in the configuration: routing security (RPKI, ROA, prefix filters) does not apply to this network', reason_ar: 'لا توجد عملية BGP في الإعداد: أمن التوجيه (RPKI وROA ومرشحات البادئات) لا ينطبق على هذه الشبكة', findings: [], own: [], announcements: [] };
  const findings = [], f = (id, severity, title, title_ar, detail, subject = null) => findings.push({ id, severity, title, title_ar, detail, subject });
  const own = [...new Set([...config.networks, ...ownPrefixes])].map(parsePrefix).filter(Boolean);
  // 1. Route origin validation.
  if (!config.rpki_servers.length) f('bgp-rov-not-configured', 'medium', 'Route origin validation is not configured', 'التحقق من أصل المسار غير مضبوط', 'No "bgp rpki server" in the BGP process');
  else if (!config.invalid_dropped) f('bgp-rov-invalid-accepted', 'medium', 'RPKI-invalid routes are not dropped from every external neighbour', 'المسارات غير الصالحة في RPKI لا تُسقط من كل جار خارجي', `Dropping on: ${config.neighbors_dropping_invalid.join(', ') || 'none'}`);
  // 2. Prefix filters per external neighbour.
  for (const n of config.ebgp) {
    if (!n.in.length) f('bgp-no-inbound-filter', 'medium', `No inbound filter on external neighbour ${n.ip} (AS${n.remote_as})`, `لا مرشح وارد على الجار الخارجي ${n.ip} (AS${n.remote_as})`, 'Any prefix the neighbour sends is accepted', n.ip);
    if (!n.out.length) f('bgp-no-outbound-filter', 'high', `No outbound filter on external neighbour ${n.ip} (AS${n.remote_as}): route leak risk`, `لا مرشح صادر على الجار الخارجي ${n.ip} (AS${n.remote_as}): خطر تسريب المسارات`, 'Every route learned can be re-advertised to this neighbour', n.ip);
  }
  // 3. ROA coverage and maxLength of own prefixes.
  const ownState = own.map(p => { const st = vrps.length ? originValidation(vrps, p.text, config.asn) : 'unknown', loose = vrps.filter(v => covers(v.prefix, p) && v.asn === config.asn && v.max_length > v.prefix.len); return { prefix: p.text, rov: st, loose_max_length: loose.map(v => `${v.prefix.text}-${v.max_length}`) }; });
  if (!vrps.length) f('bgp-no-vrp-export', 'low', 'No validated ROA payload export: ROA coverage cannot be checked', 'لا يوجد تصدير ROA متحقق منه: لا يمكن فحص تغطية ROA', 'Export VRPs with Routinator or rpki-client');
  for (const o of ownState) {
    if (o.rov === 'not-found') f('bgp-roa-missing', 'medium', `No ROA for own prefix ${o.prefix}`, `لا يوجد ROA للبادئة ${o.prefix}`, 'Networks enforcing ROV cannot tell a hijack from the real announcement', o.prefix);
    if (o.rov === 'invalid') f('bgp-roa-mismatch', 'high', `Own prefix ${o.prefix} is RPKI-invalid for AS${config.asn}`, `البادئة ${o.prefix} غير صالحة في RPKI للنظام AS${config.asn}`, 'Networks enforcing ROV will drop this announcement', o.prefix);
    if (o.loose_max_length.length) f('bgp-roa-loose-maxlength', 'low', `ROA for ${o.prefix} allows longer prefixes than announced (${o.loose_max_length.join(', ')})`, `ROA للبادئة ${o.prefix} يسمح ببادئات أطول من المعلنة`, 'RFC 9319: a loose maxLength enables forged-origin sub-prefix hijacks', o.prefix);
  }
  // 4. Possible hijacks: an own prefix or a more specific one with another origin AS.
  for (const r of table.filter(r => r.origin_as !== null && r.origin_as !== config.asn)) { const p = parsePrefix(r.prefix), mine = p && own.find(o => covers(o, p)); if (mine) f('bgp-possible-hijack', 'high', `${r.prefix} (own ${mine.text}) is originated by AS${r.origin_as}`, `${r.prefix} (ضمن ${mine.text}) يُعلَن من AS${r.origin_as}`, `Path ${r.path.join(' ')}; RPKI ${r.rpki || (vrps.length ? originValidation(vrps, r.prefix, r.origin_as) : 'unknown')}`, r.prefix); }
  // 5. Possible leaks: routes advertised to an external neighbour that are not the organisation's.
  for (const [nbr, list] of Object.entries(advertised)) { if (!config.ebgp.some(n => n.ip === nbr)) continue; const foreign = list.filter(x => { const p = parsePrefix(x.prefix); return p && !own.some(o => covers(o, p)); }); if (foreign.length) f('bgp-possible-leak', 'high', `${foreign.length} route(s) that are not ours advertised to ${nbr}`, `${foreign.length} مسار ليس لنا أُعلن إلى ${nbr}`, foreign.slice(0, 10).map(x => x.prefix).join(', '), nbr); }
  // 6. Announcement changes for own prefixes since the previous snapshot.
  const announced = table.filter(r => r.best && own.some(o => { const p = parsePrefix(r.prefix); return p && covers(o, p); })).map(r => `${r.prefix} AS${r.origin_as ?? config.asn}`), before = previous?.announcements || null;
  const changes = before ? { added: announced.filter(a => !before.includes(a)), removed: before.filter(a => !announced.includes(a)) } : null;
  if (changes && (changes.added.length || changes.removed.length)) f('bgp-announcement-changed', 'info', 'Announcements of own prefixes changed since the last snapshot', 'تغيرت إعلانات البادئات الخاصة منذ اللقطة السابقة', `Added: ${changes.added.join(', ') || 'none'}; removed: ${changes.removed.join(', ') || 'none'}`);
  for (const x of findings) x.detail_ar = (DETAIL_AR[x.id] || (d => d))(x.detail);
  return { applicable: true, asn: config.asn, ebgp_neighbors: config.ebgp.map(n => ({ ip: n.ip, remote_as: n.remote_as, inbound: n.in.map(x => `${x.type} ${x.name}`), outbound: n.out.map(x => `${x.type} ${x.name}`) })), rov: { servers: config.rpki_servers.length, invalid_dropped: config.invalid_dropped }, own: ownState, announcements: announced, changes, findings, vrps: vrps.length };
}

// Assets whose addresses are inside a prefix: the services a hijack or leak would affect.
export function prefixImpact(assets, contexts, prefixText) { const p = parsePrefix(prefixText); if (!p) return { assets: [], services: [] }; const hit = assets.filter(a => a.addresses.some(ip => /^\d+\.\d+\.\d+\.\d+$/.test(ip) && ip4(ip) >= p.start && ip4(ip) <= p.end)); return { assets: hit.map(a => a.hostname || a.external_id), services: [...new Set(hit.map(a => contexts.get(a.external_id)?.business_service).filter(Boolean))] }; }

export const ROUTING_REFERENCES = [
  { id: 'NIST SP 800-189 Rev. 1', status: 'Initial public draft (January 3, 2025; comments closed February 25, 2025), not final', status_ar: 'مسودة عامة أولية (3 يناير 2025؛ أُغلقت التعليقات 25 فبراير 2025)، غير نهائية', url: 'https://csrc.nist.gov/pubs/sp/800/189/r1/ipd' },
  { id: 'NIST SP 800-189', status: 'Final (December 2019)', status_ar: 'نهائي (ديسمبر 2019)', url: 'https://csrc.nist.gov/pubs/sp/800/189/final' },
  { id: 'RFC 6811', status: 'BGP Prefix Origin Validation', status_ar: 'التحقق من أصل بادئات BGP', url: 'https://www.rfc-editor.org/rfc/rfc6811' },
  { id: 'RFC 9319', status: 'BCP 185: avoid maxLength in ROAs', status_ar: 'BCP 185: تجنب maxLength في ROA', url: 'https://www.rfc-editor.org/rfc/rfc9319' },
];

// Latest export per router, announcement changes since the previous export, and the services inside affected prefixes.
export function routingView(store) {
  const parse = s => JSON.parse(s), by = new Map();
  for (const r of store.all("SELECT observed_at,payload FROM events WHERE kind='network.routing_security' ORDER BY observed_at,received_at")) { const d = parse(r.payload).details; by.set(d.device_ref, [...(by.get(d.device_ref) || []), { ...d, observed_at: r.observed_at }]); }
  const g = new Map(); for (const a of store.all('SELECT external_id,hostname,addresses FROM assets')) { const x = g.get(a.external_id); const ad = parse(a.addresses); if (!x) g.set(a.external_id, { external_id: a.external_id, hostname: a.hostname, addresses: ad }); else x.addresses = [...new Set([...x.addresses, ...ad])]; }
  const ctx = new Map(); for (const r of store.all("SELECT a.external_id,e.payload FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind='asset.context' ORDER BY e.observed_at")) ctx.set(r.external_id, parse(r.payload).details);
  const devices = [...by.values()].map(list => { const cur = list.at(-1), prev = list.at(-2) || null, changes = prev && cur.applicable ? { since: prev.observed_at, added: cur.announcements.filter(a => !prev.announcements.includes(a)), removed: prev.announcements.filter(a => !cur.announcements.includes(a)) } : null;
    return { ...cur, changes, findings: cur.findings.map(f => ['bgp-possible-hijack', 'bgp-roa-mismatch'].includes(f.id) && f.subject ? { ...f, impact: prefixImpact([...g.values()], ctx, f.subject) } : f) }; });
  return { devices, applicable: devices.some(d => d.applicable), references: ROUTING_REFERENCES,
    claim: 'Applies only to networks that run BGP. Route origin validation follows RFC 6811 against an imported validated ROA payload export; hijacks and leaks are possible events seen in the router\'s own tables, not a global view of the Internet.',
    claim_ar: 'ينطبق فقط على الشبكات التي تشغّل BGP. التحقق من أصل المسار وفق RFC 6811 مقابل تصدير ROA متحقق منه؛ والاختطاف والتسريب أحداث محتملة من جداول الموجّه نفسه، وليست رؤية عامة للإنترنت. ودليل NIST SP 800-189 Rev. 1 ما زال مسودة.' };
}
