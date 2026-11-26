// CG-153 Cloud attack path evidence graph. Possible paths link exposure, misconfiguration, identity and permissions,
// assets and sensitive targets from records already stored (resource inventory, cloud findings, IAM Access Analyzer,
// access grants, data stores and external attack surface observations). Every step names the record it comes from.
// A path is "validated external reachability" only when an authorized external observation (CG-072) reached a
// service on the entry resource; an exposure read from configuration alone stays "inferred". A path is a hypothesis
// for prioritising work, never proof that an attacker can or did follow it.
const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SENSITIVE = ['restricted', 'confidential'];
const SEV_AR = { critical: 'حرجة', high: 'عالية', medium: 'متوسطة', low: 'منخفضة', info: 'معلوماتية' }, PRIV_AR = { read: 'قراءة', write: 'كتابة', admin: 'إدارة' };
const latestBy = (rows, key) => { const m = new Map(); for (const r of rows) m.set(key(r), r); return [...m.values()]; };

export function buildGraph(store) {
  const ev = kind => store.all('SELECT id,observed_at,payload FROM events WHERE kind=? ORDER BY observed_at,received_at', kind).map(r => ({ id: r.id, at: r.observed_at, d: JSON.parse(r.payload).details }));
  const resources = latestBy(ev('cloud.resource_inventory').flatMap(e => e.d.resources.map(r => ({ ...r, provider: e.d.provider, event_id: e.id, at: e.at }))), r => r.resource_id);
  const findings = latestBy(ev('cloud.finding').map(e => ({ ...e.d, event_id: e.id, at: e.at })), f => f.finding_id).filter(f => f.status === 'active' && f.resource_id);
  const external = ev('cloud.access_analyzer').flatMap(e => e.d.findings.filter(f => f.status === 'ACTIVE' && f.finding_type === 'ExternalAccess').map(f => ({ resource: f.resource, event_id: e.id, at: e.at })));
  const grants = latestBy(ev('cloud.access_grant').flatMap(e => e.d.grants.map(g => ({ ...g, event_id: e.id, at: e.at }))), g => g.grant_id);
  const stores = latestBy(ev('data.store').map(e => ({ ...e.d, event_id: e.id, at: e.at })), s => s.store_id);
  const easm = ev('easm.observation').map(e => ({ target: e.d.target, services: (e.d.services || []).length, http: (e.d.http || []).length > 0, event_id: e.id, at: e.at }));
  return { resources, findings, external, grants, stores, easm };
}

function sensitivityOf(r, g) {
  const tag = String(r.tags?.data_classification || '').toLowerCase();
  const st = g.stores.find(s => s.location && (s.location === r.resource_id || s.location === r.name || s.store_id === r.resource_id));
  if (st && SENSITIVE.includes(st.classification)) return { level: st.classification, basis: 'data-store', ref: st.store_id, event_id: st.event_id };
  if (SENSITIVE.includes(tag)) return { level: tag, basis: 'tag', ref: 'data_classification', event_id: r.event_id };
  return null;
}

function entryOf(r, g) {
  const ext = g.external.find(x => x.resource === r.resource_id), seen = g.easm.find(o => o.target && (o.target === r.tags?.public_dns || o.target === r.tags?.public_ip || o.target === r.name) && (o.services || o.http));
  if (!r.public && !ext && !seen) return null;
  return { validated: !!seen, basis: [r.public ? 'inventory-public' : null, ext ? 'access-analyzer-external' : null, seen ? 'external-observation' : null].filter(Boolean), event_ids: [r.public ? r.event_id : null, ext?.event_id, seen?.event_id].filter(Boolean) };
}

export function attackPaths(store) {
  const g = buildGraph(store), paths = [];
  const misconfig = r => g.findings.filter(f => f.resource_id === r.resource_id).sort((a, b) => sevRank[b.severity] - sevRank[a.severity]);
  for (const r of g.resources) {
    const entry = entryOf(r, g); if (!entry) continue;
    const step0 = { type: 'exposure', label: `${r.name || r.resource_id} is reachable from outside`, label_ar: `${r.name || r.resource_id} قابل للوصول من الخارج`, basis: entry.validated ? 'observed' : 'inferred', sources: entry.basis, event_ids: entry.event_ids };
    const mis = misconfig(r).slice(0, 3).map(f => ({ type: 'misconfiguration', label: `${f.severity}: ${f.title}`, label_ar: `${SEV_AR[f.severity] || f.severity}: ${f.title}`, basis: 'observed', sources: [f.product], event_ids: [f.event_id] }));
    const own = sensitivityOf(r, g);
    if (own) paths.push(make([step0, ...mis, { type: 'sensitive-target', label: `${own.level} data on the exposed resource itself`, label_ar: `بيانات ${own.level === 'restricted' ? 'مقيدة' : 'سرية'} على المورد المكشوف نفسه`, basis: 'observed', sources: [own.basis], event_ids: [own.event_id] }], r, r, own, entry, mis, null));
    // Exposure -> identity attached to the resource -> permission grant -> sensitive target in the granted scope.
    const principal = r.tags?.identity || r.tags?.iam_role || r.tags?.service_account;
    if (!principal) continue;
    for (const gr of g.grants.filter(x => x.principal_ref === principal)) {
      const targets = g.resources.filter(t => t.resource_id !== r.resource_id && (gr.scope_ref === t.account_id || gr.scope_ref === t.resource_id || t.resource_id.startsWith(gr.scope_ref)));
      for (const t of targets) { const sens = sensitivityOf(t, g); if (!sens) continue;
        paths.push(make([step0, ...mis,
          { type: 'identity', label: `runs as ${principal}`, label_ar: `يعمل بهوية ${principal}`, basis: 'declared', sources: ['resource-tag'], event_ids: [r.event_id] },
          { type: 'permission', label: `${gr.privilege} on ${gr.scope_type} ${gr.scope_ref} (${gr.roles.join(', ')})`, label_ar: `صلاحية ${PRIV_AR[gr.privilege] || gr.privilege} على ${gr.scope_ref} (${gr.roles.join(', ')})`, basis: 'observed', sources: [gr.mechanism], event_ids: [gr.event_id] },
          { type: 'sensitive-target', label: `${t.name || t.resource_id} holds ${sens.level} data`, label_ar: `${t.name || t.resource_id} يحتوي بيانات ${sens.level === 'restricted' ? 'مقيدة' : 'سرية'}`, basis: 'observed', sources: [sens.basis], event_ids: [sens.event_id] }], r, t, sens, entry, mis, gr)); }
    }
  }
  return paths.sort((a, b) => b.score - a.score);
}

function make(steps, entry, target, sens, e, mis, grant) {
  const score = (e.validated ? 40 : 15) + (mis.length ? sevRank[mis[0].label.split(':')[0]] * 5 : 0) + (sens.level === 'restricted' ? 25 : 15) + (grant ? (grant.privilege === 'admin' ? 20 : grant.privilege === 'write' ? 12 : 6) : 20);
  return { id: `${entry.resource_id}->${target.resource_id}${grant ? `@${grant.grant_id}` : ''}`, entry: entry.resource_id, entry_name: entry.name || entry.resource_id, target: target.resource_id, target_name: target.name || target.resource_id, provider: entry.provider,
    status: e.validated ? 'validated-external-reachability' : 'inferred', score, severity: score >= 80 ? 'critical' : score >= 60 ? 'high' : 'medium', steps,
    inferred_steps: steps.filter(s => s.basis !== 'observed').map(s => s.type) };
}

export const DEFENDER_COMPARISON = [
  { aspect: 'Availability', defender: 'Attack path analysis is part of the paid Defender CSPM plan (not the free Foundational CSPM).', cyberguard: 'Built from records already imported; no plan or licence is assumed.', aspect_ar: 'الإتاحة', defender_ar: 'تحليل مسارات الهجوم جزء من خطة Defender CSPM المدفوعة، لا من الخطة الأساسية المجانية.', cyberguard_ar: 'يُبنى من السجلات المستوردة مسبقًا؛ ولا يُفترض أي ترخيص.' },
  { aspect: 'Internet exposure', defender: 'Uses external attack surface data to validate internet exposure of entry points.', cyberguard: 'Validated only by an authorized external observation (CG-072) of the entry resource; configuration alone is inferred.', aspect_ar: 'الانكشاف على الإنترنت', defender_ar: 'يستخدم بيانات سطح الهجوم الخارجي للتحقق من انكشاف نقاط الدخول.', cyberguard_ar: 'لا يُعد مثبتًا إلا بملاحظة خارجية مصرّح بها (CG-072) للمورد؛ والإعداد وحده استدلال.' },
  { aspect: 'Sensitive data', defender: 'Data breach paths need sensitive data discovery enabled.', cyberguard: 'Targets come from declared data stores (CG-109) or a data classification tag, and say which.', aspect_ar: 'البيانات الحساسة', defender_ar: 'مسارات تسريب البيانات تتطلب تفعيل اكتشاف البيانات الحساسة.', cyberguard_ar: 'تأتي الأهداف من مخازن البيانات المعلنة (CG-109) أو وسم التصنيف، ويُذكر المصدر.' },
  { aspect: 'Evidence', defender: 'Paths are computed in the vendor cloud security graph.', cyberguard: 'Each step lists the stored record it comes from and whether it is observed, declared or inferred.', aspect_ar: 'الأدلة', defender_ar: 'تُحسب المسارات داخل رسم الأمان السحابي للمورّد.', cyberguard_ar: 'كل خطوة تذكر السجل المخزن الذي جاءت منه وهل هي مرصودة أو معلنة أو استدلالية.' },
];

export function attackPathView(store) {
  const paths = attackPaths(store);
  return { paths: paths.slice(0, 200), summary: { total: paths.length, validated: paths.filter(p => p.status === 'validated-external-reachability').length, inferred: paths.filter(p => p.status === 'inferred').length }, comparison: DEFENDER_COMPARISON,
    references: [{ id: 'Defender CSPM', url: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management' }, { id: 'Defender EASM in Defender for Cloud', url: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-easm' }, { id: 'Sensitive data risks', url: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/data-security-review-risks' }],
    claim: 'Possible attack paths link exposure, misconfiguration, identity, permissions and sensitive targets from stored records. A path is validated external reachability only when an authorized external observation reached the entry resource; otherwise it is inferred. A path is a hypothesis for prioritisation, not proof of compromise.',
    claim_ar: 'تربط مسارات الهجوم المحتملة الانكشاف والإعداد الخاطئ والهوية والصلاحيات والأهداف الحساسة من سجلات مخزنة. ولا يُعد المسار «وصولًا خارجيًا مثبتًا» إلا إذا وصلت ملاحظة خارجية مصرّح بها إلى مورد الدخول، وإلا فهو استدلالي. والمسار فرضية لترتيب الأولويات، لا دليل على اختراق.' };
}
