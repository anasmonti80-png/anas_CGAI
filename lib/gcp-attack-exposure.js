// CG-154 GCP attack exposure posture from Security Command Center findings exported by the owner (read-only role
// roles/securitycenter.findingsViewer; gcloud scc findings list ... --format=json). Attack exposure scores, attack
// paths, toxic combinations and chokepoints come from SCC Premium or Enterprise with organization-level activation;
// simulations run on a schedule (results up to every 48 hours) and use a default high-value resource set until the
// owner defines one. CyberGuard never invents a similar score: when the tier, activation or calculation is missing,
// the finding shows "no score from SCC", never zero.
import { fail } from './common.js';

export const TIERS = ['standard', 'premium', 'enterprise', 'unknown'];
export const ACTIVATIONS = ['organization', 'project', 'unknown'];

export function availability({ tier, activation }) {
  if (tier === 'standard') return { available: false, reason: 'SCC Standard does not provide attack exposure scores or toxic combinations.', reason_ar: 'الطبقة القياسية من SCC لا توفر درجات التعرض للهجوم ولا التركيبات السامة.' };
  if (activation === 'project') return { available: false, reason: 'Attack exposure scores and attack paths cannot be used with project-level activation.', reason_ar: 'لا تعمل درجات التعرض ومسارات الهجوم مع التفعيل على مستوى المشروع.' };
  if (tier === 'unknown' || activation === 'unknown') return { available: null, reason: 'Tier or activation not declared: scores are shown only where SCC calculated them.', reason_ar: 'لم تُعلن الطبقة أو مستوى التفعيل: تُعرض الدرجات حيث حسبها SCC فقط.' };
  return { available: true, reason: null, reason_ar: null };
}

export function parseSccFindings(json) {
  const list = Array.isArray(json) ? json : json?.listFindingsResults || json?.findings; fail(Array.isArray(list), 400, 'not_scc_findings_export');
  return list.slice(0, 20000).map(x => x.finding || x).filter(f => f && f.name && f.category).map(f => {
    const ae = f.attackExposure || null, calculated = ae?.state === 'CALCULATED' && typeof ae.score === 'number';
    return { name: String(f.name).slice(0, 500), category: String(f.category).slice(0, 200), finding_class: String(f.findingClass || 'FINDING_CLASS_UNSPECIFIED'), state: String(f.state || 'ACTIVE'), severity: String(f.severity || 'SEVERITY_UNSPECIFIED'),
      resource: f.resourceName ? String(f.resourceName).slice(0, 500) : null, mute: String(f.mute || 'UNDEFINED'),
      exposure: calculated ? { score: ae.score, high: ae.exposedHighValueResourcesCount ?? null, medium: ae.exposedMediumValueResourcesCount ?? null, low: ae.exposedLowValueResourcesCount ?? null, calculated_at: ae.latestCalculationTime || null } : null,
      exposure_state: ae ? String(ae.state || 'STATE_UNSPECIFIED') : 'ABSENT',
      toxic: f.toxicCombination ? { score: typeof f.toxicCombination.attackExposureScore === 'number' ? f.toxicCombination.attackExposureScore : null, related: (f.toxicCombination.relatedFindings || []).map(String).slice(0, 50) } : null };
  });
}

export function assessGcpExposure({ findings, tier, activation, high_value_set }) {
  const av = availability({ tier, activation }), active = findings.filter(f => f.state === 'ACTIVE' && f.mute !== 'MUTED');
  const combos = active.filter(f => f.finding_class === 'TOXIC_COMBINATION' || f.finding_class === 'CHOKEPOINT').map(f => ({ ...f, risk: f.finding_class === 'CHOKEPOINT' ? 'critical' : (f.toxic?.score ?? f.exposure?.score ?? 0) >= 10 ? 'critical' : 'high' }));
  const scored = active.filter(f => f.exposure).sort((a, b) => b.exposure.score - a.exposure.score), unscored = active.filter(f => !f.exposure && f.finding_class !== 'TOXIC_COMBINATION' && f.finding_class !== 'CHOKEPOINT');
  const notes = [];
  if (av.available === false) notes.push({ text: av.reason, text_ar: av.reason_ar });
  if (av.available !== false && !scored.length && !combos.length) notes.push({ text: 'No finding has a calculated attack exposure yet; simulations run on a schedule (up to every 48 hours). Nothing is inferred meanwhile.', text_ar: 'لا يوجد استنتاج تعرض محسوب بعد؛ تعمل المحاكاة بجدول زمني (حتى كل 48 ساعة). ولا يُستنتج شيء في الأثناء.' });
  if (av.available !== false && !high_value_set) notes.push({ text: 'No high-value resource set is defined: SCC uses its default set, so scores may not reflect your priorities.', text_ar: 'لم تُعرَّف مجموعة الموارد عالية القيمة: يستخدم SCC مجموعته الافتراضية، فقد لا تعكس الدرجات أولوياتك.' });
  return { availability: av, combos, scored, unscored_count: unscored.length, unscored: unscored.slice(0, 100), notes, counts: { active: active.length, scored: scored.length, toxic: combos.filter(c => c.finding_class === 'TOXIC_COMBINATION').length, chokepoints: combos.filter(c => c.finding_class === 'CHOKEPOINT').length } };
}

export function gcpExposureView(store) {
  const latest = new Map();
  for (const r of store.all("SELECT observed_at,payload FROM events WHERE kind='cloud.gcp_attack_exposure' ORDER BY observed_at,received_at")) { const d = JSON.parse(r.payload).details; latest.set(d.organization_id, { ...d, observed_at: r.observed_at }); }
  return { organizations: [...latest.values()].map(d => ({ organization_id: d.organization_id, tier: d.tier, activation: d.activation, high_value_set: d.high_value_set, observed_at: d.observed_at, ...assessGcpExposure(d) })),
    references: [{ id: 'Attack exposure scores', url: 'https://cloud.google.com/security-command-center/docs/attack-exposure-learn' }, { id: 'Toxic combinations and chokepoints', url: 'https://cloud.google.com/security-command-center/docs/toxic-combinations-overview' }, { id: 'Finding resource (v2)', url: 'https://cloud.google.com/security-command-center/docs/reference/rest/v2/organizations.sources.findings' }],
    claim: 'Attack exposure scores, toxic combinations and chokepoints are taken from Security Command Center as calculated. They exist only in the Premium or Enterprise tier with organization-level activation; where SCC gives no score, none is invented.',
    claim_ar: 'تُؤخذ درجات التعرض للهجوم والتركيبات السامة ونقاط الاختناق من Security Command Center كما حسبها. ولا توجد إلا في طبقة Premium أو Enterprise مع تفعيل على مستوى المؤسسة؛ وحيث لا يعطي SCC درجة لا تُخترع درجة.' };
}
