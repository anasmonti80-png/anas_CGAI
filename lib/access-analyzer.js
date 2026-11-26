// CG-148 AWS IAM Access Analyzer integration from the owner's read-only exports (ListAnalyzers and ListFindingsV2).
// Three analyses, each with its own zone of trust, regional scope and price:
//  - external access (ACCOUNT / ORGANIZATION): no additional charge; analyses only the region of the analyzer, so
//    one analyzer per region is needed. Principals inside the zone of trust are trusted and never reported.
//  - unused access (*_UNUSED_ACCESS): charged per IAM role or user analysed per month; one analyzer per partition.
//  - internal access (*_INTERNAL_ACCESS): charged per resource monitored per region per month; one per region.
// An analysis that is not configured is shown as not active. Its absence of findings is never "no exposure".
import { fail } from './common.js';

export const ANALYSES = {
  external: { types: ['ACCOUNT', 'ORGANIZATION'], regional: true, paid: false, finding_types: ['ExternalAccess'],
    title: 'External access', title_ar: 'الوصول الخارجي', cost: 'No additional charge', cost_ar: 'بلا تكلفة إضافية',
    scope: 'Analyses only the region where the analyzer is enabled: one analyzer per region.', scope_ar: 'يحلل المنطقة التي فُعّل فيها فقط: محلل لكل منطقة.' },
  unused: { types: ['ACCOUNT_UNUSED_ACCESS', 'ORGANIZATION_UNUSED_ACCESS'], regional: false, paid: true, finding_types: ['UnusedIAMRole', 'UnusedIAMUserAccessKey', 'UnusedIAMUserPassword', 'UnusedPermission'],
    title: 'Unused access', title_ar: 'الوصول غير المستخدم', cost: 'Paid: per IAM role or user analysed per month', cost_ar: 'مدفوع: لكل دور أو مستخدم IAM يُحلَّل شهريًا',
    scope: 'Findings do not vary by region: one analyzer per partition.', scope_ar: 'النتائج لا تختلف حسب المنطقة: محلل واحد لكل قسم (partition).' },
  internal: { types: ['ACCOUNT_INTERNAL_ACCESS', 'ORGANIZATION_INTERNAL_ACCESS'], regional: true, paid: true, finding_types: ['InternalAccess'],
    title: 'Internal access to critical resources', title_ar: 'الوصول الداخلي إلى الموارد الحساسة', cost: 'Paid: per resource monitored per region per month', cost_ar: 'مدفوع: لكل مورد مراقَب في كل منطقة شهريًا',
    scope: 'One analyzer per region; S3, DynamoDB and RDS snapshots only.', scope_ar: 'محلل لكل منطقة؛ ويشمل S3 وDynamoDB ولقطات RDS فقط.' },
};
const TYPES = Object.values(ANALYSES).flatMap(a => a.types);
export const FINDING_TYPES = Object.values(ANALYSES).flatMap(a => a.finding_types);
const analysisOfType = t => Object.keys(ANALYSES).find(k => ANALYSES[k].types.includes(t));
const analysisOfFinding = t => Object.keys(ANALYSES).find(k => ANALYSES[k].finding_types.includes(t)) || null;

export const ZONE = {
  account: { text: 'Zone of trust is this account: access from any other account, including accounts in the same organization, is reported as external.', text_ar: 'منطقة الثقة هي هذا الحساب: الوصول من أي حساب آخر، حتى من حسابات المنظمة نفسها، يُبلَّغ عنه وصولًا خارجيًا.' },
  organization: { text: 'Zone of trust is the organization: access between member accounts is trusted and not reported; only access from outside the organization is external.', text_ar: 'منطقة الثقة هي المنظمة: الوصول بين حساباتها موثوق ولا يُبلَّغ عنه؛ والخارجي هو ما يأتي من خارج المنظمة فقط.' },
};

const arnPart = (arn, i) => String(arn || '').split(':')[i] || null;

export function parseAnalyzers(json) {
  const list = (typeof json === 'string' ? JSON.parse(json) : json)?.analyzers;
  fail(Array.isArray(list), 400, 'not_list_analyzers_output');
  return list.filter(a => TYPES.includes(a.type)).map(a => ({ name: String(a.name), arn: String(a.arn), type: a.type, analysis: analysisOfType(a.type), zone: a.type.startsWith('ORGANIZATION') ? 'organization' : 'account',
    region: arnPart(a.arn, 3), status: String(a.status || 'UNKNOWN').toUpperCase(), status_reason: a.statusReason?.code || null }));
}

export function parseFindings(json, analyzerName) {
  const list = (typeof json === 'string' ? JSON.parse(json) : json)?.findings;
  fail(Array.isArray(list), 400, 'not_list_findings_v2_output');
  return list.map(f => ({ id: String(f.id), analyzer: analyzerName, finding_type: FINDING_TYPES.includes(f.findingType) ? f.findingType : 'Unknown', analysis: analysisOfFinding(f.findingType),
    resource: f.resource ? String(f.resource).slice(0, 400) : null, resource_type: String(f.resourceType || '').slice(0, 80), owner_account: String(f.resourceOwnerAccount || ''), status: ['ACTIVE', 'ARCHIVED', 'RESOLVED'].includes(f.status) ? f.status : 'ACTIVE',
    analyzed_at: f.analyzedAt || null, error: f.error ? String(f.error).slice(0, 200) : null }));
}

// Coverage of the three analyses against the regions the owner operates in.
export function assessAnalyzer({ analyzers, findings, regions = [] }) {
  const analyses = Object.entries(ANALYSES).map(([key, a]) => {
    const active = analyzers.filter(x => x.analysis === key && x.status === 'ACTIVE'), broken = analyzers.filter(x => x.analysis === key && x.status !== 'ACTIVE');
    const covered = [...new Set(active.map(x => x.region))], missing = a.regional ? regions.filter(r => !covered.includes(r)) : [];
    const state = !active.length ? 'not-active' : missing.length ? 'partial' : 'active';
    const f = findings.filter(x => x.analysis === key && x.status === 'ACTIVE');
    return { analysis: key, title: a.title, title_ar: a.title_ar, paid: a.paid, cost: a.cost, cost_ar: a.cost_ar, scope: a.scope, scope_ar: a.scope_ar, state,
      zones: [...new Set(active.map(x => x.zone))], regions_covered: covered, regions_missing: missing, analyzers_not_active: broken.map(x => ({ name: x.name, status: x.status, reason: x.status_reason })),
      active_findings: state === 'not-active' ? null : f.length,
      note: state === 'not-active' ? (a.paid ? 'Not active: this is a paid analysis that runs only after an analyzer is created. No findings does not mean no exposure.' : 'Not active: create an analyzer (no additional charge) in each region. No findings does not mean no exposure.') : missing.length ? `Not analysed in: ${missing.join(', ')}` : null,
      note_ar: state === 'not-active' ? (a.paid ? 'غير مفعّل: تحليل مدفوع لا يعمل إلا بعد إنشاء محلل. غياب النتائج لا يعني غياب التعرض.' : 'غير مفعّل: أنشئ محللًا (بلا تكلفة إضافية) في كل منطقة. غياب النتائج لا يعني غياب التعرض.') : missing.length ? `غير محلَّل في: ${missing.join('، ')}` : null };
  });
  const active = findings.filter(f => f.status === 'ACTIVE');
  return { analyses, counts: Object.fromEntries(FINDING_TYPES.map(t => [t, active.filter(f => f.finding_type === t).length])), zones: [...new Set(analyzers.filter(x => x.status === 'ACTIVE' && x.analysis !== 'unused').map(x => x.zone))] };
}

export function accessAnalyzerView(store) {
  const latest = new Map();
  for (const r of store.all("SELECT observed_at,payload FROM events WHERE kind='cloud.access_analyzer' ORDER BY observed_at,received_at")) { const d = JSON.parse(r.payload).details; latest.set(d.account_id, { ...d, observed_at: r.observed_at }); }
  const accounts = [...latest.values()].map(d => { const a = assessAnalyzer(d);
    return { account_id: d.account_id, observed_at: d.observed_at, regions: d.regions, ...a, findings: d.findings.filter(f => f.status === 'ACTIVE').sort((x, y) => FINDING_TYPES.indexOf(x.finding_type) - FINDING_TYPES.indexOf(y.finding_type)).slice(0, 300) }; });
  return { accounts, analyses: ANALYSES, zone: ZONE,
    claim: 'IAM Access Analyzer has three separate analyses. External access is free but regional; unused and internal access are paid and only run after an analyzer of that type is created. An analysis that is not active is shown as such, and no findings from it never means no exposure.',
    claim_ar: 'لـ IAM Access Analyzer ثلاثة تحليلات منفصلة. الوصول الخارجي مجاني لكنه إقليمي، والوصول غير المستخدم والداخلي مدفوعان ولا يعملان إلا بعد إنشاء محلل من نوعهما. والتحليل غير المفعّل يظهر كذلك، وغياب نتائجه لا يعني أبدًا غياب التعرض.' };
}
