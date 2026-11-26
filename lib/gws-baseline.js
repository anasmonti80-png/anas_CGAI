// CG-147 Google Workspace security baselines from CISA SCuBA / ScubaGoggles results, compared with the Microsoft 365
// SCuBA baselines (CG-146) in four areas: MFA, external sharing, mail forwarding and rules, and third-party apps.
// CyberGuard never signs in to the domain: the owner runs ScubaGoggles and imports its JSON. What the results can
// prove depends on the APIs actually used and the edition actually licensed:
//  - the SCuBA GWS baselines assume Enterprise Plus; a feature missing from the declared edition is "license
//    dependent", not a deviation, until the owner confirms it is available;
//  - checks based on admin log events cannot see a setting never changed from its default and only reach back about
//    six months, so "No events found" is never compliance.
import { parseScuba, summarize, compare, STATUS_AR } from './m365-baseline.js';

export const PRODUCTS = [
  { code: 'commoncontrols', name: 'Common Controls' }, { code: 'gmail', name: 'Gmail' }, { code: 'drive', name: 'Google Drive and Docs' },
  { code: 'calendar', name: 'Google Calendar' }, { code: 'chat', name: 'Google Chat' }, { code: 'meet', name: 'Google Meet' },
  { code: 'groups', name: 'Groups for Business' }, { code: 'sites', name: 'Google Sites' }, { code: 'classroom', name: 'Google Classroom' },
  { code: 'assuredcontrols', name: 'Assured Controls' }, { code: 'gemini', name: 'Gemini' },
];

const ID_PRODUCT = { COMMONCONTROLS: 'commoncontrols', GMAIL: 'gmail', DRIVEDOCS: 'drive', CALENDAR: 'calendar', CHAT: 'chat', MEET: 'meet', GROUPS: 'groups', SITES: 'sites', CLASSROOM: 'classroom', ASSUREDCONTROLS: 'assuredcontrols', GEMINI: 'gemini' };

export const EDITIONS = ['business-starter', 'business-standard', 'business-plus', 'enterprise-essentials', 'enterprise-essentials-plus', 'enterprise-standard', 'enterprise-plus',
  'frontline-starter', 'frontline-standard', 'frontline-plus', 'education-fundamentals', 'education-standard', 'education-plus', 'unknown'];

// Features some baseline policies need, with the editions Google documents for them. A list may be incomplete, so an
// edition outside it makes the control license dependent (confirm in the Admin console), never a silent pass or fail.
export const FEATURES = [
  { feature: 'context-aware-access', policies: ['GWS.COMMONCONTROLS.2'], editions: ['frontline-standard', 'frontline-plus', 'enterprise-standard', 'enterprise-plus', 'education-standard', 'education-plus', 'enterprise-essentials-plus'],
    source: 'https://support.google.com/a/answer/9275380', note: 'Users without a supported edition are not subject to Context-Aware Access policies.', note_ar: 'المستخدمون دون إصدار مدعوم لا تنطبق عليهم سياسات الوصول حسب السياق.' },
  { feature: 'data-loss-prevention', policies: ['GWS.COMMONCONTROLS.18'], editions: ['frontline-standard', 'enterprise-standard', 'enterprise-plus'],
    source: 'https://github.com/cisagov/ScubaGoggles/blob/main/scubagoggles/baselines/commoncontrols.md', note: 'Google DLP is listed for Frontline Standard, Enterprise Standard and Enterprise Plus among others; Drive DLP needs Drive log events in the license.', note_ar: 'منع تسرب البيانات مدرج لإصدارات منها Frontline Standard وEnterprise Standard وEnterprise Plus؛ ويحتاج DLP في Drive إلى أحداث سجل Drive ضمن الترخيص.' },
];

// The four areas of CG-147 and their counterpart groups in the Microsoft 365 SCuBA baselines.
export const AREAS = [
  { area: 'mfa', title: 'MFA and 2-Step Verification', title_ar: 'التحقق متعدد العوامل والتحقق بخطوتين', gws: ['GWS.COMMONCONTROLS.1'], m365: ['MS.AAD.3'] },
  { area: 'sharing', title: 'External sharing', title_ar: 'المشاركة الخارجية', gws: ['GWS.DRIVEDOCS.1'], m365: ['MS.SHAREPOINT.1'] },
  { area: 'mail', title: 'Mail forwarding, delegation and gateways', title_ar: 'إعادة توجيه البريد والتفويض والبوابات', gws: ['GWS.GMAIL.1', 'GWS.GMAIL.11', 'GWS.GMAIL.12', 'GWS.GMAIL.14'], m365: ['MS.EXO.1'] },
  { area: 'apps', title: 'Third-party apps and API access', title_ar: 'التطبيقات الخارجية والوصول إلى الواجهات', gws: ['GWS.COMMONCONTROLS.10', 'GWS.COMMONCONTROLS.11'], m365: ['MS.AAD.5'] },
];

export const ACCESS = {
  role: 'Super Admin (required by ScubaGoggles)', role_ar: 'Super Admin (تتطلبه ScubaGoggles)',
  scopes_read_only: ['admin.reports.audit.readonly', 'admin.directory.domain.readonly', 'admin.directory.group.readonly', 'admin.directory.orgunit.readonly', 'admin.directory.user.readonly', 'admin.directory.rolemanagement.readonly', 'admin.directory.customer.readonly', 'cloud-identity.policies.readonly', 'cloud-identity.inboundsso.readonly'],
  scopes_not_read_only: ['apps.licensing', 'apps.groups.settings'],
  note: 'Two scopes have no read-only form; the Groups Settings API is used with the Groups Reader role through delegated admin service account authorization. Run with a dedicated, monitored admin account and revoke the OAuth client after the run.',
  note_ar: 'نطاقان لا يوجد لهما شكل قراءة فقط؛ وتُستخدم واجهة إعدادات المجموعات بدور Groups Reader عبر حساب خدمة بتفويض إداري. شغّل الأداة بحساب إداري مخصص ومراقَب، وألغِ عميل OAuth بعد التشغيل.',
  apis: ['Admin SDK API', 'Groups Settings API', 'Cloud Identity API', 'Enterprise License Manager API'],
};

const inGroups = (c, groups) => groups.some(g => c.policy === g || c.policy.startsWith(`${g}.`));

export function parseScubaGoggles(input, { edition = 'unknown' } = {}) {
  const r = parseScuba(input, { tool: 'ScubaGoggles', idPrefix: 'GWS' }), ed = EDITIONS.includes(edition) ? edition : 'unknown';
  // The product is taken from the control ID (GWS.DRIVEDOCS.* -> drive), whatever the result key is named.
  for (const c of r.controls) { const p = ID_PRODUCT[c.id.split('.')[1].toUpperCase()]; if (p) c.product = p; }
  r.products_assessed = [...new Set(r.controls.map(c => c.product))];
  for (const c of r.controls) {
    const f = FEATURES.find(x => inGroups(c, x.policies));
    c.feature = f ? f.feature : null;
    if (f && !f.editions.includes(ed) && (c.status === 'deviation' || c.status === 'meets')) { c.license_note = ed === 'unknown' ? 'Edition not declared: confirm the feature is licensed.' : `Not documented for ${ed}: confirm in the Admin console.`; c.status = 'license-dependent'; c.severity = null; }
    if (c.status === 'no-log-events') c.license_note = 'Log-based check: a setting never changed from its default leaves no event, and admin logs reach back about six months.';
    c.area = AREAS.find(a => inGroups(c, a.gws))?.area || null;
  }
  return { ...r, edition: ed };
}

// Per area: the GWS result next to the Microsoft 365 result of the latest CG-146 import, when one exists.
export function compareAreas(gwsControls, m365Controls = []) {
  return AREAS.map(a => { const g = gwsControls.filter(c => inGroups(c, a.gws)), m = m365Controls.filter(c => inGroups(c, a.m365));
    const state = list => !list.length ? 'not-assessed' : list.some(c => c.status === 'deviation' && c.level === 'shall') ? 'shall-deviation' : list.some(c => c.status === 'deviation') ? 'should-deviation' : list.some(c => c.status !== 'meets' && c.status !== 'not-applicable' && c.status !== 'omitted-by-owner') ? 'unproven' : 'meets';
    return { area: a.area, title: a.title, title_ar: a.title_ar, gws_groups: a.gws, m365_groups: a.m365, gws: { state: state(g), controls: g.length, deviations: g.filter(c => c.status === 'deviation').map(c => c.id) }, m365: { state: state(m), controls: m.length, deviations: m.filter(c => c.status === 'deviation').map(c => c.id) } }; });
}

export function gwsView(store) {
  const by = new Map();
  for (const r of store.all("SELECT observed_at,payload FROM events WHERE kind='identity.gws_baseline' ORDER BY observed_at,received_at")) { const d = JSON.parse(r.payload).details; by.set(d.domain_ref, [...(by.get(d.domain_ref) || []), { ...d, observed_at: r.observed_at }]); }
  const m365 = store.get("SELECT payload FROM events WHERE kind='identity.m365_baseline' ORDER BY observed_at DESC,received_at DESC LIMIT 1"), m365Controls = m365 ? JSON.parse(m365.payload).details.controls : [];
  const order = ['deviation', 'license-dependent', 'no-log-events', 'manual-check', 'third-party-evidence', 'not-assessed', 'omitted-by-owner', 'not-applicable', 'meets'];
  const domains = [...by.values()].map(list => { const cur = list.at(-1), prev = list.at(-2) || null;
    return { ...cur, controls: [...cur.controls].sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status) || a.id.localeCompare(b.id)), summary: summarize(cur.controls, cur.products_assessed, PRODUCTS),
      drift: compare(prev, cur), previous_at: prev?.observed_at || null, imports: list.length, areas: compareAreas(cur.controls, m365Controls) }; });
  return { domains, products: PRODUCTS, areas: AREAS, features: FEATURES, access: ACCESS, editions: EDITIONS, status_ar: STATUS_AR, m365_available: !!m365,
    references: [
      { id: 'ScubaGoggles', url: 'https://github.com/cisagov/ScubaGoggles' },
      { id: 'SCuBA GWS baselines', url: 'https://github.com/cisagov/ScubaGoggles/tree/main/scubagoggles/baselines' },
      { id: 'Context-Aware Access editions', url: 'https://support.google.com/a/answer/9275380' },
    ],
    claim: 'CyberGuard does not sign in to Google Workspace. The owner runs CISA ScubaGoggles (Super Admin is required; nine of its eleven OAuth scopes are read-only) and imports the results. The baselines assume Enterprise Plus: a control needing a feature not documented for the declared edition is license dependent, and log-based checks with no events prove nothing about a default setting.',
    claim_ar: 'لا يسجّل CyberGuard الدخول إلى Google Workspace. يشغّل المالك أداة CISA ScubaGoggles (تتطلب Super Admin، وتسعة من نطاقاتها الأحد عشر للقراءة فقط) ويستورد النتائج. وتفترض خطوط الأساس إصدار Enterprise Plus؛ فالضابط الذي يحتاج ميزة غير موثقة للإصدار المعلن «يعتمد على الترخيص»، والفحوص المبنية على السجلات دون أحداث لا تثبت شيئًا عن الإعداد الافتراضي.' };
}
