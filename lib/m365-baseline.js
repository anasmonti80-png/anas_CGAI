// CG-146 Microsoft 365 baseline assessment from CISA SCuBA / ScubaGear results. CyberGuard never signs in to the
// tenant: the owner runs ScubaGear (read-only roles such as Global Reader) and imports ScubaResults_{UUID}.json.
// Every control keeps its baseline policy version (MS.AAD.1.1v1 -> v1) and the tool version, so deviations are shown
// against the exact reference that produced them. A control the tool does not check (Not-Implemented), one that
// needs third-party evidence, an error, an omission by the owner, or a product that was not assessed is never shown
// as compliant.
import { fail } from './common.js';

export const PRODUCTS = [
  { code: 'AAD', name: 'Microsoft Entra ID' },
  { code: 'SecuritySuite', name: 'Security Suite (Defender policies since ScubaGear 2.0.0)', name_ar: 'Security Suite (سياسات Defender منذ ScubaGear 2.0.0)' },
  { code: 'EXO', name: 'Exchange Online' },
  { code: 'PowerBI', name: 'Power BI' },
  { code: 'PowerPlatform', name: 'Power Platform' },
  { code: 'SharePoint', name: 'SharePoint Online' },
  { code: 'Teams', name: 'Microsoft Teams' },
];
// Older ScubaGear output (1.x) used separate product codes that 2.0.0 folded into the Security Suite.
const LEGACY = { Defender: 'SecuritySuite' };

// Least-privilege access per product, from the ScubaGear prerequisites (interactive and non-interactive).
export const PERMISSIONS = [
  { product: 'AAD', role: 'Global Reader', app: 'Microsoft Graph: Directory.Read.All, Policy.Read.All, PrivilegedAccess.Read.AzureADGroup, PrivilegedEligibilitySchedule.Read.AzureADGroup, RoleManagement.Read.Directory, RoleManagementPolicy.Read.AzureADGroup, User.Read.All', read_only: true, note: 'Read permissions only.', note_ar: 'صلاحيات قراءة فقط.' },
  { product: 'SecuritySuite', role: 'Global Reader', app: 'Office 365 Exchange Online: Exchange.ManageAsApp + Global Reader role', read_only: true, note: 'Effective rights come from the assigned role: assign Global Reader, not Exchange Administrator.', note_ar: 'الصلاحية الفعلية من الدور المسند: أسند Global Reader وليس Exchange Administrator.' },
  { product: 'EXO', role: 'Global Reader', app: 'Office 365 Exchange Online: Exchange.ManageAsApp + Global Reader role', read_only: true, note: 'Effective rights come from the assigned role: assign Global Reader, not Exchange Administrator.', note_ar: 'الصلاحية الفعلية من الدور المسند: أسند Global Reader وليس Exchange Administrator.' },
  { product: 'PowerBI', role: 'Fabric Administrator (interactive)', app: 'No API permission; tenant setting "Service principals can access read-only admin APIs" for a security group', read_only: true, note: 'Use the service principal path: the interactive role can change settings.', note_ar: 'استخدم مسار كيان الخدمة: الدور التفاعلي يستطيع تغيير الإعدادات.' },
  { product: 'PowerPlatform', role: 'Power Platform Administrator', app: 'One-time management app registration by an administrator', read_only: false, note: 'No read-only role exists for this check; ScubaGear states it never uses write rights. Limit who holds the credential.', note_ar: 'لا يوجد دور قراءة فقط لهذا الفحص؛ وتذكر ScubaGear أنها لا تستخدم صلاحيات الكتابة. قيّد من يملك بيانات الاعتماد.' },
  { product: 'SharePoint', role: 'Global Reader', app: 'SharePoint: Sites.FullControl.All (app-only)', read_only: false, note: 'The app permission is write-capable; ScubaGear states it never uses it to write. Prefer interactive Global Reader.', note_ar: 'صلاحية التطبيق تسمح بالكتابة؛ وتذكر ScubaGear أنها لا تستخدمها للكتابة. فضّل Global Reader التفاعلي.' },
  { product: 'Teams', role: 'Global Reader', app: 'Global Reader role', read_only: true, note: 'Read permissions only.', note_ar: 'صلاحيات قراءة فقط.' },
];

export const STATUSES = ['deviation', 'meets', 'manual-check', 'third-party-evidence', 'omitted-by-owner', 'not-assessed', 'not-applicable'];
export const STATUS_AR = { deviation: 'انحراف عن خط الأساس', meets: 'مطابق', 'manual-check': 'لا تفحصه الأداة — تحقق يدوي', 'third-party-evidence': 'يحتاج دليلًا من أداة طرف ثالث', 'omitted-by-owner': 'مستثنى من المالك', 'not-assessed': 'لم يُقيَّم (خطأ)', 'not-applicable': 'لا ينطبق' };

export const REFERENCES = [
  { id: 'ScubaGear', url: 'https://github.com/cisagov/ScubaGear', note: 'CISA Secure Cloud Business Applications assessment tool for Microsoft 365' },
  { id: 'SCuBA', url: 'https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project', note: 'CISA SCuBA project and secure configuration baselines' },
  { id: 'BOD 25-01', url: 'https://www.cisa.gov/news-events/directives/bod-25-01-implementing-secure-practices-cloud-services', note: 'Binding Operational Directive 25-01, Implementing Secure Practices for Cloud Services' },
];

const ID = /^MS\.([A-Z]+)\.(\d+)\.(\d+)v(\d+)$/i;
const plain = (v, max) => String(v ?? '').replace(/<[^>]*>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/\s+/g, ' ').trim().slice(0, max);
const truthy = v => v === true || /^true$/i.test(String(v ?? ''));

function classify(result, level, qualifier, omitted) {
  const r = String(result || '').trim();
  if (omitted || /^omit/i.test(r)) return { status: 'omitted-by-owner', severity: null };
  if (/^error/i.test(r)) return { status: 'not-assessed', severity: null };
  if (/^pass$/i.test(r)) return { status: 'meets', severity: null };
  if (/^fail$/i.test(r)) return { status: 'deviation', severity: level === 'shall' ? 'high' : 'medium' };
  if (/^warning$/i.test(r)) return { status: 'deviation', severity: level === 'shall' ? 'high' : 'medium' };
  if (qualifier === 'not-implemented') return { status: 'manual-check', severity: null };
  if (qualifier === '3rd-party') return { status: 'third-party-evidence', severity: null };
  if (/^n\/?a$/i.test(r)) return { status: 'not-applicable', severity: null };
  return { status: 'not-assessed', severity: null };
}

export function parseScubaResults(input) {
  const j = typeof input === 'string' ? JSON.parse(input) : input, m = j?.MetaData || {};
  fail(m.Tool === 'ScubaGear' && typeof m.ToolVersion === 'string' && j.Results && typeof j.Results === 'object', 400, 'not_scubagear_results');
  const controls = [], products = [];
  for (const [rawCode, groups] of Object.entries(j.Results)) {
    const code = LEGACY[rawCode] || rawCode; if (!Array.isArray(groups)) continue; if (!products.includes(code)) products.push(code);
    for (const g of groups) for (const c of g?.Controls || []) {
      const id = String(c['Control ID'] || '').trim(), mm = ID.exec(id); if (!mm) continue;
      const [lvl, qual] = String(c.Criticality || '').split('/').map(x => x.trim().toLowerCase());
      const level = lvl === 'shall' ? 'shall' : 'should', qualifier = qual === 'not-implemented' ? 'not-implemented' : qual === '3rd party' ? '3rd-party' : null;
      const omitted = !!(c.OmittedEvaluationResult && String(c.OmittedEvaluationResult).trim());
      const rawReq = String(c.Requirement || ''), cut = rawReq.indexOf('<');
      const { status, severity } = classify(c.Result, level, qualifier, omitted);
      controls.push({ id, product: code, group: plain(g.GroupName, 120), policy: `MS.${mm[1].toUpperCase()}.${mm[2]}.${mm[3]}`, policy_version: Number(mm[4]),
        requirement: plain(cut > 0 ? rawReq.slice(0, cut) : rawReq, 500), bod_25_01: /BOD\s*25-01/i.test(rawReq), result: plain(c.Result, 60), level, qualifier, status, severity,
        details: plain(omitted ? c.OmittedEvaluationDetails || c.Details : c.Details, 500), incorrect_result_reported: truthy(c.IncorrectResult),
        superseded: mm[1].toUpperCase() === 'DEFENDER' ? 'Replaced by MS.SECURITYSUITE policies in ScubaGear 2.0.0' : null });
    }
  }
  return { tool: 'ScubaGear', tool_version: m.ToolVersion, report_uuid: String(m.ReportUUID || ''), assessed_at: m.TimestampZulu || null, tenant_display: plain(m.DisplayName, 200) || null, products_assessed: products, controls };
}

export function summarize(controls, productsAssessed) {
  const count = (st, lvl) => controls.filter(c => c.status === st && (!lvl || c.level === lvl)).length;
  const meets = count('meets'), deviations = count('deviation');
  return { shall_deviations: count('deviation', 'shall'), should_deviations: count('deviation', 'should'), meets, manual_check: count('manual-check'), third_party: count('third-party-evidence'), omitted: count('omitted-by-owner'), not_assessed: count('not-assessed'),
    products_not_assessed: PRODUCTS.map(p => p.code).filter(c => !productsAssessed.includes(c)),
    // Only automated results that the tool actually evaluated count toward the percentage.
    automated_score: meets + deviations ? Math.round(100 * meets / (meets + deviations)) : null };
}

// Compare two imports of the same tenant: a control that met the baseline and deviates now is a regression; a
// changed policy version or tool version is a reference change, not a regression.
export function compare(prev, cur) {
  if (!prev) return { regressions: [], improved: [], version_changes: [], tool_changed: null };
  const byPolicy = new Map(prev.controls.map(c => [c.policy, c]));
  const regressions = [], improved = [], version_changes = [];
  for (const c of cur.controls) { const p = byPolicy.get(c.policy); if (!p) continue;
    if (p.policy_version !== c.policy_version) { version_changes.push({ policy: c.policy, from: p.policy_version, to: c.policy_version }); continue; }
    if (p.status === 'meets' && c.status === 'deviation') regressions.push(c.id);
    if (p.status === 'deviation' && c.status === 'meets') improved.push(c.id); }
  return { regressions, improved, version_changes, tool_changed: prev.tool_version !== cur.tool_version ? { from: prev.tool_version, to: cur.tool_version } : null };
}

export function m365View(store) {
  const by = new Map();
  for (const r of store.all("SELECT observed_at,payload FROM events WHERE kind='identity.m365_baseline' ORDER BY observed_at,received_at")) { const d = JSON.parse(r.payload).details; by.set(d.tenant_ref, [...(by.get(d.tenant_ref) || []), { ...d, observed_at: r.observed_at }]); }
  const order = s => STATUSES.indexOf(s);
  const tenants = [...by.values()].map(list => { const cur = list.at(-1), prev = list.at(-2) || null;
    return { ...cur, controls: [...cur.controls].sort((a, b) => order(a.status) - order(b.status) || (a.level === b.level ? 0 : a.level === 'shall' ? -1 : 1) || a.id.localeCompare(b.id)),
      summary: summarize(cur.controls, cur.products_assessed), drift: compare(prev, cur), previous_at: prev?.observed_at || null, imports: list.length }; });
  return { tenants, products: PRODUCTS, permissions: PERMISSIONS, references: REFERENCES, status_ar: STATUS_AR,
    claim: 'CyberGuard does not sign in to the tenant. The owner runs CISA ScubaGear with read-only roles where they exist and imports its results; every deviation is shown with its baseline policy version and the tool version. Controls the tool does not check, those needing third-party evidence, errors, omissions and products not assessed are never counted as compliant.',
    claim_ar: 'لا يسجّل CyberGuard الدخول إلى المستأجر. يشغّل المالك أداة CISA ScubaGear بأدوار القراءة فقط حيث توجد ويستورد نتائجها؛ ويظهر كل انحراف مع إصدار سياسة خط الأساس وإصدار الأداة. والضوابط التي لا تفحصها الأداة، أو تحتاج دليلًا من طرف ثالث، أو فشل تقييمها، أو استثناها المالك، والمنتجات غير المقيَّمة، لا تُحتسب مطابقةً أبدًا.' };
}
