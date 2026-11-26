// CG-149 Entra workload identity security from read-only Microsoft Graph exports made by the tenant owner:
// service principals, application credentials, service principal sign-ins, directory audits and Conditional Access.
// Conditional Access for workload identities applies only to single-tenant service principals registered in the
// tenant and assigned directly (not through a group); managed identities and multitenant or third-party apps are
// never covered, and creating or changing such policies needs Workload Identities Premium. Every service principal
// is therefore classed as covered, not covered, or not coverable by Conditional Access, never assumed protected.
import { fail } from './common.js';

export const KINDS = ['single-tenant', 'multitenant-or-third-party', 'managed-identity', 'other'];
export const KIND_AR = { 'single-tenant': 'تطبيق أحادي المستأجر', 'multitenant-or-third-party': 'تطبيق متعدد المستأجرين أو لطرف ثالث', 'managed-identity': 'هوية مُدارة', other: 'أخرى' };
// Directory audit activities (Core Directory, ApplicationManagement) that change what a workload identity can do.
export const ACTIVITIES = {
  'Add service principal credentials': 'credential', 'Update application - Certificates and secrets management': 'credential',
  'Consent to application': 'consent', 'Add delegated permission grant': 'consent', 'Add app role assignment to service principal': 'app-role', 'Add owner to application': 'owner',
};
export const CA_LIMITS = [
  { text: 'Policies apply only to single-tenant service principals registered in this tenant.', text_ar: 'تنطبق السياسات على كيانات الخدمة أحادية المستأجر المسجلة في هذا المستأجر فقط.' },
  { text: 'Managed identities are not covered; include them in an access review instead.', text_ar: 'الهويات المُدارة غير مشمولة؛ أدرجها في مراجعة وصول بدلًا من ذلك.' },
  { text: 'Microsoft and third-party SaaS apps, including multitenant apps, are not covered.', text_ar: 'تطبيقات Microsoft وتطبيقات SaaS للأطراف الثالثة، ومنها متعددة المستأجرين، غير مشمولة.' },
  { text: 'A policy assigned to a group containing a service principal is not enforced for it; assign the service principal directly.', text_ar: 'السياسة المسندة إلى مجموعة تضم كيان خدمة لا تُطبَّق عليه؛ أسندها إلى كيان الخدمة مباشرة.' },
  { text: 'Creating or changing these policies needs Workload Identities Premium; block is the only grant control.', text_ar: 'إنشاء هذه السياسات أو تعديلها يتطلب Workload Identities Premium، والحظر هو خيار المنح الوحيد.' },
];

const list = (j, name) => { const v = (typeof j === 'string' ? JSON.parse(j) : j)?.value; fail(Array.isArray(v), 400, `not_graph_${name}_export`); return v; };
const day = 86400000;

export function parseWorkloadExports({ tenantId, servicePrincipals, applications = { value: [] }, signIns = { value: [] }, audits = { value: [] }, policies = { value: [] } }) {
  fail(/^[0-9a-f-]{36}$/i.test(String(tenantId || '')), 400, 'invalid_tenant_id');
  const spList = list(servicePrincipals, 'service_principals'); fail(spList.every(s => s.id && s.servicePrincipalType), 400, 'not_graph_service_principals_export');
  const sps = spList.map(s => {
    const type = String(s.servicePrincipalType || ''), owner = s.appOwnerOrganizationId ? String(s.appOwnerOrganizationId).toLowerCase() : null;
    const kind = type === 'ManagedIdentity' ? 'managed-identity' : type === 'Application' ? (owner && owner === tenantId.toLowerCase() ? 'single-tenant' : 'multitenant-or-third-party') : 'other';
    return { id: String(s.id), app_id: String(s.appId || ''), name: String(s.displayName || s.appId || s.id).slice(0, 200), kind, enabled: s.accountEnabled !== false };
  });
  const apps = list(applications, 'applications').map(a => ({ app_id: String(a.appId || ''), name: String(a.displayName || '').slice(0, 200), audience: String(a.signInAudience || 'AzureADMyOrg'),
    credentials: [...(a.passwordCredentials || []).map(c => ({ ...c, type: 'secret' })), ...(a.keyCredentials || []).map(c => ({ ...c, type: 'certificate' }))].slice(0, 50)
      .map(c => ({ type: c.type, key_id: String(c.keyId || ''), name: c.displayName ? String(c.displayName).slice(0, 120) : null, start: c.startDateTime || null, end: c.endDateTime || null })) }));
  const signins = list(signIns, 'sign_ins').filter(x => x.appId).slice(0, 20000).map(x => ({ at: x.createdDateTime, app_id: String(x.appId), ip: x.ipAddress ? String(x.ipAddress) : null, country: x.location?.countryOrRegion || null, error_code: Number(x.status?.errorCode ?? 0) }));
  const audit = list(audits, 'directory_audits').filter(x => ACTIVITIES[x.activityDisplayName]).slice(0, 5000).map(x => ({ at: x.activityDateTime, activity: x.activityDisplayName, category: ACTIVITIES[x.activityDisplayName],
    target: String(x.targetResources?.[0]?.displayName || x.targetResources?.[0]?.id || '').slice(0, 200), target_id: String(x.targetResources?.[0]?.id || ''), by: String(x.initiatedBy?.user?.userPrincipalName || x.initiatedBy?.app?.displayName || 'unknown').slice(0, 200) }));
  const ca = list(policies, 'conditional_access').filter(p => p.conditions?.clientApplications).map(p => ({ id: String(p.id), name: String(p.displayName || p.id).slice(0, 200), state: String(p.state || ''),
    include: (p.conditions.clientApplications.includeServicePrincipals || []).map(String), exclude: (p.conditions.clientApplications.excludeServicePrincipals || []).map(String),
    risk: (p.conditions.servicePrincipalRiskLevels || []).length > 0, locations: !!p.conditions.locations }));
  return { tenant_id: tenantId.toLowerCase(), service_principals: sps, applications: apps, signins, audits: audit, ca_policies: ca };
}

// Which enabled policy, if any, applies to each service principal; and which can never be covered.
export function caCoverage(d) {
  const enabled = d.ca_policies.filter(p => p.state === 'enabled');
  return d.service_principals.map(s => {
    if (s.kind !== 'single-tenant') return { id: s.id, state: 'not-coverable', policies: [] };
    const hits = enabled.filter(p => (p.include.includes('ServicePrincipalsInMyTenant') || p.include.includes(s.id)) && !p.exclude.includes(s.id)).map(p => p.name);
    return { id: s.id, state: hits.length ? 'covered' : 'not-covered', policies: hits };
  });
}

export function credentialFindings(d, now) {
  const out = [];
  for (const a of d.applications) for (const c of a.credentials) {
    const end = Date.parse(c.end), start = Date.parse(c.start);
    if (end && end < now) out.push({ app_id: a.app_id, app: a.name, key_id: c.key_id, type: c.type, finding: 'expired', severity: 'low' });
    else if (end && end - now <= 30 * day) out.push({ app_id: a.app_id, app: a.name, key_id: c.key_id, type: c.type, finding: 'expiring-30d', severity: 'low' });
    if (c.type === 'secret' && end && end >= now && start && end - start > 365 * day) out.push({ app_id: a.app_id, app: a.name, key_id: c.key_id, type: c.type, finding: 'long-lived-secret', severity: 'medium' });
    if (c.type === 'secret' && (!end || end >= now)) out.push({ app_id: a.app_id, app: a.name, key_id: c.key_id, type: c.type, finding: 'client-secret-in-use', severity: 'info' });
  }
  return out;
}

// A sign-in from a country or address the service principal has not used in its own history (at least a day of it).
export function signinDeviations(d, now) {
  const recent = now - day, out = [];
  for (const appId of new Set(d.signins.map(s => s.app_id))) {
    const all = d.signins.filter(s => s.app_id === appId && s.error_code === 0), hist = all.filter(s => Date.parse(s.at) < recent), cur = all.filter(s => Date.parse(s.at) >= recent);
    if (!hist.length || Date.parse(hist.map(s => s.at).sort()[0]) > now - 2 * day) continue;
    const countries = new Set(hist.map(s => s.country).filter(Boolean)), ips = new Set(hist.map(s => s.ip).filter(Boolean));
    for (const s of cur) { const newCountry = s.country && !countries.has(s.country), newIp = s.ip && !ips.has(s.ip);
      if (newCountry || newIp) out.push({ app_id: appId, at: s.at, ip: s.ip, country: s.country, reason: newCountry ? 'new-country' : 'new-address', severity: newCountry ? 'high' : 'medium' }); }
  }
  const seen = new Set(); return out.filter(x => { const k = `${x.app_id}:${x.reason}:${x.country}:${x.ip}`; if (seen.has(k)) return false; seen.add(k); return true; });
}

export function assessWorkloads(d, now) {
  const cov = caCoverage(d), byId = new Map(cov.map(c => [c.id, c])), spOfApp = new Map(d.service_principals.map(s => [s.app_id, s]));
  const caScope = d.ca_policies.filter(p => p.state === 'enabled' && p.include.length).map(p => {
    const outside = d.service_principals.filter(s => s.enabled && s.kind !== 'single-tenant');
    return { policy: p.name, all_in_tenant: p.include.includes('ServicePrincipalsInMyTenant'), managed_identities_outside: outside.filter(s => s.kind === 'managed-identity').length, multitenant_outside: outside.filter(s => s.kind === 'multitenant-or-third-party').length };
  });
  return { counts: Object.fromEntries(KINDS.map(k => [k, d.service_principals.filter(s => s.kind === k).length])),
    coverage: { covered: cov.filter(c => c.state === 'covered').length, not_covered: cov.filter(c => c.state === 'not-covered').length, not_coverable: cov.filter(c => c.state === 'not-coverable').length, any_policy: d.ca_policies.some(p => p.state === 'enabled' && p.include.length) },
    ca_scope: caScope,
    service_principals: d.service_principals.map(s => ({ ...s, ca: byId.get(s.id) })),
    credentials: credentialFindings(d, now), deviations: signinDeviations(d, now).map(x => ({ ...x, name: spOfApp.get(x.app_id)?.name || x.app_id, kind: spOfApp.get(x.app_id)?.kind || 'other' })),
    changes: [...d.audits].sort((a, b) => String(b.at).localeCompare(String(a.at))) };
}

export function workloadView(store, now = Date.now()) {
  const latest = new Map();
  for (const r of store.all("SELECT observed_at,payload FROM events WHERE kind='identity.workload_identities' ORDER BY observed_at,received_at")) { const d = JSON.parse(r.payload).details; latest.set(d.tenant_id, { ...d, observed_at: r.observed_at }); }
  return { tenants: [...latest.values()].map(d => ({ tenant_id: d.tenant_id, observed_at: d.observed_at, ...assessWorkloads(d, Date.parse(d.observed_at) || now) })), ca_limits: CA_LIMITS, kind_ar: KIND_AR,
    claim: 'Service principals, managed identities and app credentials are monitored from read-only Graph exports. Conditional Access for workload identities covers only single-tenant service principals assigned directly; managed identities and multitenant or third-party apps are shown as not coverable, never as protected.',
    claim_ar: 'تُراقَب كيانات الخدمة والهويات المُدارة وبيانات اعتماد التطبيقات من تصديرات Graph للقراءة فقط. والوصول المشروط لهويات الأحمال يشمل كيانات الخدمة أحادية المستأجر المسندة مباشرة فقط؛ أما الهويات المُدارة والتطبيقات متعددة المستأجرين أو لأطراف ثالثة فتظهر «غير قابلة للتغطية» ولا تُعد محمية أبدًا.' };
}
