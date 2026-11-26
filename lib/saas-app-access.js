// CG-159 SaaS shadow IT and app-to-app access. CyberGuard does not sign in to the tenant. The owner exports, read-only:
//  - Microsoft Entra: the authorization policy (defaultUserRolePermissions.permissionGrantPoliciesAssigned decides user
//    consent: no ManagePermissionGrantsForSelf.* entry = user consent off; microsoft-user-default-low = verified
//    publishers and low-impact permissions only; microsoft-user-default-legacy = any app), service principals and
//    oauth2PermissionGrants (consentType AllPrincipals = admin consent for every user, Principal = one user), plus the
//    SharePoint/OneDrive external sharing level from the admin center (Anyone / New and existing guests / Existing
//    guests / Only people in your organization) and the Anyone-link expiration.
//  - Google Workspace: Directory API tokens.list (clientId, displayText, scopes, anonymous, nativeApp, userKey), the
//    app access settings from Security > Access and data control > API controls (Trusted, Limited, Specific Google data,
//    Blocked) and the setting for unconfigured third-party apps.
// Only inventory metadata is kept: which apps hold which scopes and how many users granted them. User identifiers are
// reduced to counts. File-level sharing is counted only when a privacy policy reference is declared, and never by name;
// no mail, file or chat content is read.
import { fail } from './common.js';
import { riskyScope } from './identity-threats.js';

export const REFERENCES = [
  { id: 'Entra user consent settings', url: 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent' },
  { id: 'oauth2PermissionGrant', url: 'https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant' },
  { id: 'SharePoint external sharing', url: 'https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off' },
  { id: 'Google tokens.list', url: 'https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens' },
  { id: 'Google app access control', url: 'https://support.google.com/a/answer/7281227' },
  { id: 'Drive permissions', url: 'https://developers.google.com/workspace/drive/api/reference/rest/v3/permissions' },
];
// Subset of Google's published high-risk OAuth scopes for Gmail and Drive (the full list is on the app access control page).
export const GOOGLE_HIGH_RISK = ['https://mail.google.com/', 'https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.modify', 'https://www.googleapis.com/auth/gmail.compose', 'https://www.googleapis.com/auth/gmail.insert', 'https://www.googleapis.com/auth/gmail.settings.basic', 'https://www.googleapis.com/auth/gmail.settings.sharing', 'https://www.googleapis.com/auth/drive', 'https://www.googleapis.com/auth/drive.readonly'];
export const SHARING_LEVELS = ['anyone', 'new-and-existing-guests', 'existing-guests', 'only-organization'];
export const GOOGLE_ACCESS = ['trusted', 'limited', 'specific', 'blocked'];
export const UNCONFIGURED = ['allow-all', 'sign-in-only', 'block'];
const list = (j, n) => { const v = Array.isArray(j) ? j : j?.value || j?.items || j?.files; fail(Array.isArray(v), 400, `not_${n}_list`); return v; };
const highRisk = (provider, scopes) => scopes.filter(s => provider === 'google' ? GOOGLE_HIGH_RISK.includes(s) : riskyScope.test(s));

export function consentPolicy(authorizationPolicy) {
  const p = Array.isArray(authorizationPolicy?.value) ? authorizationPolicy.value[0] : authorizationPolicy;
  const assigned = p?.defaultUserRolePermissions?.permissionGrantPoliciesAssigned; fail(Array.isArray(assigned), 400, 'not_authorization_policy');
  const self = assigned.map(String).filter(a => /^managepermissiongrantsforself\./i.test(a)).map(a => a.split('.').slice(1).join('.').toLowerCase());
  return !self.length ? 'disabled' : self.includes('microsoft-user-default-legacy') ? 'all-apps' : self.every(x => x === 'microsoft-user-default-low') ? 'verified-low' : 'custom';
}

export function parseEntra({ authorizationPolicy, servicePrincipals, grants, tenantId = null }) {
  const sps = new Map(list(servicePrincipals, 'service_principal').map(s => [String(s.id), s])), apps = new Map();
  for (const g of list(grants, 'oauth2_permission_grant')) {
    const sp = sps.get(String(g.clientId)) || {}, id = String(g.clientId), a = apps.get(id) || { provider: 'entra', app_id: String(sp.appId || id), name: String(sp.displayName || id), publisher_verified: !!sp.verifiedPublisher?.displayName, internal: !!tenantId && sp.appOwnerOrganizationId === tenantId, users: new Set(), admin_consent: false, scopes: new Set(), access: null, anonymous: false, native_app: false };
    if (g.consentType === 'AllPrincipals') a.admin_consent = true; else if (g.principalId) a.users.add(String(g.principalId));
    for (const s of String(g.scope || '').split(/\s+/).filter(Boolean)) a.scopes.add(s);
    apps.set(id, a);
  }
  return { provider: 'entra', consent_policy: consentPolicy(authorizationPolicy), apps: finish([...apps.values()]) };
}

export function parseGoogle({ tokens, appAccess = [], unconfigured = null }) {
  const access = new Map(list(appAccess, 'app_access').map(a => [String(a.clientId), String(a.access).toLowerCase()])), apps = new Map();
  for (const t of list(tokens, 'token')) {
    const id = String(t.clientId), a = apps.get(id) || { provider: 'google', app_id: id, name: String(t.displayText || id), publisher_verified: null, internal: false, users: new Set(), admin_consent: false, scopes: new Set(), access: GOOGLE_ACCESS.includes(access.get(id)) ? access.get(id) : null, anonymous: false, native_app: false };
    if (t.userKey) a.users.add(String(t.userKey)); for (const s of t.scopes || []) a.scopes.add(String(s));
    a.anonymous ||= t.anonymous === true; a.native_app ||= t.nativeApp === true; apps.set(id, a);
  }
  return { provider: 'google', consent_policy: UNCONFIGURED.includes(unconfigured) ? unconfigured : 'unknown', apps: finish([...apps.values()]) };
}
const finish = apps => apps.map(a => ({ ...a, users: a.users.size, scopes: [...a.scopes].sort() })).sort((x, y) => y.users - x.users || x.name.localeCompare(y.name)).slice(0, 5000);

// Drive permissions per file, counted only. Names and ids are never kept; external users are counted by domain only.
export function countFileExposure(files, internalDomains) {
  const internal = new Set(internalDomains.map(d => d.toLowerCase())), ext = new Set(); const c = { files_reviewed: 0, anyone_discoverable: 0, anyone_with_link: 0, domain_discoverable: 0, shared_externally: 0 };
  for (const f of list(files, 'file')) { c.files_reviewed++; const ps = f.permissions || []; let external = false;
    for (const p of ps) { if (p.type === 'anyone') p.allowFileDiscovery ? c.anyone_discoverable++ : c.anyone_with_link++; else if (p.type === 'domain' && p.allowFileDiscovery) c.domain_discoverable++;
      const dom = p.type === 'domain' ? p.domain : String(p.emailAddress || '').split('@')[1]; if ((p.type === 'user' || p.type === 'group' || p.type === 'domain') && dom && !internal.has(dom.toLowerCase())) { external = true; ext.add(dom.toLowerCase()); } }
    if (external) c.shared_externally++; }
  return { ...c, external_domains: ext.size };
}

const POLICY_FINDING = { 'all-apps': ['user-consent-any-app', 'high'], custom: ['user-consent-custom-policy', 'low'], 'allow-all': ['unconfigured-apps-allowed', 'high'], unknown: ['consent-policy-unknown', 'low'] };
export function assessAppAccess(d) {
  const findings = [], add = (type, severity, subject, detail) => findings.push({ type, severity, subject, detail });
  if (POLICY_FINDING[d.consent_policy]) add(...POLICY_FINDING[d.consent_policy], d.tenant_ref, d.consent_policy);
  if (d.sharing?.level === 'anyone') add(d.sharing.anyone_link_expiration_days ? 'anyone-links-allowed' : 'anyone-links-no-expiry', d.sharing.anyone_link_expiration_days ? 'low' : 'medium', d.tenant_ref, d.sharing.anyone_link_expiration_days ? `${d.sharing.anyone_link_expiration_days} days` : 'no expiration');
  if (d.file_exposure?.anyone_discoverable) add('public-discoverable-files', 'medium', d.tenant_ref, `${d.file_exposure.anyone_discoverable} files`);
  const apps = d.apps.map(a => {
    const risky = highRisk(d.provider, a.scopes), f = [];
    if (d.provider === 'entra') { if (risky.length && !a.publisher_verified && !a.internal) f.push(['unverified-high-risk', 'high']); else if (a.admin_consent && risky.length) f.push(['tenant-wide-high-risk', 'medium']); else if (!a.publisher_verified && !a.internal) f.push(['unverified-publisher', 'low']); }
    else { if (a.access === 'blocked') f.push(['blocked-app-holds-tokens', 'high']); else if (!a.access) f.push(risky.length ? ['unreviewed-high-risk', 'high'] : ['unreviewed-app', 'medium']); else if (a.access !== 'trusted' && risky.length) f.push(['limited-high-risk', 'medium']); }
    if (a.anonymous) f.push(['anonymous-client', 'medium']);
    for (const [type, severity] of f) add(type, severity, a.name, `${a.users} users${a.admin_consent ? ', admin consent for all users' : ''}${risky.length ? `; ${risky.join(' ')}` : ''}`);
    return { ...a, high_risk_scopes: risky, findings: f.map(x => x[0]), reviewed: d.provider === 'entra' ? a.publisher_verified || a.internal : !!a.access };
  });
  const rank = { high: 0, medium: 1, low: 2 };
  return { apps, findings: findings.sort((a, b) => rank[a.severity] - rank[b.severity]),
    summary: { apps: apps.length, unreviewed: apps.filter(a => !a.reviewed).length, high_risk: apps.filter(a => a.high_risk_scopes.length).length, admin_consent: apps.filter(a => a.admin_consent).length, grants: apps.reduce((n, a) => n + a.users, 0) } };
}

export function appAccessView(store) {
  const latest = new Map();
  for (const r of store.all("SELECT observed_at,payload FROM events WHERE kind='identity.saas_app_access' ORDER BY observed_at,received_at")) { const d = JSON.parse(r.payload).details; latest.set(`${d.provider}|${d.tenant_ref}`, { ...d, observed_at: r.observed_at }); }
  return { tenants: [...latest.values()].map(d => ({ provider: d.provider, tenant_ref: d.tenant_ref, consent_policy: d.consent_policy, sharing: d.sharing, file_exposure: d.file_exposure, privacy_policy_ref: d.privacy_policy_ref, observed_at: d.observed_at, ...assessAppAccess(d) })), references: REFERENCES,
    claim: 'Third-party app access is inventoried from read-only exports: which apps hold which OAuth scopes, how many users granted them, whether the publisher is verified or the app was reviewed, the tenant consent policy and external sharing settings. Only counts of users are kept, file sharing is counted only under a declared privacy policy, and no mail, file or chat content is read.',
    claim_ar: 'يُجرد وصول التطبيقات الخارجية من تصديرات للقراءة فقط: أي التطبيقات تملك أي نطاقات OAuth، وكم مستخدمًا منحها، وهل ناشرها موثق أو راجعها المسؤول، وسياسة الموافقة في المستأجر وإعدادات المشاركة الخارجية. ولا يُحفظ من المستخدمين إلا عددهم، ولا تُعد مشاركة الملفات إلا بمرجع سياسة خصوصية معلن، ولا يُقرأ محتوى بريد أو ملفات أو محادثات.' };
}
