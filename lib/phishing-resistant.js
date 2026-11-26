// CG-150 Phishing-resistant authentication posture. Generic MFA is not phishing-resistant MFA. Following the CISA
// fact sheet "Implementing Phishing-Resistant MFA" (October 2022), methods are ranked:
//   phishing-resistant (FIDO/WebAuthn passkeys and security keys, Windows Hello for Business or platform credentials,
//   PKI/certificate-based) > app or token OTP and push with number matching > SMS or voice > not MFA.
// Inputs are read-only Entra exports: the user registration details report, Conditional Access policies and sign-ins.
// Registration proves a user can use a method, not that it is required: enforcement comes from Conditional Access
// authentication strengths. Successful sign-ins over legacy protocols bypass MFA and are shown as exceptions, as are
// the owner-declared applications that cannot use phishing-resistant methods.
import { fail } from './common.js';

export const TIERS = ['phishing-resistant', 'app-or-otp', 'sms-voice', 'not-mfa', 'none'];
export const TIER_AR = { 'phishing-resistant': 'مقاوم للتصيد', 'app-or-otp': 'تطبيق أو رمز لمرة واحدة', 'sms-voice': 'رسالة نصية أو مكالمة', 'not-mfa': 'ليس عاملًا ثانيًا', none: 'لا طريقة مسجلة' };
// methodsRegistered is a free-form string collection; unknown values stay unclassified and are never phishing-resistant.
export function methodTier(m) {
  const v = String(m);
  if (/^passKey|^fido2$|windowsHello|platformCredential|macOsSecureEnclaveKey|^x509Certificate|certificateBased/i.test(v)) return 'phishing-resistant';
  if (/^microsoftAuthenticator|OneTimePasscode$|^oath/i.test(v)) return 'app-or-otp';
  if (/^(mobilePhone|alternateMobilePhone|officePhone|sms|voice)/i.test(v)) return 'sms-voice';
  if (/^(email|securityQuestion|temporaryAccessPass|appPassword|password)$/i.test(v)) return 'not-mfa';
  return 'unclassified';
}
// Authentication method modes allowed by the built-in "Phishing-resistant MFA" authentication strength.
const PR_MODES = ['windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor'];
const MODERN_CLIENTS = ['Browser', 'Mobile Apps and Desktop clients'];

export function parseAuthPosture({ tenantId, registrations, policies = { value: [] }, signIns = { value: [] }, exceptions = [] }) {
  fail(/^[0-9a-f-]{36}$/i.test(String(tenantId || '')), 400, 'invalid_tenant_id');
  const regs = (typeof registrations === 'string' ? JSON.parse(registrations) : registrations)?.value; fail(Array.isArray(regs) && regs.every(r => r.userPrincipalName && Array.isArray(r.methodsRegistered)), 400, 'not_user_registration_details_export');
  const users = regs.slice(0, 50000).map(r => { const tiers = r.methodsRegistered.map(methodTier), best = TIERS.find(t => tiers.includes(t)) || 'none';
    return { upn: String(r.userPrincipalName).slice(0, 200), is_admin: r.isAdmin === true, user_type: r.userType === 'guest' ? 'guest' : 'member', tier: best, methods: r.methodsRegistered.map(String).slice(0, 30), unclassified: r.methodsRegistered.filter(m => methodTier(m) === 'unclassified').map(String).slice(0, 10) }; });
  const pols = ((typeof policies === 'string' ? JSON.parse(policies) : policies)?.value || []).map(p => {
    const s = p.grantControls?.authenticationStrength, combos = s?.allowedCombinations || [];
    const strength = !s ? (p.grantControls?.builtInControls || []).includes('mfa') ? 'mfa' : 'none' : (combos.length ? combos.every(c => PR_MODES.includes(c)) : /phishing-resistant/i.test(s.displayName || '')) ? 'phishing-resistant' : 'mfa';
    const u = p.conditions?.users || {}, scope = (u.includeUsers || []).includes('All') ? 'all' : (u.includeRoles || []).length ? 'roles' : (u.includeUsers || u.includeGroups || []).length ? 'some' : 'none';
    const clientTypes = p.conditions?.clientAppTypes || [], blocksLegacy = (p.grantControls?.builtInControls || []).includes('block') && clientTypes.includes('exchangeActiveSync') && clientTypes.includes('other');
    return { name: String(p.displayName || p.id).slice(0, 200), state: String(p.state || ''), strength, scope, blocks_legacy: blocksLegacy, excluded: (u.excludeUsers || []).length + (u.excludeGroups || []).length };
  });
  const sis = ((typeof signIns === 'string' ? JSON.parse(signIns) : signIns)?.value || []);
  const legacy = sis.filter(x => x.clientAppUsed && !MODERN_CLIENTS.includes(x.clientAppUsed) && Number(x.status?.errorCode ?? 0) === 0).slice(0, 5000)
    .map(x => ({ upn: String(x.userPrincipalName || '').slice(0, 200), client_app: String(x.clientAppUsed).slice(0, 80), app: String(x.appDisplayName || '').slice(0, 120), at: x.createdDateTime }));
  fail(Array.isArray(exceptions) && exceptions.length <= 500, 400, 'invalid_auth_exceptions');
  const exc = exceptions.map(e => { fail(e && e.app && e.reason && e.owner, 400, 'invalid_auth_exception'); return { app: String(e.app).slice(0, 120), reason: String(e.reason).slice(0, 300), owner: String(e.owner).slice(0, 120), compensating: e.compensating ? String(e.compensating).slice(0, 300) : null, review_by: e.review_by || null }; });
  return { tenant_id: tenantId.toLowerCase(), users, policies: pols, legacy_signins: legacy, exceptions: exc };
}

export function assessAuthPosture(d, now = Date.now()) {
  const count = (list, t) => list.filter(u => u.tier === t).length, admins = d.users.filter(u => u.is_admin), enabled = d.policies.filter(p => p.state === 'enabled');
  const enforce = enabled.some(p => p.strength === 'phishing-resistant' && p.scope === 'all') ? 'all-users' : enabled.some(p => p.strength === 'phishing-resistant' && (p.scope === 'roles' || p.scope === 'some')) ? 'some-users' : 'not-enforced';
  const legacyBlocked = enabled.some(p => p.blocks_legacy && p.scope === 'all');
  const byClient = {}; for (const s of d.legacy_signins) byClient[s.client_app] = (byClient[s.client_app] || 0) + 1;
  return { users: { total: d.users.length, ...Object.fromEntries(TIERS.map(t => [t, count(d.users, t)])) }, admins: { total: admins.length, ...Object.fromEntries(TIERS.map(t => [t, count(admins, t)])) },
    admins_without_phishing_resistant: admins.filter(u => u.tier !== 'phishing-resistant').map(u => ({ upn: u.upn, tier: u.tier })),
    unclassified_methods: [...new Set(d.users.flatMap(u => u.unclassified))],
    enforcement: enforce, legacy_blocked: legacyBlocked, policies: d.policies,
    legacy: { signins: d.legacy_signins.length, users: [...new Set(d.legacy_signins.map(s => s.upn))].length, by_client: byClient, recent: [...d.legacy_signins].sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 100) },
    exceptions: d.exceptions.map(e => ({ ...e, review_overdue: !!(e.review_by && Date.parse(e.review_by) < now) })) };
}

export function authPostureView(store, now = Date.now()) {
  const latest = new Map();
  for (const r of store.all("SELECT observed_at,payload FROM events WHERE kind='identity.auth_strength_posture' ORDER BY observed_at,received_at")) { const d = JSON.parse(r.payload).details; latest.set(d.tenant_id, { ...d, observed_at: r.observed_at }); }
  return { tenants: [...latest.values()].map(d => ({ tenant_id: d.tenant_id, observed_at: d.observed_at, ...assessAuthPosture(d, now) })), tiers: TIERS, tier_ar: TIER_AR,
    reference: { id: 'CISA: Implementing Phishing-Resistant MFA (October 2022)', url: 'https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf' },
    claim: 'MFA is not counted as phishing-resistant. Only FIDO/WebAuthn passkeys and security keys, Windows Hello for Business or platform credentials and certificate-based authentication are. Registration shows capability; enforcement is only an enabled Conditional Access policy with a phishing-resistant authentication strength. Legacy protocol sign-ins and applications that cannot use these methods are listed as exceptions.',
    claim_ar: 'لا يُحتسب التحقق متعدد العوامل العام مقاومًا للتصيد. المقاوم فقط: مفاتيح المرور ومفاتيح الأمان FIDO/WebAuthn، وWindows Hello for Business أو بيانات اعتماد المنصة، والمصادقة بالشهادات. والتسجيل يثبت القدرة فقط؛ أما الإلزام فهو سياسة وصول مشروط مفعّلة بقوة مصادقة مقاومة للتصيد. ويُدرج الدخول عبر البروتوكولات القديمة والتطبيقات التي لا تدعم هذه الطرق استثناءات.' };
}
