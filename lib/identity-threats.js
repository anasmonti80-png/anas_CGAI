// CG-015 identity threat analysis: missing MFA, stale accounts, anomalous sign-in, password spraying,
// brute force, risky OAuth consents and identity-provider changes. Pure functions over stored evidence.
const DAY = 24 * 60 * 60 * 1000;
const riskyScope = /(\.ReadWrite\.All$)|(^Mail\.(Read|ReadWrite|Send)$)|(^Files\.ReadWrite\.All$)|(^Directory\.)|(^RoleManagement\.)|(^Application\.ReadWrite)|(^full_access_as_app$)/i;
const sensitiveIdpSettings = new Set(['federation', 'conditional-access', 'mfa-policy', 'sso-certificate', 'password-policy', 'identity-provider', 'token-lifetime']);

export function accountPostureFindings(posture, now) {
  const findings = [];
  for (const account of posture.accounts) {
    if (!account.enabled) continue;
    if (account.mfa_registered === false) findings.push({ type: 'mfa-not-registered', severity: account.privileged ? 'high' : 'medium', subject: account.principal_ref, detail: account.privileged ? 'privileged account without MFA' : 'account without MFA' });
    const last = account.last_signin_at ? Date.parse(account.last_signin_at) : null;
    if (last === null || now - last > 90 * DAY) findings.push({ type: 'stale-account', severity: account.privileged ? 'high' : 'medium', subject: account.principal_ref, detail: last === null ? 'enabled but never signed in' : `no sign-in for ${Math.floor((now - last) / DAY)} days` });
    if (account.credential_changed_at && now - Date.parse(account.credential_changed_at) > 365 * DAY) findings.push({ type: 'password-not-rotated', severity: 'low', subject: account.principal_ref, detail: `password unchanged for ${Math.floor((now - Date.parse(account.credential_changed_at)) / DAY)} days` });
  }
  return findings;
}

export function signinFindings(batch) {
  const findings = [], failures = batch.signins.filter(s => s.result === 'failure'), successes = batch.signins.filter(s => s.result === 'success');
  const byIp = new Map();
  for (const f of failures) if (f.source_ip) { if (!byIp.has(f.source_ip)) byIp.set(f.source_ip, new Map()); const m = byIp.get(f.source_ip); m.set(f.principal_ref, (m.get(f.principal_ref) || 0) + 1); }
  for (const [ip, principals] of byIp) if (principals.size >= 10 && Math.max(...principals.values()) <= 3) findings.push({ type: 'password-spraying', severity: 'high', subject: ip, detail: `${principals.size} accounts, at most ${Math.max(...principals.values())} failures each`, key: `${batch.batch_id}:${ip}` });
  const byPrincipal = new Map();
  for (const f of failures) byPrincipal.set(f.principal_ref, (byPrincipal.get(f.principal_ref) || 0) + 1);
  for (const [principal, count] of byPrincipal) if (count >= 10) {
    const lastFailure = failures.filter(f => f.principal_ref === principal).map(f => f.at).sort().pop();
    const success = successes.some(s => s.principal_ref === principal && s.at > lastFailure);
    findings.push({ type: success ? 'brute-force-then-success' : 'brute-force', severity: success ? 'high' : 'medium', subject: principal, detail: `${count} failures${success ? ' followed by a success' : ''}`, key: `${batch.batch_id}:${principal}` });
  }
  const sorted = [...successes].filter(s => s.country).sort((a, b) => a.at.localeCompare(b.at)), seen = new Map();
  for (const s of sorted) {
    const prior = seen.get(s.principal_ref) || [];
    const last = prior[prior.length - 1];
    if (last && last.country !== s.country && Date.parse(s.at) - Date.parse(last.at) <= 60 * 60 * 1000) findings.push({ type: 'impossible-travel', severity: 'high', subject: s.principal_ref, detail: `${last.country} → ${s.country} within ${Math.round((Date.parse(s.at) - Date.parse(last.at)) / 60000)} min`, key: `${batch.batch_id}:${s.signin_id}` });
    else if (prior.length && !prior.some(p => p.country === s.country)) findings.push({ type: 'new-country-signin', severity: 'medium', subject: s.principal_ref, detail: `first sign-in from ${s.country}`, key: `${batch.batch_id}:${s.signin_id}` });
    seen.set(s.principal_ref, [...prior, s]);
  }
  return findings;
}

export function oauthFindings(consent) {
  const risky = consent.scopes.filter(scope => riskyScope.test(scope)), offlineMail = consent.scopes.includes('offline_access') && consent.scopes.some(s => /^Mail\./i.test(s));
  if ((!consent.publisher_verified && (risky.length || offlineMail)) || (consent.consent_type === 'admin' && !consent.publisher_verified)) return [{ type: 'risky-oauth-consent', severity: 'high', subject: consent.app_ref, detail: `${consent.consent_type} consent, ${consent.publisher_verified ? 'verified' : 'unverified'} publisher, scopes: ${(risky.length ? risky : consent.scopes).join(' ')}`, key: consent.consent_id }];
  if (risky.length) return [{ type: 'broad-oauth-consent', severity: 'medium', subject: consent.app_ref, detail: `verified publisher with broad scopes: ${risky.join(' ')}`, key: consent.consent_id }];
  return [];
}

export function idpChangeFindings(change) {
  if (!sensitiveIdpSettings.has(change.setting)) return [];
  return change.authorization_ref ? [{ type: 'idp-change-authorized', severity: 'info', subject: change.setting, detail: `${change.action} by ${change.actor_ref} (${change.authorization_ref})`, key: change.change_id }]
    : [{ type: 'idp-change-unauthorized', severity: 'high', subject: change.setting, detail: `${change.action} by ${change.actor_ref} without authorization reference`, key: change.change_id }];
}

export const identityAlertRules = {
  'password-spraying': 'CG-IDENT-SPRAY-009', 'brute-force-then-success': 'CG-IDENT-BRUTE-010', 'brute-force': 'CG-IDENT-BRUTE-010',
  'impossible-travel': 'CG-IDENT-TRAVEL-011', 'risky-oauth-consent': 'CG-IDENT-OAUTH-012', 'idp-change-unauthorized': 'CG-IDENT-IDP-013',
};
