// CG-049 Temporary, least-privilege cloud access. Each cloud.access_grant records how CyberGuard (or anyone the review
// covers) reaches one account, subscription or project: the roles, the mechanism and when the access ends. The review
// flags standing administrator access, root credentials, standing write access, sessions longer than one hour and grants
// that span a whole organisation instead of one account, subscription or project.
const short = (v, max = 300) => (v === null || v === undefined || v === '' ? null : String(v).replace(/[\x00-\x1f\x7f]/g, ' ').trim().slice(0, max) || null);
const isoZ = v => { const t = Date.parse(v); return Number.isFinite(t) ? new Date(t).toISOString() : null; };
const obj = v => (typeof v === 'string' ? JSON.parse(v) : v);

export const grantMechanisms = ['assume-role', 'pim-activation', 'pim-eligible', 'impersonation', 'conditional-binding', 'standing-assignment', 'directory-role', 'root-credentials'];
export const grantScopes = ['account', 'subscription', 'project', 'resource-group', 'organization', 'management-group', 'folder', 'tenant'];
const broadScopes = ['organization', 'management-group', 'folder', 'tenant'];
const temporaryMechanisms = ['assume-role', 'pim-activation', 'pim-eligible', 'impersonation'];
export const maxSessionSeconds = 3600;

const adminRoles = [/^AdministratorAccess$/, /^IAMFullAccess$/, /^Owner$/, /^User Access Administrator$/, /^Role Based Access Control Administrator$/, /^Global Administrator$/, /^Privileged Role Administrator$/, /^Privileged Authentication Administrator$/, /^Security Administrator$/, /^roles\/owner$/, /^roles\/editor$/, /^roles\/resourcemanager\.(organization|folder|project)IamAdmin$/, /^roles\/resourcemanager\.organizationAdmin$/, /^roles\/iam\.(securityAdmin|serviceAccountTokenCreator|serviceAccountKeyAdmin)$/];
const readRoles = [/ReadOnly/i, /^SecurityAudit$/, /^ViewOnlyAccess$/, /^Reader$/, /Reader$/, /^Security Reader$/, /^Global Reader$/, /viewer$/i, /Viewer$/, /securityReviewer$/, /findingsViewer$/, /^roles\/browser$/, /^CyberGuard Read Only$/];
export const privilegeOf = roles => (roles.some(r => adminRoles.some(re => re.test(r))) ? 'admin' : roles.length && roles.every(r => readRoles.some(re => re.test(r))) ? 'read' : 'write');

// Review one grant at time `now`: returns status (compliant | warning | violation | expired) and the reasons.
export function reviewGrant(g, now = Date.now()) {
  const violations = [], warnings = [], expires = g.expires_at ? Date.parse(g.expires_at) : null, temporary = temporaryMechanisms.includes(g.mechanism) || (expires !== null);
  if (expires !== null && expires <= now) return { status: 'expired', reasons: ['expired'], temporary: true };
  if (g.mechanism === 'root-credentials') violations.push('root-credentials');
  if (g.privilege === 'admin' && g.mechanism !== 'pim-eligible' && !(g.mechanism === 'pim-activation' && expires !== null)) violations.push(temporary ? 'admin-not-time-bound' : 'standing-admin');
  if (g.privilege === 'write' && !temporary) violations.push('standing-write');
  // Write access spanning an organisation, management group or folder; tenant directory roles are covered by the admin rules, and PIM eligibility or a time-bound activation is not standing access.
  if (broadScopes.includes(g.scope_type) && g.scope_type !== 'tenant' && g.privilege !== 'read' && g.mechanism !== 'pim-eligible' && !(g.mechanism === 'pim-activation' && expires !== null)) violations.push('broad-write-scope');
  if (g.max_session_seconds !== null && g.max_session_seconds > maxSessionSeconds) warnings.push('session-too-long');
  if (broadScopes.includes(g.scope_type) && g.privilege === 'read') warnings.push('broad-read-scope');
  if (g.privilege === 'read' && !temporary) warnings.push('standing-read');
  return { status: violations.length ? 'violation' : warnings.length ? 'warning' : 'compliant', reasons: [...violations, ...warnings], temporary };
}

const scopeOf = scope => { const s = String(scope || '').toLowerCase();
  return s.includes('/resourcegroups/') ? 'resource-group' : /^\/subscriptions\/[^/]+\/?$/.test(s) ? 'subscription' : s.includes('managementgroups') ? 'management-group' : s === '/' || s === '' ? 'tenant' : s.startsWith('organizations/') ? 'organization' : s.startsWith('folders/') ? 'folder' : s.startsWith('projects/') ? 'project' : 'subscription'; };

// AWS: iam get-role + iam list-attached-role-policies for the connector role in one member account.
export function awsRoleGrant(roleJson, attachedJson, accountId) {
  const role = obj(roleJson)?.Role, attached = obj(attachedJson)?.AttachedPolicies; if (!role || !Array.isArray(attached)) throw new Error('need iam get-role and iam list-attached-role-policies output');
  const roles = attached.map(p => p.PolicyName), trust = JSON.stringify(role.AssumeRolePolicyDocument || {});
  return { grant_id: `aws:${accountId}:${role.RoleName}`, provider: 'aws', scope_type: 'account', scope_ref: accountId, principal_ref: short(role.Arn, 300), roles, privilege: privilegeOf(roles), mechanism: 'assume-role', max_session_seconds: Number(role.MaxSessionDuration) || 3600, expires_at: null, conditions: [/sts:ExternalId/.test(trust) ? 'external id required' : 'no external id', /aws:MultiFactorAuthPresent/.test(trust) ? 'MFA required' : null].filter(Boolean), evidence_ref: short(`iam get-role ${role.RoleName}`, 200) };
}
// AWS: iam get-account-summary — root access keys are standing root credentials.
export function awsRootGrant(summaryJson, accountId) {
  const m = obj(summaryJson)?.SummaryMap; if (!m) throw new Error('need iam get-account-summary output');
  if (!(Number(m.AccountAccessKeysPresent) > 0)) return null;
  return { grant_id: `aws:${accountId}:root-access-keys`, provider: 'aws', scope_type: 'account', scope_ref: accountId, principal_ref: `arn:aws:iam::${accountId}:root`, roles: ['root'], privilege: 'admin', mechanism: 'root-credentials', max_session_seconds: null, expires_at: null, conditions: [Number(m.AccountMFAEnabled) > 0 ? 'root MFA enabled' : 'root MFA not enabled'], evidence_ref: 'iam get-account-summary AccountAccessKeysPresent' };
}
// Azure RBAC: roleAssignmentScheduleInstances (active, including PIM activations) and roleEligibilityScheduleInstances.
export function azureRoleGrants(activeJson, eligibleJson = null) {
  const rows = [...(obj(activeJson)?.value || []).map(x => ({ x, eligible: false })), ...((eligibleJson && obj(eligibleJson)?.value) || []).map(x => ({ x, eligible: true }))];
  return rows.map(({ x, eligible }) => { const p = x.properties || {}, role = p.expandedProperties?.roleDefinition?.displayName || String(p.roleDefinitionId || '').split('/').pop(), scope = p.scope || p.expandedProperties?.scope?.id || '';
    return { grant_id: short(`azure:${x.name || x.id}`, 300), provider: 'azure', scope_type: scopeOf(scope), scope_ref: short(scope || '/', 300), principal_ref: short(p.expandedProperties?.principal?.displayName || p.principalId, 300), roles: [role], privilege: privilegeOf([role]), mechanism: eligible ? 'pim-eligible' : p.assignmentType === 'Activated' ? 'pim-activation' : 'standing-assignment', max_session_seconds: null, expires_at: eligible ? null : isoZ(p.endDateTime), conditions: [p.condition ? short(p.condition, 200) : null, eligible && p.endDateTime ? `eligible until ${isoZ(p.endDateTime)}` : null].filter(Boolean), evidence_ref: eligible ? 'roleEligibilityScheduleInstances' : 'roleAssignmentScheduleInstances' }; });
}
// Microsoft Entra directory roles: Graph roleManagement/directory/roleAssignmentScheduleInstances (+ eligibility) with $expand=roleDefinition,principal
export function entraDirectoryRoleGrants(activeJson, eligibleJson = null, tenant = 'tenant') {
  const rows = [...(obj(activeJson)?.value || []).map(x => ({ x, eligible: false })), ...((eligibleJson && obj(eligibleJson)?.value) || []).map(x => ({ x, eligible: true }))];
  return rows.map(({ x, eligible }) => { const role = x.roleDefinition?.displayName || x.roleDefinitionId; return { grant_id: short(`entra:${x.id}`, 300), provider: 'azure', scope_type: 'tenant', scope_ref: short(`${tenant}${x.directoryScopeId && x.directoryScopeId !== '/' ? x.directoryScopeId : ''}`, 300), principal_ref: short(x.principal?.userPrincipalName || x.principal?.displayName || x.principalId, 300), roles: [role], privilege: privilegeOf([role]), mechanism: eligible ? 'pim-eligible' : 'directory-role', max_session_seconds: null, expires_at: eligible ? null : isoZ(x.endDateTime), conditions: [x.assignmentType ? `assignment ${x.assignmentType}` : null].filter(Boolean), evidence_ref: eligible ? 'roleEligibilityScheduleInstances (directory)' : 'roleAssignmentScheduleInstances (directory)' }; }).map(g => (g.mechanism === 'directory-role' && g.expires_at ? { ...g, mechanism: 'pim-activation' } : g));
}
// Google Cloud: bindings of one member in a getIamPolicy result; an IAM condition "request.time < timestamp(...)" is an expiry.
export function gcpMemberGrants(policyJson, member, scopeRef, { impersonated = false } = {}) {
  const p = obj(policyJson); if (!Array.isArray(p?.bindings)) throw new Error('need a getIamPolicy result');
  return p.bindings.filter(b => (b.members || []).includes(member)).map(b => { const m = String(b.condition?.expression || '').match(/request\.time\s*<\s*timestamp\(["']([^"']+)["']\)/);
    return { grant_id: short(`gcp:${scopeRef}:${member}:${b.role}`, 300), provider: 'gcp', scope_type: scopeOf(scopeRef), scope_ref: short(scopeRef, 300), principal_ref: short(member, 300), roles: [b.role], privilege: privilegeOf([b.role]), mechanism: impersonated ? 'impersonation' : m ? 'conditional-binding' : 'standing-assignment', max_session_seconds: impersonated ? 3600 : null, expires_at: m ? isoZ(m[1]) : null, conditions: [b.condition?.title ? short(b.condition.title, 200) : null].filter(Boolean), evidence_ref: 'getIamPolicy' }; });
}
