// CG-048 Google Cloud read-only converters. Inputs are the documented read outputs of gcloud / Google Cloud APIs:
//   projects list, Security Command Center findings, Cloud Logging LogEntry (Cloud Audit Logs, VPC Flow Logs, Firewall
//   Rules Logging, external HTTP(S) load balancer logs with Cloud Armor), getIamPolicy, compute firewall-rules list,
//   compute security-policies describe and compute networks subnets list. Nothing here writes to Google Cloud.
import { isIP } from 'node:net';

export const gcpServices = ['asset-inventory', 'scc', 'cloud-audit-logs', 'vpc-flow-logs', 'firewall-rules-logging', 'vpc-firewall', 'cloud-armor', 'iam'];
export const gcpProjectPattern = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const short = (v, max = 300) => (v === null || v === undefined || v === '' ? null : String(v).replace(/[\x00-\x1f\x7f]/g, ' ').trim().slice(0, max) || null);
const isoZ = v => { const t = Date.parse(v); return Number.isFinite(t) ? new Date(t).toISOString() : null; };
const obj = v => (typeof v === 'string' ? JSON.parse(v) : v);
const arr = (v, name) => { const x = obj(v), l = Array.isArray(x) ? x : x?.items || x?.findings || x?.listFindingsResults || x?.projects || x?.entries || x?.rules; if (!Array.isArray(l)) throw new Error(`not a ${name} response`); return l.slice(0, 20000); };
const cidrOk = v => isIP(String(v).split('/')[0]) !== 0;

// gcloud projects list --format=json
export function projects(json) {
  return arr(json, 'projects list').map(p => ({ account_id: String(p.projectId || ''), name: short(p.name, 200), status: { ACTIVE: 'active', DELETE_REQUESTED: 'pending-closure', DELETE_IN_PROGRESS: 'pending-closure' }[p.lifecycleState || p.state] || 'unknown', access: 'not-attempted' })).filter(p => gcpProjectPattern.test(p.account_id));
}

// Service state per project from what the read calls returned; anything missing stays "not-checked".
// enabledApis: {project: gcloud services list --enabled}; subnets: {project: networks subnets list}; firewalls: {project: firewall-rules list};
// armor: {project: security-policies list}; iam: {project: get-iam-policy | 'access-denied'}; scc: 'enabled'|'disabled'|'access-denied' (organization level)
export function gcpServiceStatus({ accounts, enabledApis = {}, subnets = {}, firewalls = {}, armor = {}, iam = {}, scc }) {
  const rows = [];
  for (const a of accounts.filter(x => x.status === 'active' && ['assumed', 'management'].includes(x.access))) {
    const add = (service, status, detail = null, region = null) => rows.push({ account_id: a.account_id, region, service, status, detail: short(detail, 300) });
    const apis = enabledApis[a.account_id];
    if (apis === 'access-denied') add('asset-inventory', 'access-denied'); else if (apis) { const names = arr(apis, 'services list').map(s => String(s.config?.name || s.name || '').split('/').pop()); add('asset-inventory', names.includes('cloudasset.googleapis.com') ? 'enabled' : 'disabled', names.includes('cloudasset.googleapis.com') ? 'Cloud Asset API enabled' : 'Cloud Asset API not enabled'); } else add('asset-inventory', 'not-checked');
    add('scc', scc === 'enabled' ? 'enabled' : scc === 'disabled' ? 'disabled' : scc === 'access-denied' ? 'access-denied' : 'not-checked', scc ? 'organization level' : null);
    const pol = iam[a.account_id];
    if (pol === 'access-denied') { add('iam', 'access-denied'); add('cloud-audit-logs', 'access-denied'); }
    else if (pol) { const p = obj(pol), data = (p.auditConfigs || []).filter(c => c.service === 'allServices' || c.service).flatMap(c => (c.auditLogConfigs || []).map(l => l.logType)); add('iam', 'enabled', `${(p.bindings || []).length} binding(s)`); add('cloud-audit-logs', data.some(t => /DATA_(READ|WRITE)/.test(t)) ? 'enabled' : 'disabled', data.some(t => /DATA_(READ|WRITE)/.test(t)) ? `Admin Activity and Data Access (${[...new Set(data)].join(', ')})` : 'Admin Activity only (always on); Data Access logs not configured'); }
    else { add('iam', 'not-checked'); add('cloud-audit-logs', 'not-checked'); }
    const sn = subnets[a.account_id];
    if (sn === 'access-denied') add('vpc-flow-logs', 'access-denied');
    else if (sn) { const list = arr(sn, 'subnets list'), byRegion = {}; for (const s of list) { const r = String(s.region || '').split('/').pop() || 'unknown'; (byRegion[r] ||= []).push(s.logConfig?.enable === true || s.enableFlowLogs === true); }
      if (!list.length) add('vpc-flow-logs', 'not-available', 'no subnets'); for (const [r, flags] of Object.entries(byRegion)) add('vpc-flow-logs', flags.every(Boolean) ? 'enabled' : 'disabled', `${flags.filter(Boolean).length}/${flags.length} subnet(s) with flow logs`, r); }
    else add('vpc-flow-logs', 'not-checked');
    const fw = firewalls[a.account_id];
    if (fw === 'access-denied') { add('vpc-firewall', 'access-denied'); add('firewall-rules-logging', 'access-denied'); }
    else if (fw) { const list = arr(fw, 'firewall-rules list'), logged = list.filter(r => r.logConfig?.enable).length; add('vpc-firewall', list.length ? 'enabled' : 'disabled', `${list.length} rule(s)`); add('firewall-rules-logging', list.length && logged === list.length ? 'enabled' : 'disabled', `${logged}/${list.length} rule(s) logged`); }
    else { add('vpc-firewall', 'not-checked'); add('firewall-rules-logging', 'not-checked'); }
    const ar = armor[a.account_id];
    if (ar === 'access-denied') add('cloud-armor', 'access-denied'); else if (ar) { const list = arr(ar, 'security-policies list'); add('cloud-armor', list.length ? 'enabled' : 'disabled', list.length ? `${list.length} security polic(ies)` : 'no Cloud Armor policy'); } else add('cloud-armor', 'not-checked');
  }
  return rows;
}

// gcloud scc findings list <org> --format=json  (ListFindingsResult: {finding, resource})
export function sccFindings(json) {
  return arr(json, 'SCC findings list').map(x => { const f = x.finding || x, r = x.resource || {}, project = r.projectDisplayName || r.project_display_name || f.sourceProperties?.ProjectId || null;
    return { finding_id: short(f.name, 300), provider: 'gcp', account_id: project, region: short(r.location || f.sourceProperties?.location || null, 40), product: 'scc', title: short(f.category, 300) || 'SCC finding', severity: ({ CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' })[f.severity] || 'info', resource_type: short(r.type || null, 200), resource_id: short(f.resourceName || r.name, 500), status: f.state === 'INACTIVE' ? 'resolved' : f.mute === 'MUTED' ? 'suppressed' : 'active', compliance: f.findingClass === 'MISCONFIGURATION' ? (f.state === 'INACTIVE' ? 'passed' : 'failed') : null, types: [short(f.findingClass, 200), ...(f.compliances || []).slice(0, 3).map(c => short(`${c.standard} ${c.version || ''}`.trim(), 200))].filter(Boolean), first_seen: isoZ(f.createTime), updated_at: isoZ(f.eventTime) }; }).filter(f => f.finding_id && gcpProjectPattern.test(f.account_id || ''));
}

// getIamPolicy  →  identity.directory_snapshot details (directory type gcp-iam)
export const privilegedGcpRoles = ['roles/owner', 'roles/editor', 'roles/resourcemanager.organizationAdmin', 'roles/resourcemanager.projectIamAdmin', 'roles/iam.securityAdmin', 'roles/iam.serviceAccountAdmin', 'roles/iam.serviceAccountKeyAdmin', 'roles/iam.serviceAccountTokenCreator', 'roles/iam.workloadIdentityPoolAdmin', 'roles/compute.admin', 'roles/compute.securityAdmin', 'roles/storage.admin', 'roles/logging.admin', 'roles/securitycenter.admin'];
export function iamSnapshot(json, project, { method = 'export-import', credentialRef = null } = {}) {
  const p = obj(json); if (!Array.isArray(p?.bindings)) throw new Error('not a getIamPolicy response (bindings[] missing)');
  const kind = m => (m.startsWith('user:') ? 'user' : m.startsWith('group:') ? 'group' : m.startsWith('serviceAccount:') || m.startsWith('principal') ? 'service' : m.startsWith('deleted:') ? 'user' : 'group');
  const principals = new Map(), privileges = [], publicBindings = [];
  for (const b of p.bindings.slice(0, 2000)) for (const m of (b.members || []).slice(0, 2000)) {
    const priv = privilegedGcpRoles.includes(b.role), cond = b.condition ? ` if ${b.condition.title || b.condition.expression}` : '';
    if (['allUsers', 'allAuthenticatedUsers'].includes(m)) publicBindings.push({ member: m, role: b.role });
    const cur = principals.get(m); principals.set(m, { principal_ref: short(m, 300), type: kind(m), enabled: m.startsWith('deleted:') ? false : null, privileged: Boolean(cur?.privileged || priv) });
    privileges.push({ principal_ref: short(m, 300), privilege: short(`${b.role}${cond}`, 300), scope: short(`projects/${project}`, 500) });
  }
  return { details: { snapshot_id: `gcp-iam:${project}:${p.etag || 'policy'}`, directory: { type: 'gcp-iam', ref: `gcp-iam:${project}` }, connector: { method, read_only: true, credential_ref: credentialRef }, principals: [...principals.values()].slice(0, 5000), memberships: [], privileges: privileges.slice(0, 20000) }, publicBindings };
}

// A role granted to allUsers or allAuthenticatedUsers is public: reported as a derived finding with its evidence (the policy binding).
export function publicBindingFindings(publicBindings, project, etag = null) {
  return publicBindings.map(b => ({ finding_id: `iam-public:${project}:${b.role}:${b.member}`, provider: 'gcp', account_id: project, region: null, product: 'other', title: `Public IAM binding: ${b.member} has ${b.role}`, severity: privilegedGcpRoles.includes(b.role) ? 'critical' : 'high', resource_type: 'cloudresourcemanager.googleapis.com/Project', resource_id: `projects/${project}`, status: 'active', compliance: 'failed', types: ['derived from getIamPolicy', ...(etag ? [`etag ${etag}`] : [])], first_seen: null, updated_at: null }));
}

// gcloud compute firewall-rules list  →  firewall.ruleset rules (lowest priority first, deny before allow at equal priority, implied rules last)
export function vpcFirewallRules(json, network = null) {
  const list = arr(json, 'firewall-rules list').filter(r => !network || String(r.network || '').endsWith(`/${network}`)), rules = [];
  const sorted = [...list].sort((a, b) => (a.priority ?? 1000) - (b.priority ?? 1000) || (a.denied ? 0 : 1) - (b.denied ? 0 : 1));
  for (const r of sorted) { const ingress = (r.direction || 'INGRESS') === 'INGRESS', entries = r.denied || r.allowed || [];
    const ranges = (ingress ? r.sourceRanges : r.destinationRanges) || [], named = [...(r.sourceTags || []).map(t => `tag:${t}`), ...(r.sourceServiceAccounts || []).map(s => `sa:${s}`)];
    const peer = !ranges.length || ranges.some(x => ['0.0.0.0/0', '::/0'].includes(x)) ? ['any'] : ranges.filter(cidrOk);
    const scope = [...(r.targetTags || []).map(t => `target tag ${t}`), ...(r.targetServiceAccounts || []).map(s => `target service account ${s}`)];
    entries.forEach((e, i) => { const proto = String(e.IPProtocol || 'all').toLowerCase(), ports = !e.ports?.length || !['tcp', 'udp', 'sctp'].includes(proto) ? ['any'] : e.ports.map(String);
      rules.push({ rule_id: short(`${r.name}:${i}`, 300), name: short(r.name, 300), position: rules.length + 1, enabled: r.disabled !== true, direction: ingress ? 'in' : 'out', action: r.denied ? 'deny' : 'allow', protocol: proto === 'all' ? 'any' : proto, src: ingress ? (peer.length ? peer : ['any']) : ['any'], dst: ingress ? ['any'] : (peer.length ? peer : ['any']), src_ports: ['any'], dst_ports: ports, application: null, profile: short(String(r.network || '').split('/').pop() || null, 50), last_hit_at: null, hit_count: null, expires_at: null, owner: null, created_at: isoZ(r.creationTimestamp), filters_readable: !(ingress && named.length), scope_constraints: [...scope, ...(named.length ? [`also matches ${named.slice(0, 3).join(', ')} not resolved`] : [])].slice(0, 20).map(x => short(x, 120)) }); });
  }
  rules.push({ rule_id: 'implied-deny-ingress', name: 'implied deny ingress', position: rules.length + 1, enabled: true, direction: 'in', action: 'deny', protocol: 'any', src: ['any'], dst: ['any'], src_ports: ['any'], dst_ports: ['any'], application: null, profile: 'implied', last_hit_at: null, hit_count: null, expires_at: null, owner: null, created_at: null, filters_readable: true, scope_constraints: [] });
  rules.push({ rule_id: 'implied-allow-egress', name: 'implied allow egress', position: rules.length + 1, enabled: true, direction: 'out', action: 'allow', protocol: 'any', src: ['any'], dst: ['any'], src_ports: ['any'], dst_ports: ['any'], application: null, profile: 'implied', last_hit_at: null, hit_count: null, expires_at: null, owner: null, created_at: null, filters_readable: true, scope_constraints: ['implied egress rule'] });
  return { vendor: 'gcp-vpc-firewall', rules: rules.slice(0, 5000), unreadable: rules.filter(r => !r.filters_readable).length };
}

// gcloud compute security-policies describe <policy>  →  firewall.ruleset rules for the backend the policy protects
export function cloudArmorRules(json) {
  const p = obj(json); if (!Array.isArray(p?.rules)) throw new Error('not a Cloud Armor security policy (rules[] missing)');
  const rules = [...p.rules].sort((a, b) => a.priority - b.priority).map((r, i) => { const ips = r.match?.config?.srcIpRanges || [], expr = r.match?.expr?.expression || null, act = String(r.action || '');
    return { rule_id: short(`${p.name}:${r.priority}`, 300), name: short(r.description || `${p.name} priority ${r.priority}`, 300), position: i + 1, enabled: r.preview !== true, direction: 'in', action: act.startsWith('deny') ? 'deny' : 'allow', protocol: 'tcp', src: ips.includes('*') || !ips.length ? ['any'] : ips.filter(cidrOk), dst: ['any'], src_ports: ['any'], dst_ports: ['any'], application: short(expr, 300), profile: short(act === 'throttle' || act === 'rate_based_ban' ? 'rate-limited' : act, 50), last_hit_at: null, hit_count: null, expires_at: null, owner: null, created_at: null, filters_readable: !expr, scope_constraints: [short(`Cloud Armor policy ${p.name}`, 120), ...(r.preview ? ['preview mode: logged, not enforced'] : [])] }; });
  return { vendor: 'gcp-cloud-armor', rules, preview: rules.filter(r => !r.enabled).length, unreadable: rules.filter(r => !r.filters_readable).length };
}

// Cloud Logging output (gcloud logging read --format=json, an export {"entries":[...]}, or JSON lines)  →  one LogEntry per line
export function logEntryLines(input) { const t = String(input).trim(); if (t.startsWith('[')) return JSON.parse(t).slice(0, 5000).map(e => JSON.stringify(e)); if (t.startsWith('{') && t.includes('"entries"')) return (JSON.parse(t).entries || []).slice(0, 5000).map(e => JSON.stringify(e)); return t.split(/\r?\n/).filter(Boolean).slice(0, 5000); }

// Cloud Audit Log methods that disable visibility, widen access or open the network.
export const riskyGcpMethods = ['google.logging.v2.ConfigServiceV2.DeleteSink', 'google.logging.v2.ConfigServiceV2.UpdateSink', 'google.logging.v2.ConfigServiceV2.UpdateCmekSettings', 'SetIamPolicy', 'google.iam.admin.v1.CreateServiceAccountKey', 'google.iam.admin.v1.SetIAMPolicy', 'v1.compute.firewalls.insert', 'v1.compute.firewalls.patch', 'v1.compute.firewalls.update', 'v1.compute.subnetworks.patch', 'v1.compute.securityPolicies.delete', 'v1.compute.securityPolicies.removeRule', 'v1.compute.securityPolicies.patchRule', 'google.cloud.securitycenter.v1.SecurityCenter.UpdateNotificationConfig', 'google.cloud.securitycenter.v1.SecurityCenter.UpdateFinding', 'storage.setIamPermissions'];
