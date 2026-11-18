// CG-047 Azure and Microsoft Entra read-only converters. Inputs are the documented read outputs of:
//   ARM /subscriptions (az account list), Azure Resource Graph (az graph query), Microsoft Defender for Cloud
//   (pricings, alerts, assessments), Microsoft Sentinel incidents, Microsoft Graph auditLogs/signIns and
//   auditLogs/directoryAudits, Azure Monitor activity log records, VNet flow logs, Azure Firewall structured logs,
//   network security groups and Azure Firewall policy rule collection groups. Nothing here writes to Azure.
import { isIP } from 'node:net';

export const azureServices = ['resource-graph', 'entra-logs', 'defender-for-cloud', 'sentinel', 'azure-monitor', 'vnet-flow-logs', 'azure-firewall', 'nsg', 'network-watcher'];
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const short = (v, max = 300) => (v === null || v === undefined || v === '' ? null : String(v).replace(/[\x00-\x1f\x7f]/g, ' ').trim().slice(0, max) || null);
const isoZ = v => { const t = Date.parse(v); return Number.isFinite(t) ? new Date(t).toISOString() : null; };
const obj = v => (typeof v === 'string' ? JSON.parse(v) : v);
const list = (v, name) => { const x = obj(v), l = Array.isArray(x) ? x : Array.isArray(x?.value) ? x.value : Array.isArray(x?.data) ? x.data : null; if (!l) throw new Error(`not a ${name} response (value[] or data[] missing)`); return l.slice(0, 20000); };
export const subscriptionOf = id => { const m = String(id || '').match(/\/subscriptions\/([0-9a-f-]{36})/i); return m && GUID.test(m[1]) ? m[1].toLowerCase() : null; };
const sev = v => ({ high: 'high', medium: 'medium', low: 'low', informational: 'info', critical: 'critical' })[String(v || '').toLowerCase()] || 'info';

// az account list  /  GET /subscriptions
export function subscriptions(json) {
  return list(json, 'subscriptions').map(s => ({ account_id: String(s.subscriptionId || s.id || '').replace(/^\/subscriptions\//, '').toLowerCase(), name: short(s.displayName || s.name, 200), status: { enabled: 'active', warned: 'active', pastdue: 'active', disabled: 'suspended', deleted: 'pending-closure' }[String(s.state || '').toLowerCase()] || 'unknown', access: 'not-attempted' })).filter(s => GUID.test(s.account_id));
}

// Service state from what the read calls actually returned. Missing inputs leave the service "not-checked".
// graph: Resource Graph rows (id, type, location, subscriptionId, properties.targetResourceId for flow logs)
// pricings: { <subscription>: az security pricing list }   diagnostics: { <subscription>: az monitor diagnostic-settings subscription list }
// sentinel: { <subscription>: [workspace ids with Microsoft Sentinel onboarded] }   entra: 'enabled' | 'access-denied' | undefined
export function azureServiceStatus({ accounts, graph = null, pricings = {}, diagnostics = {}, sentinel = {}, entra }) {
  const rows = [], type = r => String(r.type || '').toLowerCase();
  // Only subscriptions CyberGuard could actually read get service rows; refused or inactive ones become a single gap.
  for (const a of accounts.filter(x => x.status === 'active' && ['assumed', 'management'].includes(x.access))) {
    const res = graph ? graph.filter(r => (r.subscriptionId || subscriptionOf(r.id)) === a.account_id) : null, add = (service, status, detail = null, region = null) => rows.push({ account_id: a.account_id, region, service, status, detail: short(detail, 300) });
    if (!res) { for (const s of ['resource-graph', 'vnet-flow-logs', 'azure-firewall', 'nsg', 'network-watcher']) add(s, 'not-checked'); }
    else {
      add('resource-graph', 'enabled', `${res.length} resource(s)`);
      const flows = res.filter(r => type(r) === 'microsoft.network/networkwatchers/flowlogs'), vnetFlows = flows.filter(r => /\/virtualnetworks\//i.test(r.properties?.targetResourceId || '')), nsgFlows = flows.filter(r => /\/networksecuritygroups\//i.test(r.properties?.targetResourceId || ''));
      add('vnet-flow-logs', vnetFlows.length ? 'enabled' : 'disabled', vnetFlows.length ? `${vnetFlows.length} VNet flow log(s)` : nsgFlows.length ? `only ${nsgFlows.length} NSG flow log(s), retiring 2027-09-30` : 'no flow logs');
      const fw = res.filter(r => type(r) === 'microsoft.network/azurefirewalls'); add('azure-firewall', fw.length ? 'enabled' : 'disabled', fw.length ? `${fw.length} firewall(s)` : 'no Azure Firewall deployed');
      const nsg = res.filter(r => type(r) === 'microsoft.network/networksecuritygroups'), asg = res.filter(r => type(r) === 'microsoft.network/applicationsecuritygroups'); add('nsg', nsg.length ? 'enabled' : 'disabled', `${nsg.length} NSG(s), ${asg.length} ASG(s)`);
      const vnetRegions = [...new Set(res.filter(r => type(r) === 'microsoft.network/virtualnetworks').map(r => String(r.location).toLowerCase()))], watchers = new Set(res.filter(r => type(r) === 'microsoft.network/networkwatchers').map(r => String(r.location).toLowerCase()));
      if (!vnetRegions.length) add('network-watcher', 'not-available', 'no virtual networks');
      for (const region of vnetRegions) add('network-watcher', watchers.has(region) ? 'enabled' : 'disabled', watchers.has(region) ? 'Network Watcher present' : 'virtual networks without Network Watcher', region);
    }
    const p = pricings[a.account_id];
    if (p === 'access-denied') add('defender-for-cloud', 'access-denied');
    else if (p) { const plans = list(p, 'pricings'), on = plans.filter(x => (x.properties?.pricingTier || x.pricingTier) === 'Standard').map(x => x.name); add('defender-for-cloud', on.length ? 'enabled' : 'disabled', on.length ? `plans: ${on.slice(0, 12).join(', ')}` : 'all plans Free'); }
    else add('defender-for-cloud', 'not-checked');
    const dg = diagnostics[a.account_id];
    if (dg === 'access-denied') add('azure-monitor', 'access-denied');
    else if (dg) { const s = list(dg, 'diagnostic settings'), exp = s.filter(x => (x.properties?.logs || x.logs || []).some(l => l.enabled)); add('azure-monitor', exp.length ? 'enabled' : 'disabled', exp.length ? `activity log exported by ${exp.length} setting(s)` : 'activity log not exported'); }
    else add('azure-monitor', 'not-checked');
    const sw = sentinel[a.account_id]; add('sentinel', sw === 'access-denied' ? 'access-denied' : Array.isArray(sw) ? (sw.length ? 'enabled' : 'disabled') : 'not-checked', Array.isArray(sw) ? `${sw.length} workspace(s)` : null);
    add('entra-logs', entra === 'enabled' ? 'enabled' : entra === 'access-denied' ? 'access-denied' : 'not-checked', entra === 'enabled' ? 'Graph auditLogs readable (tenant level)' : null);
  }
  return rows;
}

// Defender for Cloud security alerts: GET .../providers/Microsoft.Security/alerts
export function defenderAlerts(json) {
  return list(json, 'Defender for Cloud alerts').map(a => { const p = a.properties || a; return { finding_id: short(a.id || a.name, 300), provider: 'azure', account_id: subscriptionOf(a.id) || subscriptionOf(p.resourceIdentifiers?.[0]?.azureResourceId), region: short(p.location || a.location || null, 40), product: 'defender-for-cloud', title: short(p.alertDisplayName || p.alertType, 300) || 'Defender alert', severity: sev(p.severity), resource_type: short((r => (r ? String(r).split('/providers/').pop().split('/').slice(0, 2).join('/') : null))(p.resourceIdentifiers?.find(x => x.azureResourceId)?.azureResourceId), 200), resource_id: short(p.compromisedEntity || p.resourceIdentifiers?.[0]?.azureResourceId, 500), status: ({ active: 'active', inprogress: 'active', resolved: 'resolved', dismissed: 'suppressed' })[String(p.status || 'Active').toLowerCase()] || 'active', compliance: null, types: [short(p.alertType, 200)].filter(Boolean), first_seen: isoZ(p.startTimeUtc || p.timeGeneratedUtc), updated_at: isoZ(p.timeGeneratedUtc || p.endTimeUtc) }; }).filter(f => f.finding_id && f.account_id);
}

// Defender for Cloud assessments (recommendations) from Resource Graph "securityresources" or the assessments API.
export function defenderAssessments(json) {
  return list(json, 'Defender for Cloud assessments').map(a => { const p = a.properties || {}, code = String(p.status?.code || '').toLowerCase(), rid = p.resourceDetails?.Id || p.resourceDetails?.id || a.id; return { finding_id: short(a.id, 300), provider: 'azure', account_id: subscriptionOf(a.id) || subscriptionOf(rid), region: null, product: 'defender-for-cloud', title: short(p.displayName, 300) || 'Recommendation', severity: sev(p.metadata?.severity), resource_type: short(String(rid || '').split('/providers/').pop()?.split('/').slice(0, 2).join('/') || null, 200), resource_id: short(rid, 500), status: code === 'unhealthy' ? 'active' : 'resolved', compliance: code === 'unhealthy' ? 'failed' : code === 'healthy' ? 'passed' : 'not-available', types: ['recommendation'], first_seen: isoZ(p.status?.firstEvaluationDate), updated_at: isoZ(p.status?.statusChangeDate) }; }).filter(f => f.finding_id && f.account_id);
}

// Microsoft Sentinel incidents: GET .../workspaces/{ws}/providers/Microsoft.SecurityInsights/incidents
export function sentinelIncidents(json) {
  return list(json, 'Sentinel incidents').map(i => { const p = i.properties || {}; return { finding_id: short(i.id, 300), provider: 'azure', account_id: subscriptionOf(i.id), region: null, product: 'sentinel', title: short(`#${p.incidentNumber ?? ''} ${p.title || ''}`.trim(), 300) || 'Sentinel incident', severity: sev(p.severity), resource_type: 'Microsoft.SecurityInsights/incidents', resource_id: short(String(i.id).split('/providers/Microsoft.SecurityInsights')[0], 500), status: String(p.status || 'New').toLowerCase() === 'closed' ? 'resolved' : 'active', compliance: null, types: (p.additionalData?.tactics || []).slice(0, 10).map(t => short(t, 200)), first_seen: isoZ(p.firstActivityTimeUtc || p.createdTimeUtc), updated_at: isoZ(p.lastModifiedTimeUtc) }; }).filter(f => f.finding_id && f.account_id);
}

// Microsoft Graph GET /auditLogs/signIns  →  identity.signin_activity details
export function entraSignins(json, directoryRef) {
  const rows = list(json, 'Graph signIns'), signins = rows.map(s => { const at = isoZ(s.createdDateTime), ok = Number(s.status?.errorCode) === 0, ip = s.ipAddress && isIP(s.ipAddress) ? s.ipAddress : null, req = String(s.authenticationRequirement || '').toLowerCase(), mfaFail = (s.authenticationDetails || []).some(d => d.authenticationStepRequirement?.toLowerCase?.().includes('multifactor') && d.succeeded === false);
    return at && { signin_id: short(s.id, 200), principal_ref: short(s.userPrincipalName || s.userId, 300), at: at.replace(/\.\d{3}Z$/, '.000Z'), result: ok ? 'success' : 'failure', failure_reason: ok ? null : short(s.status?.failureReason || `error ${s.status?.errorCode}`, 200), source_ip: ip, country: short(s.location?.countryOrRegion, 10), client_app: short(s.clientAppUsed || s.appDisplayName, 200), mfa: mfaFail ? 'failed' : req === 'multifactorauthentication' ? (ok ? 'satisfied' : 'unknown') : req === 'singlefactorauthentication' ? 'not-required' : 'unknown' }; }).filter(Boolean).filter(s => s.signin_id && s.principal_ref);
  if (!signins.length) throw new Error('no usable sign-in records');
  const times = signins.map(s => s.at).sort();
  return { batch_id: `entra-signins:${times[0]}:${signins.length}`, directory_ref: directoryRef, window: { starts_at: times[0], ends_at: times[times.length - 1] }, signins };
}

// Microsoft Graph GET /auditLogs/directoryAudits  →  identity.idp_change details for identity-provider settings only.
const auditSetting = a => { const t = `${a.activityDisplayName || ''} ${(a.targetResources || []).map(r => r.displayName || '').join(' ')}`.toLowerCase();
  return /conditional access/.test(t) ? 'conditional-access' : /federat/.test(t) ? 'federation' : /authentication method|mfa|multi-factor/.test(t) ? 'mfa-policy' : /password policy|password protection/.test(t) ? 'password-policy' : /token lifetime/.test(t) ? 'token-lifetime' : /identity provider|external identit/.test(t) ? 'identity-provider' : /certificate/.test(t) && /sso|saml|single sign/.test(t) ? 'sso-certificate' : null; };
export function entraDirectoryAudits(json, directoryRef) {
  const changes = [], skipped = []; for (const a of list(json, 'Graph directoryAudits')) {
    const setting = auditSetting(a), at = isoZ(a.activityDateTime); if (!setting || !at || a.result === 'failure') { skipped.push(a.id); continue; }
    const verb = String(a.activityDisplayName || '').toLowerCase(), mods = (a.targetResources || []).flatMap(r => r.modifiedProperties || []);
    const vals = k => short(mods.map(m => `${m.displayName}: ${m[k] ?? ''}`).join('; ').replace(/"/g, ''), 500);
    changes.push({ change_id: short(a.id, 200), directory_ref: directoryRef, setting, action: /^(add|create)/.test(verb) ? 'created' : /^delete|^remove/.test(verb) ? 'deleted' : /disable/.test(verb) ? 'disabled' : /enable/.test(verb) ? 'enabled' : 'modified', actor_ref: short(a.initiatedBy?.user?.userPrincipalName || a.initiatedBy?.app?.displayName || 'unknown', 300), at: at.replace(/\.\d{3}Z$/, '.000Z'), authorization_ref: null, before_summary: vals('oldValue'), after_summary: vals('newValue') });
  }
  return { changes, skipped: skipped.length };
}

// az network nsg show (or list)  →  firewall.ruleset rules, priority order, default rules included
const nsgAddr = (single, plural, groups) => { const vals = [...(plural?.length ? plural : [single])].filter(v => v !== undefined && v !== null && v !== ''), named = [...vals.filter(v => !['*', 'Internet', '0.0.0.0/0', 'Any'].includes(v) && isIP(String(v).split('/')[0]) === 0), ...(groups || []).map(g => `asg:${String(g.id || '').split('/').pop()}`)];
  return { values: vals.some(v => ['*', 'Internet', '0.0.0.0/0', 'Any'].includes(v)) ? ['any'] : vals.filter(v => isIP(String(v).split('/')[0]) !== 0).length ? vals.filter(v => isIP(String(v).split('/')[0]) !== 0) : ['any'], readable: !named.length, named }; };
const nsgPorts = (single, plural) => { const v = (plural?.length ? plural : [single]).filter(Boolean).map(String); return v.includes('*') || !v.length ? ['any'] : v; };
export function nsgRules(json) {
  const x = obj(json), groups = Array.isArray(x) ? x : x?.value ? x.value : [x]; if (!groups.every(g => g && (g.securityRules || g.properties?.securityRules))) throw new Error('not an NSG response (securityRules missing)');
  const rules = [];
  for (const g of groups.slice(0, 500)) { const props = g.properties || g, all = [...(props.securityRules || []), ...(props.defaultSecurityRules || [])].map(r => ({ ...r, ...(r.properties || {}) })).sort((a, b) => (a.direction || '').localeCompare(b.direction || '') || a.priority - b.priority);
    for (const r of all) { const src = nsgAddr(r.sourceAddressPrefix, r.sourceAddressPrefixes, r.sourceApplicationSecurityGroups), dst = nsgAddr(r.destinationAddressPrefix, r.destinationAddressPrefixes, r.destinationApplicationSecurityGroups);
      rules.push({ rule_id: short(`${g.name}:${r.name}`, 300), name: short(`${g.name} ${r.name}`, 300), position: r.priority, enabled: true, direction: String(r.direction).toLowerCase() === 'outbound' ? 'out' : 'in', action: String(r.access).toLowerCase() === 'deny' ? 'deny' : 'allow', protocol: r.protocol === '*' ? 'any' : String(r.protocol || 'any').toLowerCase(), src: src.values, dst: dst.values, src_ports: nsgPorts(r.sourcePortRange, r.sourcePortRanges), dst_ports: nsgPorts(r.destinationPortRange, r.destinationPortRanges), application: null, profile: short(g.location, 50), last_hit_at: null, hit_count: null, expires_at: null, owner: null, created_at: null, filters_readable: src.readable && dst.readable, scope_constraints: [short(`nsg ${g.name}`, 120), ...[...src.named, ...dst.named].slice(0, 5).map(n => short(`${n} not resolved`, 120))] }); } }
  const seen = new Set(); rules.forEach(r => { while (seen.has(`${r.direction}:${r.position}`)) r.position += 100000; seen.add(`${r.direction}:${r.position}`); });
  return { vendor: 'azure-nsg', rules: rules.slice(0, 5000), unreadable: rules.filter(r => !r.filters_readable).length };
}

// az network firewall policy rule-collection-group list  →  firewall.ruleset rules in processing order (DNAT, network, application)
export function azureFirewallPolicyRules(json) {
  const groups = list(json, 'rule collection groups').map(g => ({ ...g, ...(g.properties || {}) })).sort((a, b) => a.priority - b.priority), rules = [];
  const kind = c => ({ FirewallPolicyNatRuleCollection: 0, FirewallPolicyFilterRuleCollection: 1 })[c.ruleCollectionType] ?? 1;
  for (const g of groups) for (const c of [...(g.ruleCollections || [])].sort((a, b) => a.priority - b.priority)) for (const r of c.rules || []) {
    const network = r.ruleType === 'NetworkRule', app = r.ruleType === 'ApplicationRule', srcNamed = (r.sourceIpGroups || []).length > 0, dstNamed = (r.destinationIpGroups || []).length > 0 || (r.destinationFqdns || []).length > 0 || (network && (r.destinationAddresses || []).some(a => isIP(String(a).split('/')[0]) === 0 && a !== '*'));
    const addr = (l, named) => (!l?.length || l.includes('*') ? ['any'] : l.filter(a => isIP(String(a).split('/')[0]) !== 0).length ? l.filter(a => isIP(String(a).split('/')[0]) !== 0) : ['any']);
    const protos = network ? (r.ipProtocols || []).map(p => String(p).toLowerCase()) : app ? (r.protocols || []).map(p => String(p.protocolType).toLowerCase()) : (r.ipProtocols || []).map(p => String(p).toLowerCase());
    rules.push({ rule_id: short(`${g.name}/${c.name}/${r.name}`, 300), name: short(`${c.name} ${r.name}`, 300), position: rules.length + 1, enabled: true, direction: 'in', action: c.ruleCollectionType === 'FirewallPolicyNatRuleCollection' ? 'allow' : String(c.action?.type).toLowerCase() === 'deny' ? 'deny' : 'allow', protocol: protos.length === 1 && ['tcp', 'udp', 'icmp'].includes(protos[0]) ? protos[0] : 'any', src: addr(r.sourceAddresses, srcNamed), dst: app ? ['any'] : addr(r.destinationAddresses, dstNamed), src_ports: ['any'], dst_ports: app ? (r.protocols || []).map(p => String(p.port)).filter(p => /^\d+$/.test(p)).length ? (r.protocols || []).map(p => String(p.port)) : ['any'] : (r.destinationPorts || []).includes('*') || !(r.destinationPorts || []).length ? ['any'] : r.destinationPorts.map(String), application: app ? short([...(r.targetFqdns || []), ...(r.fqdnTags || [])].join(','), 300) : null, profile: short(kind(c) === 0 ? 'dnat' : app ? 'application' : 'network', 50), last_hit_at: null, hit_count: null, expires_at: null, owner: null, created_at: null, filters_readable: !srcNamed && !(dstNamed && !app), scope_constraints: [] });
  }
  return { vendor: 'azure-firewall', rules: rules.slice(0, 5000), unreadable: rules.filter(r => !r.filters_readable).length };
}

// VNet flow log blob {"records":[...]}  →  one JSON line per flow tuple for the azure-vnet-flow-json format
export function vnetFlowLines(json) {
  const v = obj(json); if (!Array.isArray(v?.records)) throw new Error('not a VNet flow log file (records[] missing)');
  const out = []; for (const rec of v.records) for (const f of rec.flowRecords?.flows || []) for (const g of f.flowGroups || []) for (const t of g.flowTuples || []) out.push(JSON.stringify({ target: rec.targetResourceID || null, acl: f.aclID || null, rule: g.rule || null, tuple: t }));
  return out.slice(0, 5000);
}

// Azure Monitor activity log operations that disable visibility, open the network or widen access.
export const riskyAzureOperations = ['microsoft.insights/diagnosticsettings/delete', 'microsoft.network/networkwatchers/flowlogs/delete', 'microsoft.security/pricings/write', 'microsoft.securityinsights/dataconnectors/delete', 'microsoft.operationalinsights/workspaces/delete', 'microsoft.network/networksecuritygroups/securityrules/write', 'microsoft.network/firewallpolicies/rulecollectiongroups/write', 'microsoft.authorization/roleassignments/write', 'microsoft.authorization/roledefinitions/write', 'microsoft.keyvault/vaults/accesspolicies/write'];
