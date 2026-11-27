// CG-171 Blast radius calculator for four change types, from the relationships CyberGuard can see:
//  - stop a service on a host: infrastructure roles the host provides (CG-133 impact graph), its business service and
//    owner (asset context), and the distinct clients seen talking to it in flow logs over seven days;
//  - shut a switch port: the devices learned on the port, its LLDP neighbour and the roles they hold (CG-133);
//  - disable a user account: hosts it signed in to or opened remote sessions on, applications and SaaS services that run
//    as it, and permissions it used, over 30 days;
//  - change a cloud security group: the resources that reference it in the cloud inventory, public exposure and their
//    business services.
// Each result names what it is based on. When no relationship is visible the impact is "unknown" and a person must
// review it; the calculator never reports "no impact" for lack of data.
import { fail, object, text, choice } from './common.js';
import { ImpactGraph } from './impact-graph.js';

export const CHANGES = ['stop-service', 'switch-port-shutdown', 'disable-user', 'security-group-change'];
const parse = s => JSON.parse(s);
const level = n => n === 0 ? 'none' : n <= 5 ? 'limited' : 'broad';

export function blastRadius(store, domain, input, { clock = () => Date.now() } = {}) {
  object(input, ['change_type', 'asset_ref', 'target'], 'blast_radius');
  const change = choice(input.change_type, CHANGES, 'blast_change_type'), target = input.target || {}, since7 = new Date(clock() - 7 * 86400000).toISOString(), since30 = new Date(clock() - 30 * 86400000).toISOString();
  const ig = new ImpactGraph(store, { domain, clock }), ctx = ig.contexts(), basis = [], warnings = [];
  const out = (affected, extra = {}) => { const total = Object.values(affected).reduce((n, v) => n + (Array.isArray(v) ? v.length : 0), 0) + (extra.everyone ? 100 : 0);
    const impact = !basis.length ? 'unknown' : extra.everyone ? 'broad' : level(total);
    if (impact === 'unknown') warnings.push({ en: 'No relationship is visible for this target: the impact is unknown and needs human review.', ar: 'لا تظهر أي علاقة لهذا الهدف: الأثر غير معروف ويحتاج مراجعة بشرية.' });
    return { change_type: change, target, impact, requires_human_review: ['unknown', 'broad'].includes(impact), affected, based_on: basis, warnings, ...extra,
      claim: 'Blast radius from visible relationships only; when none is visible the impact is unknown and a person reviews it.', claim_ar: 'نطاق الأثر من العلاقات الظاهرة فقط؛ وحين لا تظهر علاقة يكون الأثر غير معروف ويراجعه شخص.' }; };
  if (change === 'stop-service' || change === 'switch-port-shutdown') {
    const asset_ref = text(input.asset_ref, 'blast_asset_ref', 200), type = change === 'stop-service' ? 'endpoint.stop-service' : 'network.switch-port-admin-down';
    let r; try { r = ig.assess({ action_type: type, asset_ref, target }); } catch (e) { fail(e.code !== 'impact_target_asset_not_found', 404, 'blast_target_asset_not_found'); throw e; }
    const a = store.get('SELECT addresses FROM assets WHERE external_id=? LIMIT 1', asset_ref), addrs = a ? parse(a.addresses) : [], clients = new Set();
    if (change === 'stop-service' && addrs.length) for (const row of store.all("SELECT payload FROM events WHERE kind='log.batch' AND received_at>=? LIMIT 2000", since7)) for (const rec of parse(row.payload).details.records || []) if (rec.category === 'flow' && addrs.includes(rec.dst_ip) && rec.src_ip && !addrs.includes(rec.src_ip)) clients.add(rec.src_ip);
    if (r.roles.length) basis.push('impact-graph-roles'); if (r.scope?.devices?.length) basis.push('switch-port-map'); if (r.affected.services.length) basis.push('asset-context'); if (clients.size) basis.push('flow-logs-7d');
    for (const role of r.roles) warnings.push({ en: `${r.asset.hostname || asset_ref} provides ${role.role} to ${role.consumers === 'everyone' ? 'everyone' : `${role.consumers} consumers`}`, ar: `${r.asset.hostname || asset_ref} يقدم ${role.role_ar} لـ ${role.consumers === 'everyone' ? 'الجميع' : `${role.consumers} مستفيدين`}` });
    for (const s of r.affected.services) warnings.push({ en: `Business service ${s.business_service} (${s.criticality}) owned by ${s.owner}`, ar: `خدمة الأعمال ${s.business_service} (${s.criticality}) ومالكها ${s.owner}` });
    if (r.core_management !== 'none') warnings.push({ en: `Core network or management path: ${r.core_management}`, ar: `الشبكة الأساسية أو مسار الإدارة: ${r.core_management}` });
    return out({ devices: (r.scope?.devices || []).map(d => d.ref), clients: [...clients].slice(0, 200), services: r.affected.services.map(s => s.business_service) }, { everyone: r.affected.everyone, core_management: r.core_management, impact_graph_decision: r.decision });
  }
  if (change === 'disable-user') {
    const acct = text(target.account, 'blast_account', 300).toLowerCase(), same = v => typeof v === 'string' && (v.toLowerCase() === acct || v.toLowerCase().endsWith(`\\${acct}`) || v.toLowerCase().split('@')[0] === acct);
    const hosts = new Set(), apps = new Set(), perms = new Set(); let signins = 0;
    for (const r of store.all("SELECT kind,payload FROM events WHERE received_at>=? AND kind IN ('identity.signin_activity','remote.authenticated','remote.active','identity.saas_service_inventory','identity.permission_usage')", since30)) { const p = parse(r.payload), d = p.details;
      if (r.kind === 'identity.signin_activity') for (const s of d.signins) { if (same(s.principal_ref)) { signins++; if (s.client_app) apps.add(s.client_app); } }
      else if (r.kind.startsWith('remote.')) { if (same(d.target_b?.account) || same(d.source_a?.account)) hosts.add(d.target_b?.hostname || p.asset.hostname || p.asset.external_id); }
      else if (r.kind === 'identity.saas_service_inventory') { if (same(d.service_identity?.identity_ref)) apps.add(d.application?.name || d.inventory_id); }
      else for (const e of d.entries || []) if (same(e.principal)) perms.add(e.permission); }
    if (signins) basis.push('sign-ins-30d'); if (hosts.size) basis.push('remote-sessions-30d'); if (apps.size) basis.push('applications-and-saas'); if (perms.size) basis.push('permission-usage');
    if (apps.size && !signins) warnings.push({ en: `Applications run as this account (${[...apps].slice(0, 5).join(', ')}): disabling it can stop them`, ar: `تعمل تطبيقات بهذا الحساب (${[...apps].slice(0, 5).join('، ')}): تعطيله قد يوقفها` });
    return out({ hosts: [...hosts], applications: [...apps], permissions: [...perms].slice(0, 100) }, { sign_ins: signins });
  }
  const group = text(target.group_id, 'blast_group_id', 200), resources = [];
  for (const r of store.all("SELECT payload FROM events WHERE kind='cloud.resource_inventory' ORDER BY observed_at DESC LIMIT 20")) for (const x of parse(r.payload).details.resources) if ((x.security_groups || []).includes(group)) resources.push(x);
  const unique = [...new Map(resources.map(x => [x.resource_id, x])).values()]; if (unique.length) basis.push('cloud-inventory-security-groups');
  if (unique.some(x => x.public)) warnings.push({ en: 'Some resources behind this group are public: a rule change can expose or cut them from the internet', ar: 'بعض الموارد خلف هذه المجموعة عامة: تغيير القاعدة قد يكشفها أو يقطعها عن الإنترنت' });
  return out({ resources: unique.map(x => x.resource_id), public_resources: unique.filter(x => x.public).map(x => x.resource_id), services: [...new Set(unique.map(x => ctx.get(x.resource_id)?.business_service).filter(Boolean))] });
}
