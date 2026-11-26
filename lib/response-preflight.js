// CG-117 Response preflight. Before any response action, one read-only report answers: which asset is the target
// (resolved from any mix of IP, MAC, hostname, cloud resource id or asset id, and refused when identifiers disagree or
// match several assets), what the impact is (criticality, business service, protected role, hosts that depend on it,
// network isolation path), whether a connector and a licensed device capability can perform the action, the state of the
// management channel, and the service dependencies. Each check is pass, warn or block; the report never acts.
import { isIP } from 'node:net';
import { fail, text, choice } from './common.js';
import { responseActionCatalog } from './response-actions.js';
import { actionCapability, negotiate } from './capability-negotiation.js';
import { verifyPath, verifyMac } from './port-map.js';

const parse = s => JSON.parse(s);
const normMac = m => String(m).toLowerCase().replace(/[^0-9a-f]/g, '').replace(/(..)(?!$)/g, '$1:');
const DISRUPTIVE = new Set(['endpoint.isolate-device', 'endpoint.shutdown-host', 'endpoint.stop-service', 'endpoint.disable-service', 'network.switch-port-admin-down', 'network.nac-quarantine-endpoint', 'network.block-ip', 'network.block-port']);
const ISOLATION = new Set(['endpoint.isolate-device', 'network.switch-port-admin-down', 'network.nac-quarantine-endpoint']);
const ADMIN_PORTS = new Set([22, 53, 88, 135, 389, 445, 636, 3389, 5985, 5986]);

export class ResponsePreflight {
  constructor(store, { domain, clock }) { Object.assign(this, { s: store, d: domain, clock: clock || (() => Date.now()) }); }
  latest(kind, key) { const m = new Map(); for (const r of this.s.all('SELECT asset_id,observed_at,payload FROM events WHERE kind=? ORDER BY observed_at,received_at', kind)) { const d = parse(r.payload).details; m.set(key(d, r), { ...d, asset_id: r.asset_id, observed_at: r.observed_at }); } return [...m.values()]; }
  resolve(ids) {
    // One device seen by several sources has one row per source; the central identity is its external id.
    const rowsAll = this.s.all("SELECT a.*,s.kind source_kind FROM assets a JOIN sources s ON s.id=a.source_id ORDER BY (s.kind='response-connector'),a.last_seen DESC").map(a => ({ ...a, addresses: parse(a.addresses) })), grouped = new Map();
    for (const a of rowsAll) { const g = grouped.get(a.external_id); if (!g) grouped.set(a.external_id, { ...a, row_ids: [a.id] }); else { g.row_ids.push(a.id); g.addresses = [...new Set([...g.addresses, ...a.addresses])]; } }
    const assets = [...grouped.values()], maps = this.d.portMaps(), by = {}, notes = [];
    if (ids.asset_id) by.asset_id = assets.filter(a => a.row_ids.includes(ids.asset_id));
    if (ids.ip) by.ip = assets.filter(a => a.addresses.includes(ids.ip));
    if (ids.hostname) { const h = ids.hostname.toLowerCase(); by.hostname = assets.filter(a => (a.hostname || '').toLowerCase() === h || (a.hostname || '').toLowerCase().split('.')[0] === h.split('.')[0] || a.external_id.toLowerCase() === h); }
    if (ids.mac) { const m = normMac(ids.mac), ips = [...new Set(maps.flatMap(x => x.arp.filter(a => a.mac === m).map(a => a.ip)))]; by.mac = assets.filter(a => a.addresses.some(ip => ips.includes(ip))); notes.push({ identifier: 'mac', resolved_ips: ips, location: verifyMac(maps, m) }); }
    if (ids.cloud_id) { const res = this.latest('cloud.resource_inventory', (d, r) => r.observed_at).flatMap(i => i.resources.map(x => ({ ...x, provider: i.provider }))).find(x => x.resource_id === ids.cloud_id); by.cloud_id = res ? assets.filter(a => a.external_id === res.resource_id || (res.name && (a.hostname || '').toLowerCase() === res.name.toLowerCase())) : []; notes.push({ identifier: 'cloud_id', resource: res || null }); }
    const sets = Object.entries(by), union = [...new Map(sets.flatMap(([, list]) => list).map(a => [a.id, a])).values()];
    const agree = union.filter(a => sets.every(([, list]) => list.some(x => x.id === a.id)));
    return { by: Object.fromEntries(sets.map(([k, list]) => [k, list.map(a => ({ id: a.id, external_id: a.external_id, hostname: a.hostname, sources: a.row_ids.length }))])), candidates: union, agreed: agree, notes };
  }
  run(input) {
    const ids = {}, raw = input?.identifiers || {};
    for (const k of Object.keys(raw)) fail(['ip', 'mac', 'hostname', 'cloud_id', 'asset_id'].includes(k), 400, `unknown_target_identifier_${k}`);
    if (raw.ip) { ids.ip = text(raw.ip, 'target_ip', 64); fail(isIP(ids.ip), 400, 'invalid_target_ip'); }
    if (raw.mac) { ids.mac = text(raw.mac, 'target_mac', 32); fail(/^([0-9a-f]{2}[:-]?){5}[0-9a-f]{2}$|^([0-9a-f]{4}\.){2}[0-9a-f]{4}$/i.test(ids.mac), 400, 'invalid_target_mac'); }
    if (raw.hostname) ids.hostname = text(raw.hostname, 'target_hostname', 253);
    if (raw.cloud_id) ids.cloud_id = text(raw.cloud_id, 'target_cloud_id', 500);
    if (raw.asset_id) ids.asset_id = text(raw.asset_id, 'target_asset_id', 64);
    fail(Object.keys(ids).length, 400, 'target_identifier_required');
    const type = input.action_type ? choice(input.action_type, Object.keys(responseActionCatalog), 'action_type') : null, spec = type ? responseActionCatalog[type] : null;
    const checks = [], add = (id, state, en, ar, data = undefined) => checks.push({ id, state, detail: en, detail_ar: ar, ...(data === undefined ? {} : { data }) }), now = this.clock();
    // 1. Target identification.
    const r = this.resolve(ids), given = Object.keys(ids);
    if (r.agreed.length === 1) add('target', 'pass', `All ${given.length} identifier(s) resolve to ${r.agreed[0].hostname || r.agreed[0].external_id}`, `كل المعرفات (${given.length}) تشير إلى ${r.agreed[0].hostname || r.agreed[0].external_id}`, r.by);
    else if (r.agreed.length > 1) add('target', 'block', `The identifiers match ${r.agreed.length} assets; add another identifier`, `المعرفات تطابق ${r.agreed.length} أصول؛ أضف معرفًا آخر`, r.by);
    else if (r.candidates.length) { const none = Object.entries(r.by).filter(([, l]) => !l.length).map(([k]) => k); add('target', 'block', none.length ? `Identifier ${none.join(', ')} matches no asset while the others do` : 'The identifiers point to different assets', none.length ? `المعرف ${none.join('، ')} لا يطابق أي أصل بينما تطابق المعرفات الأخرى` : 'المعرفات تشير إلى أصول مختلفة', r.by); }
    else add('target', 'block', 'No asset matches the identifiers', 'لا يوجد أصل يطابق المعرفات', r.by);
    const asset = r.agreed.length === 1 ? r.agreed[0] : null;
    if (!asset) return this.result(ids, type, null, checks, r);
    // 2. Impact.
    const ctx = this.latest('asset.context', (d, row) => row.asset_id).filter(c => asset.row_ids.includes(c.asset_id)).sort((x, y) => y.observed_at.localeCompare(x.observed_at))[0] || null;
    const critical = asset.criticality === 'critical' || ctx?.service_criticality === 'critical';
    add('impact-criticality', critical ? 'warn' : 'pass', `Criticality ${asset.criticality}${ctx ? `, business service ${ctx.business_service} (${ctx.service_criticality}), owner ${ctx.owner.display_name}` : ', no business context recorded'}`, `الأهمية ${asset.criticality}${ctx ? `، الخدمة ${ctx.business_service} (${ctx.service_criticality})، المالك ${ctx.owner.display_name}` : '، لا يوجد سياق أعمال مسجل'}`, ctx ? { owner: ctx.owner, business_service: ctx.business_service, maintenance_windows: ctx.maintenance_windows, data_sensitivity: ctx.data_sensitivity } : null);
    if (!ctx) add('impact-context', 'warn', 'No owner or maintenance window recorded: the business impact is unknown', 'لا يوجد مالك أو نافذة صيانة مسجلة: أثر العمل غير معروف');
    const since = new Date(now - 7 * 86400000).toISOString(), dependents = new Map();
    for (const row of this.s.all("SELECT payload FROM events WHERE kind='log.batch' AND observed_at>=? LIMIT 5000", since)) for (const rec of parse(row.payload).details.records || []) if (rec.dst_ip && asset.addresses.includes(rec.dst_ip) && rec.src_ip && !asset.addresses.includes(rec.src_ip)) { const x = dependents.get(rec.src_ip) || new Set(); if (rec.dst_port) x.add(rec.dst_port); dependents.set(rec.src_ip, x); }
    const infra = [...dependents.values()].some(p => [...p].some(x => [53, 88, 389, 636].includes(x)));
    add('impact-dependents', dependents.size >= 20 || infra ? 'warn' : 'pass', `${dependents.size} other host(s) connected to it in the last 7 days${infra ? ', including DNS or directory traffic' : ''}`, `${dependents.size} جهاز آخر اتصل به خلال 7 أيام${infra ? '، منها حركة DNS أو دليل' : ''}`, { hosts: dependents.size, ports: [...new Set([...dependents.values()].flatMap(p => [...p]))].sort((a, b) => a - b).slice(0, 20) });
    const mgmt = this.d.managementPreflights().filter(m => m.asset_ref === asset.external_id && !m.source_revoked && (!type || m.action_type === type)).sort((a, b) => b.captured_at.localeCompare(a.captured_at))[0] || null;
    const role = mgmt?.protected_role || (asset.device_type === 'domain-controller' ? 'domain-controller' : 'none');
    if (role !== 'none') add('impact-protected-role', type && DISRUPTIVE.has(type) ? 'block' : 'warn', `Protected infrastructure (${role}): device-level disruption is refused`, `بنية محمية (${role}): يُرفض أي تعطيل على مستوى الجهاز`);
    if (type && ISOLATION.has(type)) { const ip = ids.ip || asset.addresses[0], v = ip ? verifyPath({ ip, maps: this.d.portMaps(), asset }) : { safe_to_isolate: false, steps: [] }; add('impact-isolation-path', v.safe_to_isolate ? 'pass' : 'block', v.safe_to_isolate ? `Isolation path verified to ${v.switch_ref} ${v.interface}` : `Isolation path not verified: ${(v.steps.find(s => s.state !== 'verified') || {}).detail || 'no address'}`, v.safe_to_isolate ? `مسار العزل متحقق حتى ${v.switch_ref} ${v.interface}` : `مسار العزل غير متحقق: ${(v.steps.find(s => s.state !== 'verified') || {}).detail_ar || 'لا يوجد عنوان'}`, v.steps); }
    // CG-133 impact graph: roles, people and business services touched, and core / management path impact.
    if (type && this.d.impactGraph) { const g = this.d.impactGraph.assess({ action_type: type, asset_ref: asset.external_id, target: input.target || {} }), svc = g.affected.services.map(x => x.business_service);
      add('impact-graph', g.decision === 'blocked' ? 'block' : g.decision === 'review-required' || g.decision === 'ready-with-impact' ? 'warn' : 'pass', g.decision === 'blocked' ? `Impact on the core network or management path is unknown: ${g.unknown.map(u => u.en).join('; ')}` : `Roles touched: ${g.roles.map(r => r.role).join(', ') || 'none'}; core/management ${g.core_management}; services: ${svc.join(', ') || 'none'}`, g.decision === 'blocked' ? `أثره على الشبكة الأساسية أو مسار الإدارة غير معروف: ${g.unknown.map(u => u.ar).join('؛ ')}` : `الأدوار المتأثرة: ${g.roles.map(r => r.role_ar).join('، ') || 'لا شيء'}؛ الشبكة الأساسية والإدارة: ${({ none: 'لا أثر', affected: 'متأثرة' })[g.core_management]}؛ الخدمات: ${svc.join('، ') || 'لا شيء'}`, g); }
    // 3. Connector and licensed capability.
    if (type) {
      const conns = this.d.responseConnectors().filter(c => !c.source_revoked && c.status === 'active' && c.owner_system === spec.owner && c.capabilities.includes(type) && c.target_asset_refs.includes(asset.external_id));
      add('connector', conns.length ? 'pass' : 'block', conns.length ? `Connector ${conns[0].connector_id} can run ${type} on this asset (tested ${conns[0].tested_at})` : `No active connector can run ${type} on this asset`, conns.length ? `الموصل ${conns[0].connector_id} يستطيع تنفيذ ${type} على هذا الأصل` : `لا يوجد موصل فعال يستطيع تنفيذ ${type} على هذا الأصل`, conns.map(c => c.connector_id));
      const needed = actionCapability[type], probe = needed ? this.d.latestCapabilityProbes().find(p => p.device_ref === asset.external_id) : null;
      if (needed && probe) { const c = negotiate(probe, now).find(x => x.capability === needed); add('capability-license', c.available ? 'pass' : 'block', c.available ? `Device capability ${needed} available (version and licence checked)` : `Device capability ${needed} unavailable: ${c.reasons.join(', ')}`, c.available ? `قدرة الجهاز ${needed} متاحة (تحقق من الإصدار والترخيص)` : `قدرة الجهاز ${needed} غير متاحة: ${c.reasons.join('، ')}`, c); }
      else if (needed) add('capability-license', 'warn', `No capability probe for this device: version and licence for ${needed} are not verified`, `لا يوجد فحص قدرات لهذا الجهاز: الإصدار والترخيص لـ ${needed} غير متحققين`);
      // 4. Management channel.
      if (spec.requires_management_preflight) {
        if (!mgmt) add('management-channel', 'block', 'No management preflight for this action and asset', 'لا يوجد فحص قناة إدارة لهذا الإجراء والأصل');
        else { const age = (now - Date.parse(mgmt.captured_at)) / 60000, state = age > 15 ? 'block' : mgmt.management_channel_impact === 'unknown' ? 'block' : mgmt.management_channel_impact === 'would-cut' && mgmt.alternate_management?.status !== 'ready' ? 'block' : 'pass';
          add('management-channel', state, `Management channel impact ${mgmt.management_channel_impact}${mgmt.management_channel_impact === 'would-cut' ? `, alternate management ${mgmt.alternate_management?.status}` : ''}; preflight ${Math.round(age)} min old${age > 15 ? ' (stale, older than 15 min)' : ''}`, `أثر قناة الإدارة ${mgmt.management_channel_impact}؛ عمر الفحص ${Math.round(age)} دقيقة${age > 15 ? ' (قديم)' : ''}`, { captured_at: mgmt.captured_at, connector_id: mgmt.connector_id }); }
      }
      const src = conns[0] && this.s.get('SELECT name,last_received,stale_seconds,revoked FROM sources WHERE id=?', conns[0].source_id);
      if (src) { const silent = !src.last_received || now - Date.parse(src.last_received) > src.stale_seconds * 1000; add('management-source', silent ? 'warn' : 'pass', silent ? `Connector source ${src.name} has not reported within its interval` : `Connector source ${src.name} is reporting`, silent ? `مصدر الموصل ${src.name} لم يبلغ ضمن مدته` : `مصدر الموصل ${src.name} يبلغ بانتظام`); }
    }
    // 5. Service dependencies.
    const svc = this.d.servicePreflights().filter(p => p.asset_ref === asset.external_id && !p.source_revoked);
    if (svc.length) add('dependencies', svc.some(p => p.dependency_refs?.length) ? 'warn' : 'pass', `${svc.length} service(s) captured; dependent services: ${[...new Set(svc.flatMap(p => p.dependency_refs || []))].join(', ') || 'none'}`, `${svc.length} خدمة مسجلة؛ الخدمات المعتمدة: ${[...new Set(svc.flatMap(p => p.dependency_refs || []))].join('، ') || 'لا شيء'}`, svc.map(p => ({ service_ref: p.service_ref, dependency_refs: p.dependency_refs, recoverable: p.recoverable, captured_at: p.captured_at })));
    else if (type && spec.requires_service_preflight) add('dependencies', 'block', 'No service preflight: dependencies and recovery are unknown', 'لا يوجد فحص خدمة: التبعيات والاسترداد غير معروفة');
    else add('dependencies', 'warn', 'No service dependencies recorded for this asset', 'لا توجد تبعيات خدمات مسجلة لهذا الأصل');
    return this.result(ids, type, asset, checks, r);
  }
  result(ids, type, asset, checks, r) {
    const blocked = checks.filter(c => c.state === 'block');
    return { identifiers: ids, action_type: type, asset: asset ? { id: asset.id, external_id: asset.external_id, hostname: asset.hostname, device_type: asset.device_type, addresses: asset.addresses, criticality: asset.criticality } : null, resolution_notes: r.notes,
      decision: blocked.length ? 'blocked' : checks.some(c => c.state === 'warn') ? 'ready-with-warnings' : 'ready', blocking: blocked.map(c => c.id), checks, checked_at: new Date(this.clock()).toISOString(),
      claim: 'Read-only preflight: target identification across IP, MAC, hostname and cloud id, impact, connector and licensed capability, management channel and dependencies. Nothing is executed; a ready result still needs the governed preview and independent approval.',
      claim_ar: 'فحص مسبق للقراءة فقط: تحديد الهدف عبر IP وMAC واسم الجهاز ومعرف السحابة، والأثر، والموصل والقدرة المرخصة، وقناة الإدارة، والتبعيات. لا يُنفذ شيء؛ والنتيجة الجاهزة تحتاج المعاينة المحكومة وموافقة مستقلة.' };
  }
}
