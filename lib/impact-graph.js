// CG-133 Network change impact graph. Every response action is mapped, before it runs, to the infrastructure roles it
// touches (DNS, directory, DHCP, storage, VoIP, hypervisor, management, core, shared uplink) and to the people and business
// services that depend on them. Roles come from owner declarations and from evidence (directory controllers, traffic to
// well-known service ports, switch port maps with LLDP neighbours, voice VLANs and uplinks), and each says which. A
// disruptive change whose effect on the core network or the management path cannot be determined is refused.
import { randomUUID } from 'node:crypto';
import { fail, text, choice } from './common.js';
import { responseActionCatalog } from './response-actions.js';

const parse = s => JSON.parse(s);
export const ROLES = ['dns', 'ad', 'dhcp', 'storage', 'voip', 'hypervisor', 'management', 'core', 'shared-uplink'];
export const ROLE_AR = { dns: 'DNS', ad: 'الدليل (AD)', dhcp: 'DHCP', storage: 'التخزين', voip: 'الاتصال الصوتي', hypervisor: 'المضيف الافتراضي', management: 'مسار الإدارة', core: 'الشبكة الأساسية', 'shared-uplink': 'وصلة صاعدة مشتركة' };
const SERVICE_PORTS = { 53: 'dns', 88: 'ad', 389: 'ad', 636: 'ad', 3268: 'ad', 67: 'dhcp', 445: 'storage', 2049: 'storage', 3260: 'storage', 5060: 'voip', 5061: 'voip' };
export const DISRUPTIVE = new Set(['endpoint.isolate-device', 'endpoint.shutdown-host', 'endpoint.stop-service', 'endpoint.disable-service', 'network.switch-port-admin-down', 'network.nac-quarantine-endpoint', 'network.block-ip', 'network.block-port']);
const NETWORK_DEVICES = new Set(['switch', 'router', 'firewall']);
const mac = m => String(m || '').toLowerCase().replace(/[^0-9a-f]/g, '').replace(/(..)(?!$)/g, '$1:');
const iface = s => String(s || '').replace(/^GigabitEthernet/i, 'Gi').replace(/^TenGigabitEthernet/i, 'Te').replace(/^FastEthernet/i, 'Fa');

export class ImpactGraph {
  constructor(store, { domain, clock }) { Object.assign(this, { s: store, d: domain, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  declare(actor, input) {
    const asset_ref = text(input?.asset_ref, 'impact_asset_ref', 200), role = choice(input?.role, ROLES, 'impact_role');
    const raw = input.consumers === undefined ? ['*'] : input.consumers; fail(Array.isArray(raw) && raw.length >= 1 && raw.length <= 500, 400, 'invalid_impact_consumers');
    const consumers = [...new Set(raw.map(c => text(c, 'impact_consumer', 200)))], note = text(input.note, 'impact_note', 500, true) || null, id = randomUUID(), at = this.now();
    this.s.transaction(() => { this.s.run('DELETE FROM impact_roles WHERE asset_ref=? AND role=?', asset_ref, role); this.s.run('INSERT INTO impact_roles(id,asset_ref,role,consumers_json,note,declared_by,declared_at) VALUES (?,?,?,?,?,?,?)', id, asset_ref, role, JSON.stringify(consumers), note, actor, at); this.s.audit(actor, 'impact_graph.role_declared', id, { asset_ref, role, consumers: consumers.length }, at); });
    return { id, asset_ref, role, consumers, note, declared_by: actor, declared_at: at };
  }
  remove(actor, id) { const r = this.s.get('SELECT * FROM impact_roles WHERE id=?', id); fail(r, 404, 'impact_role_not_found'); this.s.transaction(() => { this.s.run('DELETE FROM impact_roles WHERE id=?', id); this.s.audit(actor, 'impact_graph.role_removed', id, { asset_ref: r.asset_ref, role: r.role }, this.now()); }); return { removed: id }; }
  assets() {
    const g = new Map();
    for (const a of this.s.all('SELECT id,external_id,hostname,device_type,addresses,criticality FROM assets ORDER BY last_seen DESC')) { const x = g.get(a.external_id); if (!x) g.set(a.external_id, { ...a, addresses: parse(a.addresses), row_ids: [a.id] }); else { x.row_ids.push(a.id); x.addresses = [...new Set([...x.addresses, ...parse(a.addresses)])]; } }
    return [...g.values()];
  }
  contexts() {
    const m = new Map();
    for (const r of this.s.all("SELECT a.external_id,e.payload FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind='asset.context' ORDER BY e.observed_at,e.received_at")) { const d = parse(r.payload).details; m.set(r.external_id, { business_service: d.business_service, service_criticality: d.service_criticality, owner: d.owner.display_name, site: d.site }); }
    return m;
  }
  // Providers: who holds which role, for whom, and on what basis.
  providers() {
    const assets = this.assets(), byIp = new Map(assets.flatMap(a => a.addresses.map(ip => [ip, a]))), out = [], push = p => { if (!out.some(x => x.provider === p.provider && x.role === p.role && x.basis === p.basis)) out.push(p); };
    for (const r of this.s.all('SELECT * FROM impact_roles ORDER BY declared_at')) push({ id: r.id, provider: r.asset_ref, role: r.role, consumers: parse(r.consumers_json), basis: 'declared', note: r.note, declared_by: r.declared_by, declared_at: r.declared_at });
    for (const a of assets.filter(a => a.device_type === 'domain-controller')) for (const role of ['ad', 'dns']) push({ provider: a.external_id, role, consumers: ['*'], basis: 'device-type' });
    const since = new Date(this.clock() - 7 * 86400000).toISOString(), traffic = new Map();
    for (const row of this.s.all("SELECT payload FROM events WHERE kind='log.batch' AND observed_at>=? LIMIT 5000", since)) for (const rec of parse(row.payload).details.records || []) {
      const role = SERVICE_PORTS[rec.dst_port], dst = rec.dst_ip && byIp.get(rec.dst_ip); if (!role || !dst || !rec.src_ip) continue;
      const k = `${dst.external_id}|${role}`, set = traffic.get(k) || new Set(); set.add(byIp.get(rec.src_ip)?.external_id || rec.src_ip); traffic.set(k, set);
    }
    for (const [k, set] of traffic) { const [provider, role] = k.split('|'); set.delete(provider); if (set.size) push({ provider, role, consumers: [...set], basis: 'traffic' }); }
    for (const m of this.d.portMaps()) for (const sp of m.switchports) {
      const port = `${m.switch_ref}:${sp.interface}`, on = this.onPort(m, sp.interface, byIp), n = m.lldp.find(x => x.interface === sp.interface);
      if (n?.hypervisor) push({ provider: port, role: 'hypervisor', consumers: on.map(x => x.ref), basis: 'lldp', neighbour: n.system_name });
      else if (sp.mode === 'trunk' || n?.capabilities.some(c => ['B', 'R', 'Bridge', 'Router'].includes(c))) push({ provider: port, role: 'shared-uplink', consumers: on.map(x => x.ref), basis: 'port-map', neighbour: n?.system_name || null });
      if (sp.voice_vlan) { const phones = m.mac_table.filter(e => e.interface === sp.interface && e.vlan === sp.voice_vlan).map(e => e.mac); if (phones.length) push({ provider: port, role: 'voip', consumers: phones, basis: 'voice-vlan' }); }
    }
    return out;
  }
  onPort(m, name, byIp) { return [...new Set(m.mac_table.filter(e => e.interface === name).map(e => e.mac))].map(x => { const ip = m.arp.find(a => a.mac === x)?.ip, a = ip && byIp.get(ip); return { mac: x, ip: ip || null, ref: a?.external_id || ip || x }; }); }
  // Read-only assessment of one proposed action.
  assess(input) {
    const type = choice(input?.action_type, Object.keys(responseActionCatalog), 'action_type'), spec = responseActionCatalog[type], target = input.target || {};
    const assets = this.assets(), byIp = new Map(assets.flatMap(a => a.addresses.map(ip => [ip, a]))), providers = this.providers(), ctx = this.contexts();
    const asset = input.asset_ref ? assets.find(a => a.external_id === input.asset_ref) : input.asset_id ? assets.find(a => a.row_ids.includes(input.asset_id)) : null;
    fail(asset, 404, 'impact_target_asset_not_found');
    const declared = providers.filter(p => p.basis === 'declared'), coreMgmt = declared.filter(p => ['core', 'management'].includes(p.role)), notes = [];
    const isCoreMgmt = ref => coreMgmt.filter(p => p.provider === ref || assets.find(a => a.external_id === p.provider)?.hostname?.toLowerCase() === String(ref).toLowerCase());
    let touched = [], scope = null, unknown = [], affectedCore = [];
    const holdsOf = ref => providers.filter(p => p.provider === ref);
    if (type === 'network.switch-port-admin-down' || type === 'network.nac-quarantine-endpoint') {
      const maps = this.d.portMaps(); let m = null, name = null;
      if (type === 'network.switch-port-admin-down') { m = maps.find(x => x.switch_ref === asset.external_id); name = iface(target.interface_ref); }
      else { const t = mac(target.mac); for (const x of maps) { const e = x.mac_table.find(e => e.mac === t && !/^(Po|Vl|CPU)/i.test(e.interface)); if (e) { m = x; name = e.interface; break; } } }
      const sp = m?.switchports.find(s => s.interface === name);
      if (!sp) unknown.push({ en: `Port ${name || target.mac || '?'} is not in any switch port map: what it carries is unknown`, ar: `المنفذ ${name || target.mac || '?'} غير موجود في خرائط المنافذ: لا يُعرف ما يحمله` });
      else {
        const port = `${m.switch_ref}:${name}`, n = m.lldp.find(x => x.interface === name), on = this.onPort(m, name, byIp);
        scope = { port, mode: sp.mode, neighbour: n?.system_name || null, devices: on };
        touched = holdsOf(port);
        const uplink = touched.find(p => p.role === 'shared-uplink');
        if (uplink) { const hit = n?.system_name ? isCoreMgmt(n.system_name) : []; if (hit.length) affectedCore.push(...hit.map(p => ({ ...p, via: port }))); else unknown.push({ en: `${port} is an uplink to ${n?.system_name || 'an unidentified neighbour'} whose role is not declared`, ar: `${port} وصلة صاعدة إلى ${n?.system_name || 'جار غير معروف'} ودوره غير مصرح به` }); }
        for (const d of on) { const a = assets.find(x => x.external_id === d.ref); if (a) touched.push(...holdsOf(a.external_id)); }
      }
    } else if (spec.target === 'ip' || spec.target === 'network-port') {
      const victim = spec.target === 'ip' ? byIp.get(target.ip) || null : asset;
      scope = spec.target === 'ip' ? { ip: target.ip, resolves_to: victim?.external_id || null, enforced_on: asset.external_id } : { port: target.port, protocol: target.protocol, direction: target.direction, enforced_on: asset.external_id };
      const role = spec.target === 'network-port' ? SERVICE_PORTS[target.port] : null;
      if (victim) touched = holdsOf(victim.external_id).filter(p => !role || p.role === role || ['core', 'management'].includes(p.role));
      if (!coreMgmt.length) unknown.push({ en: 'No core network or management path is declared, so the effect of a network block on them cannot be determined', ar: 'لم تُعرَّف الشبكة الأساسية ولا مسار الإدارة، فلا يمكن تحديد أثر الحظر الشبكي عليهما' });
      else { const hit = victim ? isCoreMgmt(victim.external_id) : []; affectedCore.push(...hit); }
    } else {
      touched = holdsOf(asset.external_id); scope = { asset: asset.external_id };
      if (NETWORK_DEVICES.has(asset.device_type) && !isCoreMgmt(asset.external_id).length && !declared.some(p => p.provider === asset.external_id)) unknown.push({ en: `${asset.hostname || asset.external_id} is a ${asset.device_type} with no declared role`, ar: `${asset.hostname || asset.external_id} جهاز شبكي (${asset.device_type}) دون دور مصرح به` });
    }
    if (!['network.switch-port-admin-down', 'network.nac-quarantine-endpoint'].includes(type) && !(spec.target === 'ip' || spec.target === 'network-port')) affectedCore.push(...isCoreMgmt(asset.external_id));
    affectedCore.push(...touched.filter(p => ['core', 'management'].includes(p.role)));
    const roles = [...new Map(touched.map(p => [`${p.provider}|${p.role}|${p.basis}`, p])).values()];
    const everyone = roles.some(p => p.consumers.includes('*')), consumers = [...new Set(roles.flatMap(p => p.consumers).filter(c => c !== '*'))];
    const services = new Map(); for (const ref of [scope?.resolves_to || asset.external_id, ...consumers, ...(scope?.devices || []).map(d => d.ref)].filter(Boolean)) { const c = ctx.get(ref); if (c) services.set(c.business_service, { business_service: c.business_service, criticality: c.service_criticality, owner: c.owner, via: [...(services.get(c.business_service)?.via || []), ref] }); }
    const core_management = unknown.length ? 'unknown' : affectedCore.length ? 'affected' : 'none';
    const disruptive = DISRUPTIVE.has(type), decision = !disruptive ? 'not-disruptive' : core_management === 'unknown' ? 'blocked' : core_management === 'affected' ? 'review-required' : roles.length || services.size ? 'ready-with-impact' : 'ready';
    return { action_type: type, asset: { external_id: asset.external_id, hostname: asset.hostname, device_type: asset.device_type }, scope, decision, core_management, unknown, affected_core: [...new Map(affectedCore.map(p => [`${p.provider}|${p.role}`, { provider: p.provider, role: p.role, via: p.via || null }])).values()],
      roles: roles.map(p => ({ provider: p.provider, role: p.role, role_ar: ROLE_AR[p.role], basis: p.basis, consumers: p.consumers.includes('*') ? 'everyone' : p.consumers.length, neighbour: p.neighbour || null })),
      affected: { everyone, devices: new Set([...consumers, ...(scope?.devices || []).map(x => x.ref)]).size, services: [...services.values()] }, notes, assessed_at: this.now(),
      claim: 'Impact is derived from declared roles and from observed evidence; a role the graph has no evidence for is not shown. A disruptive change whose effect on the core network or the management path is unknown is refused.',
      claim_ar: 'الأثر مستخرج من الأدوار المصرح بها والأدلة المرصودة؛ والدور الذي لا دليل عليه لا يظهر. ويُرفض أي تغيير معطِّل لا يُعرف أثره على الشبكة الأساسية أو مسار الإدارة.' };
  }
  // Called by the governed preview: refuses disruptive changes with unknown core or management impact.
  guard(type, asset, target) { if (!DISRUPTIVE.has(type)) return null; const r = this.assess({ action_type: type, asset_ref: asset.external_id, target }); fail(r.core_management !== 'unknown', 409, 'change_impact_unknown_on_core_or_management'); return r; }
  view() {
    const p = this.providers(), counts = Object.fromEntries(ROLES.map(r => [r, p.filter(x => x.role === r).length]));
    return { roles: ROLES.map(r => ({ role: r, role_ar: ROLE_AR[r] })), providers: p, counts, core_management_declared: p.some(x => x.basis === 'declared' && ['core', 'management'].includes(x.role)),
      claim_ar: 'يربط كل إجراء بتبعيات DNS والدليل وDHCP والتخزين والاتصال الصوتي والمضيف الافتراضي ومسار الإدارة والوصلات المشتركة قبل تنفيذه، ويمنع تلقائيًا أي تغيير معطِّل لا يُعرف أثره على الشبكة الأساسية أو مسار الإدارة.' };
  }
}
