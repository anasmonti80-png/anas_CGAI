import { fail } from './common.js';
// CG-132 Intended versus observed state. The intended state comes from an approved source of truth (NetBox REST
// exports); the observed state is what CyberGuard actually sees (assets, ARP and MAC tables, switchport VLANs, asset
// context owners). Differences in presence, IP, MAC, interface, VLAN and owner are listed with which side changed more
// recently, so a person reviews each one before the source of truth is updated. CyberGuard never writes to NetBox:
// reviewed updates are exported as a patch for the NetBox owner to apply.
const mac = v => String(v || '').toLowerCase().replace(/[^0-9a-f]/g, '').replace(/(..)(?!$)/g, '$1:') || null;
const bareIp = v => String(v || '').split('/')[0] || null;
const iface = v => String(v || '').replace(/^GigabitEthernet/i, 'Gi').replace(/^TenGigabitEthernet/i, 'Te').replace(/^FastEthernet/i, 'Fa');

export function parseNetbox({ devices, interfaces = { results: [] } }) {
  const byDevice = new Map(); for (const i of interfaces.results || []) { const n = i.device?.name; if (!n) continue; const ep = (i.connected_endpoints || i.link_peers || [])[0];
    (byDevice.get(n) || byDevice.set(n, []).get(n)).push({ netbox_id: i.id, name: i.name, mac: mac(i.mac_address), vlan: i.untagged_vlan?.vid ?? null, switch: ep?.device?.name || null, port: ep?.name ? iface(ep.name) : null, last_updated: i.last_updated || null }); }
  return (devices.results || []).map(d => ({ netbox_id: d.id, name: d.name, ip: bareIp(d.primary_ip4?.address || d.primary_ip?.address), site: d.site?.name || null, role: (d.role || d.device_role)?.name || null, owner: d.tenant?.name || null, last_updated: d.last_updated || null, interfaces: byDevice.get(d.name) || [] }));
}

export function reconcile(intended, observed) {
  const conflicts = [], add = (key, type, device, detail, detail_ar, intendedValue, observedValue, sotAt, obsAt, netbox = null) => conflicts.push({ key, type, device, detail, detail_ar, intended: intendedValue, observed: observedValue, source_of_truth_updated: sotAt, observed_at: obsAt, newer: !sotAt || !obsAt ? 'unknown' : obsAt > sotAt ? 'observed' : 'source-of-truth', netbox });
  const arp = observed.maps.flatMap(m => m.arp.map(a => ({ ...a, switch_ref: m.switch_ref, at: m.observed_at }))), macs = observed.maps.flatMap(m => m.mac_table.filter(e => !/^(CPU|Vl)/i.test(e.interface)).map(e => ({ ...e, switch_ref: m.switch_ref, at: m.observed_at, sp: m.switchports.find(s => s.interface === e.interface) })));
  const known = new Set();
  for (const d of intended) {
    const asset = observed.assets.find(a => (a.hostname || '').toLowerCase() === d.name.toLowerCase()) || (d.ip ? observed.assets.find(a => a.addresses.includes(d.ip)) : null), seenIp = d.ip ? arp.find(a => a.ip === d.ip) : null;
    if (d.ip) known.add(d.ip); if (asset) known.add(asset.id);
    if (!asset && !seenIp) { add(`${d.name}:not-observed`, 'not-observed', d.name, `${d.name} is in the source of truth but was not observed (no asset, no ARP entry for ${d.ip || 'its address'})`, `${d.name} موجود في مصدر الحقيقة ولم يُرصد`, d.ip, null, d.last_updated, null, { object: 'dcim.device', id: d.netbox_id }); continue; }
    if (asset && d.ip && !asset.addresses.includes(d.ip)) add(`${d.name}:ip`, 'ip-mismatch', d.name, `Primary IP ${d.ip} in the source of truth; observed ${asset.addresses.join(', ') || 'none'}`, `العنوان الأساسي ${d.ip} في مصدر الحقيقة؛ المرصود ${asset.addresses.join('، ') || 'لا شيء'}`, d.ip, asset.addresses, d.last_updated, asset.last_seen, { object: 'ipam.ip_address', device_id: d.netbox_id });
    for (const i of d.interfaces) {
      if (seenIp && i.mac && seenIp.mac !== i.mac) add(`${d.name}:${i.name}:mac`, 'mac-mismatch', d.name, `${i.name} MAC ${i.mac} in the source of truth; ARP shows ${seenIp.mac} for ${d.ip}`, `عنوان MAC للمنفذ ${i.name} مختلف عن المرصود`, i.mac, seenIp.mac, i.last_updated, seenIp.at, { object: 'dcim.interface', id: i.netbox_id });
      const learned = i.mac ? macs.filter(e => e.mac === i.mac) : []; if (!learned.length) continue; const edge = learned.find(e => e.sp?.mode === 'access') || learned[0];
      if (i.port && (edge.interface !== i.port || (i.switch && edge.switch_ref !== i.switch))) add(`${d.name}:${i.name}:interface`, 'interface-mismatch', d.name, `Cabled to ${i.switch || '?'} ${i.port} in the source of truth; MAC learned on ${edge.switch_ref} ${edge.interface}${edge.sp?.mode === 'trunk' ? ' (trunk)' : ''}`, `موصول في مصدر الحقيقة بالمنفذ ${i.port}؛ المرصود ${edge.switch_ref} ${edge.interface}`, `${i.switch} ${i.port}`, `${edge.switch_ref} ${edge.interface}`, i.last_updated, edge.at, { object: 'dcim.interface', id: i.netbox_id });
      if (i.vlan !== null && edge.vlan !== i.vlan) add(`${d.name}:${i.name}:vlan`, 'vlan-mismatch', d.name, `Untagged VLAN ${i.vlan} in the source of truth; MAC learned in VLAN ${edge.vlan}`, `الشبكة الافتراضية ${i.vlan} في مصدر الحقيقة؛ المرصود ${edge.vlan}`, i.vlan, edge.vlan, i.last_updated, edge.at, { object: 'dcim.interface', id: i.netbox_id });
    }
    const ctxOwner = asset ? observed.owners[asset.id] : null;
    if (!d.owner) add(`${d.name}:owner`, 'owner-missing', d.name, `${d.name} has no owner (tenant) in the source of truth${ctxOwner ? `; CyberGuard records ${ctxOwner}` : ''}`, `${d.name} بلا مالك في مصدر الحقيقة`, null, ctxOwner, d.last_updated, null, { object: 'dcim.device', id: d.netbox_id });
    else if (ctxOwner && ctxOwner !== d.owner) add(`${d.name}:owner`, 'owner-mismatch', d.name, `Owner ${d.owner} in the source of truth; CyberGuard asset context says ${ctxOwner}`, `المالك ${d.owner} في مصدر الحقيقة؛ سياق الأصل يقول ${ctxOwner}`, d.owner, ctxOwner, d.last_updated, null, { object: 'dcim.device', id: d.netbox_id });
  }
  for (const a of observed.assets.filter(a => !known.has(a.id) && !a.addresses.some(ip => known.has(ip)) && !['switch', 'router', 'firewall'].includes(a.device_type))) add(`${a.hostname || a.external_id}:unregistered`, 'unregistered', a.hostname || a.external_id, `${a.hostname || a.external_id} (${a.addresses.join(', ') || 'no address'}) is observed but not in the source of truth`, `${a.hostname || a.external_id} مرصود وغير مسجل في مصدر الحقيقة`, null, a.addresses, null, a.last_seen);
  const unknownArp = new Map(); for (const e of arp.filter(e => !known.has(e.ip) && !observed.assets.some(a => a.addresses.includes(e.ip)))) unknownArp.set(e.ip, [...(unknownArp.get(e.ip) || []), e]);
  for (const [ip, es] of unknownArp) { const macs = [...new Set(es.map(e => e.mac))], at = es.map(e => e.at).filter(Boolean).sort().at(-1) || null; add(`${ip}:unregistered`, 'unregistered', ip, `${ip} (${macs.join(', ')}) answers ARP on ${es[0].switch_ref} but is not in the source of truth`, `${ip} (${macs.join('، ')}) يظهر في ARP وغير مسجل في مصدر الحقيقة`, null, macs.join(', '), null, at); }
  return conflicts;
}

export const DECISIONS = ['update-source-of-truth', 'fix-device', 'accept-difference'];
export class IntendedState {
  constructor(store, { clock }) { Object.assign(this, { s: store, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  intended() { const r = this.s.get("SELECT observed_at,payload FROM events WHERE kind='inventory.intended' ORDER BY observed_at DESC,received_at DESC LIMIT 1"); return r ? { at: r.observed_at, ...JSON.parse(r.payload).details } : null; }
  observed() {
    const assets = [...new Map(this.s.all("SELECT a.*,s.kind source_kind FROM assets a JOIN sources s ON s.id=a.source_id WHERE a.external_id<>'source-of-truth:netbox' ORDER BY a.last_seen").map(a => [a.external_id, { ...a, addresses: JSON.parse(a.addresses) }])).values()];
    const maps = [...new Map(this.s.all("SELECT observed_at,payload FROM events WHERE kind='network.port_map' ORDER BY observed_at").map(r => { const d = JSON.parse(r.payload).details; return [d.switch_ref, { ...d, observed_at: r.observed_at }]; })).values()];
    const owners = {}; for (const r of this.s.all("SELECT e.payload,a.external_id FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind='asset.context' ORDER BY e.observed_at")) { const o = JSON.parse(r.payload).details.owner?.display_name; const asset = assets.find(x => x.external_id === r.external_id); if (o && asset) owners[asset.id] = o; }
    return { assets, maps, owners };
  }
  review(actor, input) {
    const key = String(input.key || ''), decision = DECISIONS.includes(input.decision) ? input.decision : null, note = String(input.note || '').slice(0, 1000);
    fail(decision, 400, 'invalid_review_decision');
    const c = this.view().conflicts.find(x => x.key === key); fail(c, 404, 'conflict_not_found');
    fail(decision !== 'update-source-of-truth' || c.netbox, 409, 'nothing_to_update_in_source_of_truth');
    this.s.run('INSERT INTO intended_reviews(key,decision,note,conflict,reviewed_by,reviewed_at) VALUES (?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET decision=excluded.decision,note=excluded.note,conflict=excluded.conflict,reviewed_by=excluded.reviewed_by,reviewed_at=excluded.reviewed_at', key, decision, note, JSON.stringify(c), actor, this.now());
    this.s.audit(actor, 'intended_state.reviewed', key, { decision, type: c.type }, this.now()); return this.view();
  }
  // Reviewed "update the source of truth" decisions as a patch for the NetBox owner; nothing is sent to NetBox.
  patch() { return { schema_version: 'cg.netbox-patch/1', generated_at: this.now(), applied_by_cyberguard: false, changes: this.s.all("SELECT * FROM intended_reviews WHERE decision='update-source-of-truth' ORDER BY reviewed_at").map(r => { const c = JSON.parse(r.conflict); return { netbox: c.netbox, type: c.type, device: c.device, from: c.intended, to: c.observed, reviewed_by: r.reviewed_by, reviewed_at: r.reviewed_at, note: r.note }; }) }; }
  view() {
    const i = this.intended(), conflicts = i ? reconcile(i.devices, this.observed()) : [], reviews = new Map(this.s.all('SELECT key,decision,reviewed_by,reviewed_at FROM intended_reviews').map(r => [r.key, r]));
    return { source: i ? { source: i.source, exported_at: i.exported_at, devices: i.devices.length } : null, conflicts: conflicts.map(c => ({ ...c, review: reviews.get(c.key) || null })), summary: Object.fromEntries(['not-observed', 'unregistered', 'ip-mismatch', 'mac-mismatch', 'interface-mismatch', 'vlan-mismatch', 'owner-missing', 'owner-mismatch'].map(t => [t, conflicts.filter(c => c.type === t).length])), unreviewed: conflicts.filter(c => !reviews.has(c.key)).length,
      claim: 'Intended state from the source of truth is compared with what CyberGuard observes; each difference shows which side changed more recently and needs a person to decide before the source of truth is updated. CyberGuard never writes to the source of truth.',
      claim_ar: 'تُقارن الحالة المقصودة من مصدر الحقيقة بما يرصده CyberGuard فعلًا؛ ويبين كل اختلاف أي الجانبين تغير مؤخرًا ويحتاج قرارًا بشريًا قبل تحديث مصدر الحقيقة. لا يكتب CyberGuard في مصدر الحقيقة أبدًا.' };
  }
}
