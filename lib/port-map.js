// CG-101 Physical/network relationship verification before isolation: IP -> MAC -> switch port -> VLAN -> user -> asset.
// Parsers read the text Cisco IOS / IOS-XE prints for "show ip arp", "show mac address-table",
// "show interfaces switchport" and "show lldp neighbors detail". verifyPath() proves each link from evidence and refuses
// trunk ports, uplinks to network devices and ports serving shared virtualization hosts or many devices.
const mac = v => String(v || '').toLowerCase().replace(/[^0-9a-f]/g, '').replace(/(..)(?!$)/g, '$1:');
const iface = v => String(v || '').replace(/^GigabitEthernet/i, 'Gi').replace(/^TenGigabitEthernet/i, 'Te').replace(/^FastEthernet/i, 'Fa').replace(/^TwentyFiveGigE/i, 'Twe').replace(/^Port-channel/i, 'Po');
export function parseArp(text) { return String(text).split(/\r?\n/).map(l => l.match(/^Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f.]{14})\s+ARPA\s+(\S+)/i)).filter(Boolean).map(m => ({ ip: m[1], mac: mac(m[2]), interface: iface(m[3]) })); }
export function parseMacTable(text) { return String(text).split(/\r?\n/).map(l => l.match(/^\s*(\d+)\s+([0-9a-f.]{14})\s+(DYNAMIC|STATIC)\s+(\S+)/i)).filter(Boolean).map(m => ({ vlan: Number(m[1]), mac: mac(m[2]), type: m[3].toLowerCase(), interface: iface(m[4]) })); }
export function parseSwitchport(text) {
  return String(text).split(/\n(?=Name: )/).map(b => { const name = b.match(/^Name: (\S+)/m)?.[1]; if (!name) return null; const op = b.match(/^Operational Mode: (.+)$/m)?.[1]?.trim() || '', adm = b.match(/^Administrative Mode: (.+)$/m)?.[1]?.trim() || '';
    return { interface: iface(name), mode: /trunk/.test(op) || (/trunk/.test(adm) && !/access/.test(op)) ? 'trunk' : /access/.test(op) ? 'access' : /down/.test(op) ? 'down' : 'other', access_vlan: Number(b.match(/^Access Mode VLAN: (\d+)/m)?.[1]) || null, voice_vlan: Number(b.match(/^Voice VLAN: (\d+)/m)?.[1]) || null }; }).filter(Boolean);
}
export function parseLldp(text) {
  return String(text).split(/-{10,}/).map(b => { const local = b.match(/^Local Intf: (\S+)/m)?.[1]; if (!local) return null; const caps = (b.match(/^Enabled Capabilities: (.+)$/m)?.[1] || b.match(/^System Capabilities: (.+)$/m)?.[1] || '').split(',').map(s => s.trim()).filter(Boolean);
    const desc = (b.match(/^System Description:\s*\n?(.+)$/m)?.[1] || '').trim();
    return { interface: iface(local), system_name: b.match(/^System Name: (.+)$/m)?.[1]?.trim() || null, capabilities: caps, description: desc.slice(0, 200), hypervisor: /vmware esx|hyper-v|proxmox|xenserver|kvm|nutanix/i.test(desc) }; }).filter(Boolean);
}
// Each step is verified, unverified (no evidence) or blocking (evidence shows isolation would be unsafe).
export function verifyPath({ ip, maps, nacRecords = [], asset = null }) {
  const steps = [], add = (step, state, detail, detail_ar) => steps.push({ step, state, detail, detail_ar });
  const arp = maps.flatMap(m => m.arp.map(a => ({ ...a, switch_ref: m.switch_ref }))).filter(a => a.ip === ip);
  const macs = [...new Set(arp.map(a => a.mac))];
  if (!macs.length) { add('ip-to-mac', 'unverified', `No ARP entry for ${ip}`, `لا يوجد إدخال ARP للعنوان ${ip}`); return { verified: false, safe_to_isolate: false, steps }; }
  if (macs.length > 1) { add('ip-to-mac', 'blocking', `${ip} maps to several MAC addresses (${macs.join(', ')}): possible spoofing or a shared address`, `العنوان ${ip} يرتبط بعدة عناوين MAC (${macs.join('، ')}): انتحال محتمل أو عنوان مشترك`); return { verified: false, safe_to_isolate: false, steps }; }
  const m = macs[0]; add('ip-to-mac', 'verified', `${ip} -> ${m} (ARP)`, `${ip} ← ${m} (ARP)`);
  const learned = maps.flatMap(x => x.mac_table.filter(e => e.mac === m && !/^(Po|Vl|CPU)/i.test(e.interface)).map(e => ({ ...e, switch_ref: x.switch_ref, sw: x })));
  const edge = learned.filter(e => { const sp = e.sw.switchports.find(s => s.interface === e.interface); return sp && sp.mode === 'access'; });
  if (!learned.length) { add('mac-to-port', 'unverified', `MAC ${m} is not in any collected MAC address table`, `العنوان ${m} غير موجود في جداول MAC المجموعة`); return { verified: false, safe_to_isolate: false, steps }; }
  if (!edge.length) { add('mac-to-port', 'blocking', `MAC ${m} is only learned on trunk or uplink ports (${learned.map(e => `${e.switch_ref} ${e.interface}`).join(', ')})`, `العنوان ${m} معروف فقط على منافذ trunk أو uplink`); return { verified: false, safe_to_isolate: false, steps }; }
  if (edge.length > 1) { add('mac-to-port', 'blocking', `MAC ${m} appears on several access ports: ${edge.map(e => `${e.switch_ref} ${e.interface}`).join(', ')}`, `العنوان ${m} يظهر على عدة منافذ وصول`); return { verified: false, safe_to_isolate: false, steps }; }
  const port = edge[0], sp = port.sw.switchports.find(s => s.interface === port.interface), others = port.sw.mac_table.filter(e => e.interface === port.interface && e.mac !== m);
  add('mac-to-port', 'verified', `${m} -> ${port.switch_ref} ${port.interface} (access port)`, `${m} ← ${port.switch_ref} ${port.interface} (منفذ وصول)`);
  const neighbor = port.sw.lldp.find(n => n.interface === port.interface);
  if (neighbor && (neighbor.hypervisor || neighbor.capabilities.some(c => ['B', 'R', 'Bridge', 'Router', 'W', 'WLAN Access Point'].includes(c)))) add('port-role', 'blocking', `${port.interface} connects to ${neighbor.system_name || 'a device'} (${neighbor.hypervisor ? 'virtualization host' : neighbor.capabilities.join(',')}): shutting it would cut other systems`, `${port.interface} متصل بـ${neighbor.system_name || 'جهاز'} (${neighbor.hypervisor ? 'مضيف افتراضي' : neighbor.capabilities.join(',')}): إيقافه يقطع أنظمة أخرى`);
  else if (others.length > 1) add('port-role', 'blocking', `${port.interface} has ${others.length + 1} MAC addresses: a shared or virtualization host may sit behind it`, `${port.interface} عليه ${others.length + 1} عناوين MAC: قد يكون خلفه مضيف مشترك أو افتراضي`);
  else add('port-role', 'verified', `${port.interface} is an edge access port${others.length ? ' (one more device, likely an IP phone)' : ''}`, `${port.interface} منفذ وصول طرفي${others.length ? ' (جهاز إضافي واحد، غالبًا هاتف IP)' : ''}`);
  if (sp.access_vlan && sp.access_vlan === port.vlan) add('vlan', 'verified', `VLAN ${port.vlan} matches the access VLAN`, `الشبكة الافتراضية ${port.vlan} تطابق شبكة الوصول`);
  else if (sp.voice_vlan === port.vlan) add('vlan', 'verified', `VLAN ${port.vlan} is the voice VLAN`, `الشبكة الافتراضية ${port.vlan} هي شبكة الصوت`);
  else add('vlan', 'blocking', `MAC learned in VLAN ${port.vlan} but the port access VLAN is ${sp.access_vlan}`, `العنوان معروف في VLAN ${port.vlan} بينما شبكة وصول المنفذ ${sp.access_vlan}`);
  const user = [...nacRecords].reverse().find(r => r.category === 'nac' && r.outcome === 'success' && r.mac === m);
  if (user) add('user', 'verified', `Last NAC login on ${m}: ${user.user}`, `آخر دخول NAC على ${m}: ${user.user}`); else add('user', 'unverified', `No NAC login seen for ${m}`, `لا يوجد دخول NAC مرصود لـ${m}`);
  if (asset) add('asset', (asset.addresses || []).includes(ip) ? 'verified' : 'blocking', (asset.addresses || []).includes(ip) ? `${ip} belongs to asset ${asset.external_id}` : `${ip} is not an address of asset ${asset.external_id}`, (asset.addresses || []).includes(ip) ? `${ip} يخص الأصل ${asset.external_id}` : `${ip} ليس عنوانًا للأصل ${asset.external_id}`);
  const blocking = steps.some(s => s.state === 'blocking');
  return { verified: !blocking && steps.filter(s => s.step !== 'user').every(s => s.state === 'verified'), safe_to_isolate: !blocking && steps.filter(s => s.step !== 'user').every(s => s.state === 'verified'), switch_ref: port.switch_ref, interface: port.interface, mac: m, vlan: port.vlan, user: user?.user || null, steps };
}
// A switch port named in an isolation request must be a verified edge access port on that switch.
export function verifyPort(maps, switchRef, interfaceRef) {
  const m = maps.find(x => x.switch_ref === switchRef); if (!m) return { safe_to_isolate: false, reason: 'no-port-map-for-switch' };
  const name = iface(interfaceRef), sp = m.switchports.find(s => s.interface === name); if (!sp) return { safe_to_isolate: false, reason: 'port-not-in-port-map' };
  if (sp.mode !== 'access') return { safe_to_isolate: false, reason: 'port-is-not-an-access-port' };
  const n = m.lldp.find(x => x.interface === name); if (n && (n.hypervisor || n.capabilities.some(c => ['B', 'R', 'Bridge', 'Router', 'W', 'WLAN Access Point'].includes(c)))) return { safe_to_isolate: false, reason: n.hypervisor ? 'port-serves-virtualization-host' : 'port-is-an-uplink' };
  const macs = new Set(m.mac_table.filter(e => e.interface === name).map(e => e.mac)); if (macs.size > 2) return { safe_to_isolate: false, reason: 'port-serves-several-devices' };
  return { safe_to_isolate: true, reason: null, interface: name, macs: [...macs], vlan: sp.access_vlan };
}
// NAC quarantine names an endpoint MAC: it must be learned on exactly one edge access port that is not an uplink and
// does not serve a virtualization host or several devices.
export function verifyMac(maps, macAddress) {
  const target = mac(macAddress), learned = maps.flatMap(x => x.mac_table.filter(e => e.mac === target && !/^(Po|Vl|CPU)/i.test(e.interface)).map(e => ({ ...e, sw: x })));
  const edge = learned.filter(e => e.sw.switchports.find(s => s.interface === e.interface)?.mode === 'access');
  if (!learned.length) return { safe_to_isolate: false, reason: 'mac-not-in-port-maps' };
  if (edge.length !== 1) return { safe_to_isolate: false, reason: edge.length ? 'mac-on-several-access-ports' : 'mac-only-on-trunks-or-uplinks' };
  const port = verifyPort(maps, edge[0].sw.switch_ref, edge[0].interface);
  return port.safe_to_isolate ? { safe_to_isolate: true, reason: null, switch_ref: edge[0].sw.switch_ref, interface: edge[0].interface, vlan: edge[0].vlan } : port;
}
