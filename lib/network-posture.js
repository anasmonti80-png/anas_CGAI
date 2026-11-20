// CG-096 Network posture across IPv4, IPv6, Wi-Fi, DNS/DHCP, VPN, VLAN, trunks, ACL, NAT and BGP/OSPF from an
// authorized, read-only configuration export (Cisco IOS / IOS-XE syntax). Every area reports whether it was assessed,
// absent from the configuration, not collected, or not readable (authorization errors in the export); nothing is
// assumed about an area that was not read.
export const AREAS = ['ipv4', 'ipv6', 'wifi', 'dns', 'dhcp', 'vpn', 'vlan', 'trunks', 'acl', 'nat', 'routing'];
const ADMIN = { 22: 'ssh', 23: 'telnet', 3389: 'rdp', 445: 'smb', 5985: 'winrm', 161: 'snmp', 80: 'http', 443: 'https' };

function interfaces(lines) {
  const out = []; let cur = null;
  for (const l of lines) { const m = l.match(/^interface (\S+)/); if (m) { cur = { name: m[1], lines: [] }; out.push(cur); continue; } if (cur && /^\s/.test(l)) cur.lines.push(l.trim()); else cur = null; }
  return out;
}
function blocks(lines, re) { const out = []; let cur = null; for (const l of lines) { const m = l.match(re); if (m) { cur = { head: m, lines: [] }; out.push(cur); continue; } if (cur && /^\s/.test(l)) cur.lines.push(l.trim()); else cur = null; } return out; }

export function analyseNetworkPosture(config, { collected = AREAS } = {}) {
  const lines = String(config).split(/\r?\n/), ifs = interfaces(lines), has = re => lines.some(l => re.test(l));
  const unreadable = has(/^% ?(Command authorization failed|Authorization failed|Invalid input|Access denied)/i) || !has(/^(hostname|version) /);
  const result = {}, find = (area, id, severity, en, ar, detail = null) => result[area].findings.push({ id, severity, title: en, title_ar: ar, detail });
  for (const a of AREAS) result[a] = { area: a, state: !collected.includes(a) ? 'not-collected' : unreadable ? 'not-readable' : 'assessed', findings: [] };
  const run = (area, present, fn) => { if (result[area].state !== 'assessed') return; if (!present) { result[area].state = 'not-in-config'; return; } fn(); };
  // IPv4
  run('ipv4', ifs.some(i => i.lines.some(l => /^ip address \d/.test(l))), () => { if (has(/^ip source-route/)) find('ipv4', 'ip-source-route', 'medium', 'IP source routing is enabled', 'توجيه المصدر IP مفعّل'); if (!has(/^no ip source-route/) && !has(/^ip source-route/)) {} if (ifs.some(i => i.lines.includes('ip proxy-arp'))) find('ipv4', 'proxy-arp', 'low', 'Proxy ARP enabled on an interface', 'Proxy ARP مفعّل على واجهة'); });
  // IPv6
  const v6 = has(/^ipv6 unicast-routing/) || ifs.some(i => i.lines.some(l => /^ipv6 (address|enable)/.test(l)));
  run('ipv6', v6, () => { if (!ifs.some(i => i.lines.some(l => /^ipv6 (traffic-filter|nd raguard)/.test(l))) && !has(/^ipv6 nd raguard policy/)) find('ipv6', 'ipv6-unfiltered', 'medium', 'IPv6 is enabled without traffic filters or RA guard', 'IPv6 مفعّل دون مرشحات حركة أو حماية RA'); });
  // Wi-Fi (autonomous IOS dot11 SSIDs and IOS-XE wlan profiles)
  const ssids = blocks(lines, /^dot11 ssid (\S+)/), wlans = blocks(lines, /^wlan (\S+)/);
  run('wifi', ssids.length + wlans.length > 0, () => {
    for (const s of ssids) if (!s.lines.some(l => /key-management wpa/.test(l))) find('wifi', `wifi-open:${s.head[1]}`, 'high', `SSID ${s.head[1]} has no WPA key management (open or WEP)`, `الشبكة اللاسلكية ${s.head[1]} بلا إدارة مفاتيح WPA (مفتوحة أو WEP)`);
    for (const w of wlans) { if (w.lines.some(l => /^no security wpa$/.test(l))) find('wifi', `wifi-open:${w.head[1]}`, 'high', `WLAN ${w.head[1]} has WPA disabled`, `الشبكة اللاسلكية ${w.head[1]} معطّل فيها WPA`); else if (w.lines.some(l => /^security wpa wpa1/.test(l)) && !w.lines.some(l => /^no security wpa wpa1/.test(l))) find('wifi', `wifi-wpa1:${w.head[1]}`, 'medium', `WLAN ${w.head[1]} allows legacy WPA1`, `الشبكة اللاسلكية ${w.head[1]} تسمح بـWPA1 القديم`); }
  });
  // DNS
  const ns = [...new Set(lines.flatMap(l => (l.match(/^ip name-server (?:vrf \S+ )?(.+)$/) || [, ''])[1].split(/\s+/).filter(Boolean)))];
  run('dns', ns.length > 0 || has(/^ip domain[ -]lookup/), () => { if (ns.length === 1) find('dns', 'dns-single-server', 'low', 'Only one DNS server is configured', 'خادم DNS واحد فقط مضبوط'); if (!ns.length) find('dns', 'dns-lookup-no-server', 'low', 'DNS lookup enabled without a configured server (broadcast lookups)', 'البحث في DNS مفعّل دون خادم مضبوط (استعلامات بث)'); });
  // DHCP
  const accessPorts = ifs.filter(i => i.lines.includes('switchport mode access'));
  run('dhcp', has(/^ip dhcp (pool|snooping)/) || accessPorts.length > 0, () => { if (accessPorts.length && !has(/^ip dhcp snooping$/)) find('dhcp', 'dhcp-snooping-off', 'medium', `DHCP snooping is not enabled while ${accessPorts.length} access ports exist`, `حماية DHCP snooping غير مفعّلة مع وجود ${accessPorts.length} منافذ وصول`); });
  // VPN
  const isakmp = blocks(lines, /^crypto isakmp policy (\d+)/), ts = lines.filter(l => /^crypto ipsec transform-set/.test(l));
  run('vpn', isakmp.length + ts.length > 0 || has(/^crypto ikev2/), () => {
    for (const p of isakmp) { const weak = p.lines.filter(l => /^(encr(yption)? (des|3des)|hash md5|group (1|2|5))$/.test(l)); if (weak.length) find('vpn', `vpn-weak-ike:${p.head[1]}`, 'high', `IKE policy ${p.head[1]} uses weak parameters: ${weak.join(', ')}`, `سياسة IKE رقم ${p.head[1]} تستخدم معاملات ضعيفة: ${weak.join('، ')}`, weak.join(', ')); }
    for (const l of ts) if (/esp-(des|3des|md5-hmac|null)\b/.test(l)) find('vpn', `vpn-weak-esp:${l.split(/\s+/)[3]}`, 'high', `IPsec transform set ${l.split(/\s+/)[3]} uses weak ESP algorithms`, `مجموعة IPsec ${l.split(/\s+/)[3]} تستخدم خوارزميات ESP ضعيفة`);
  });
  // VLAN and trunks
  const switchports = ifs.filter(i => i.lines.some(l => l.startsWith('switchport')));
  run('vlan', switchports.length > 0 || has(/^vlan \d/), () => {
    const vlan1 = accessPorts.filter(i => !i.lines.some(l => /^switchport access vlan (?!1$)\d+$/.test(l)) && !i.lines.includes('shutdown'));
    if (vlan1.length) find('vlan', 'vlan1-access', 'low', `${vlan1.length} active access ports are in VLAN 1`, `${vlan1.length} منافذ وصول نشطة في VLAN 1`, vlan1.map(i => i.name).slice(0, 10).join(', '));
  });
  const trunks = ifs.filter(i => i.lines.includes('switchport mode trunk')), dynamic = ifs.filter(i => i.lines.some(l => /^switchport mode dynamic (desirable|auto)$/.test(l)));
  run('trunks', trunks.length + dynamic.length > 0, () => {
    if (dynamic.length) find('trunks', 'dtp-dynamic', 'medium', `${dynamic.length} ports negotiate trunking (DTP dynamic)`, `${dynamic.length} منافذ تتفاوض على وضع trunk (DTP)`, dynamic.map(i => i.name).slice(0, 10).join(', '));
    const all = trunks.filter(i => !i.lines.some(l => /^switchport trunk allowed vlan /.test(l))); if (all.length) find('trunks', 'trunk-all-vlans', 'medium', `${all.length} trunks carry all VLANs`, `${all.length} منافذ trunk تمرر كل الشبكات الافتراضية`, all.map(i => i.name).slice(0, 10).join(', '));
    const native = trunks.filter(i => !i.lines.some(l => /^switchport trunk native vlan (?!1$)\d+$/.test(l))); if (native.length) find('trunks', 'native-vlan-1', 'medium', `${native.length} trunks use native VLAN 1`, `${native.length} منافذ trunk تستخدم VLAN 1 كشبكة أصلية`, native.map(i => i.name).slice(0, 10).join(', '));
    const neg = trunks.filter(i => !i.lines.includes('switchport nonegotiate')); if (neg.length) find('trunks', 'trunk-dtp-on', 'low', `${neg.length} trunks still send DTP (no switchport nonegotiate)`, `${neg.length} منافذ trunk ما زالت ترسل DTP`, neg.map(i => i.name).slice(0, 10).join(', '));
  });
  // ACL
  const acl = lines.filter(l => /^(access-list \d+ |\s*(\d+ )?)permit ip any any\b/.test(l));
  run('acl', has(/^(ip )?access-list /), () => { if (acl.length) find('acl', 'acl-permit-any', 'high', `ACL entries permit any IP traffic (${acl.length})`, `قواعد ACL تسمح بأي حركة IP (${acl.length})`, acl.slice(0, 5).map(l => l.trim()).join(' | ')); });
  // NAT
  const statics = lines.map(l => l.match(/^ip nat inside source static (tcp|udp) (\S+) (\d+) (?:interface \S+|\S+) (\d+)/)).filter(Boolean);
  run('nat', has(/^ip nat /), () => { for (const m of statics) { const port = Number(m[3]), adm = ADMIN[port]; find('nat', `nat-static:${m[1]}-${m[4]}`, adm && !['http', 'https'].includes(adm) ? 'high' : 'medium', `Static NAT publishes ${m[2]}:${port}/${m[1]} on outside port ${m[4]}${adm ? ` (${adm})` : ''}`, `NAT ثابت ينشر ${m[2]}:${port}/${m[1]} على المنفذ الخارجي ${m[4]}${adm ? ` (${adm})` : ''}`); } });
  // Routing: BGP and OSPF
  const bgp = blocks(lines, /^router bgp (\d+)/), ospf = blocks(lines, /^router ospf (\d+)/);
  run('routing', bgp.length + ospf.length > 0, () => {
    for (const b of bgp) { const neighbors = [...new Set(b.lines.map(l => l.match(/^neighbor (\S+) remote-as/)?.[1]).filter(Boolean))];
      for (const n of neighbors) { const nl = b.lines.filter(l => l.startsWith(`neighbor ${n} `));
        if (!nl.some(l => / password /.test(l))) find('routing', `bgp-no-auth:${n}`, 'high', `BGP neighbor ${n} has no authentication`, `جار BGP ${n} بلا مصادقة`);
        if (!nl.some(l => / (prefix-list|route-map|filter-list) \S+ in$/.test(l))) find('routing', `bgp-no-filter:${n}`, 'medium', `BGP neighbor ${n} has no inbound route filter`, `جار BGP ${n} بلا مرشح مسارات وارد`); } }
    for (const o of ospf) { const areaAuth = o.lines.some(l => /^area \S+ authentication/.test(l)), ifAuth = ifs.some(i => i.lines.some(l => /^ip ospf (authentication|message-digest-key)/.test(l)));
      if (!areaAuth && !ifAuth) find('routing', `ospf-no-auth:${o.head[1]}`, 'medium', `OSPF process ${o.head[1]} has no authentication`, `عملية OSPF ${o.head[1]} بلا مصادقة`); }
  });
  return { hostname: lines.find(l => l.startsWith('hostname '))?.split(' ')[1] || null, readable: !unreadable, areas: AREAS.map(a => result[a]) };
}
