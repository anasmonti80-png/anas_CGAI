// CG-134 Layer-2 security posture. From an authorized, read-only switch configuration export it reports, per device,
// whether DHCP snooping, Dynamic ARP Inspection, IP Source Guard and 802.1X are enabled, partial, disabled, unsupported or
// not collected, with the VLANs and access ports they cover. Rogue DHCP, MAC moves and ARP conflicts are collected as
// signals from switch logs, ARP tables, port map history and flow records. One signal is never treated as proof: a
// subject seen by a single source is a low "needs corroboration" alert, and only independent sources raise it.
const iface = s => String(s || '').replace(/^GigabitEthernet/i, 'Gi').replace(/^TenGigabitEthernet/i, 'Te').replace(/^FastEthernet/i, 'Fa').replace(/^TwoGigabitEthernet/i, 'Tw');
const mac = m => String(m || '').toLowerCase().replace(/[^0-9a-f]/g, '').replace(/(..)(?!$)/g, '$1:');
export const FEATURES = ['dhcp-snooping', 'dai', 'ip-source-guard', '802.1x'];
export const FEATURE_AR = { 'dhcp-snooping': 'تطفل DHCP', dai: 'فحص ARP الديناميكي', 'ip-source-guard': 'حارس مصدر IP', '802.1x': '802.1X' };
export const SIGNALS = ['rogue-dhcp', 'mac-move', 'arp-conflict'];
const RULE = { 'rogue-dhcp': 'CG-L2-ROGUE-DHCP-134', 'mac-move': 'CG-L2-MAC-MOVE-134', 'arp-conflict': 'CG-L2-ARP-CONFLICT-134' };
const BENIGN = {
  'rogue-dhcp': ['A newly installed or test DHCP server', 'A home router, printer or appliance with its DHCP server left on'],
  'mac-move': ['A virtual machine migrated between hosts', 'Wireless roaming or a cable moved to another port', 'NIC teaming or a loop'],
  'arp-conflict': ['A first-hop redundancy (HSRP/VRRP) virtual address', 'A device re-addressed while an old ARP entry remains', 'Two devices given the same static address by mistake'],
};
const BENIGN_AR = {
  'rogue-dhcp': ['خادم DHCP جديد أو تجريبي', 'موجّه منزلي أو طابعة أو جهاز ترك خادم DHCP مفعّلًا'],
  'mac-move': ['آلة افتراضية انتقلت بين مضيفين', 'تجوال لاسلكي أو كابل نُقل إلى منفذ آخر', 'تجميع بطاقات الشبكة أو حلقة'],
  'arp-conflict': ['عنوان افتراضي لتكرار البوابة (HSRP/VRRP)', 'جهاز غُيّر عنوانه وبقي إدخال ARP قديم', 'جهازان أُعطيا العنوان الثابت نفسه خطأً'],
};
const vlanList = s => String(s).split(',').flatMap(p => { const [a, b] = p.trim().split('-').map(Number); return Number.isInteger(a) ? (Number.isInteger(b) ? Array.from({ length: Math.min(b - a + 1, 4094) }, (_, i) => a + i) : [a]) : []; });

// Parse a Cisco IOS / IOS-XE running configuration.
export function parseL2Config(textIn) {
  const lines = String(textIn).split(/\r?\n/), g = { snooping: false, snoopingVlans: [], dai: [], dot1x: false, aaa: false, helpers: [], hostname: null }, ports = []; let cur = null;
  for (const raw of lines) {
    const l = raw.replace(/\s+$/, '');
    if (/^\S/.test(l)) cur = null;
    let m;
    if ((m = l.match(/^interface (\S+)/))) { cur = { interface: iface(m[1]), mode: null, vlan: 1, snooping_trust: false, dai_trust: false, ipsg: false, dot1x: false, mab: false, shutdown: false }; ports.push(cur); continue; }
    if (cur) {
      const t = l.trim();
      if ((m = t.match(/^switchport mode (\S+)/))) cur.mode = m[1];
      else if ((m = t.match(/^switchport access vlan (\d+)/))) cur.vlan = Number(m[1]);
      else if (t === 'ip dhcp snooping trust') cur.snooping_trust = true;
      else if (t === 'ip arp inspection trust') cur.dai_trust = true;
      else if (/^ip verify source( |$)/.test(t)) cur.ipsg = true;
      else if (/^(authentication port-control auto|dot1x port-control auto|access-session port-control auto)$/.test(t)) cur.dot1x = true;
      else if (t === 'mab') cur.mab = true;
      else if (t === 'shutdown') cur.shutdown = true;
      else if ((m = t.match(/^ip helper-address (\S+)/))) g.helpers.push(m[1]);
      continue;
    }
    if ((m = l.match(/^hostname (\S+)/))) g.hostname = m[1];
    else if (l === 'ip dhcp snooping') g.snooping = true;
    else if ((m = l.match(/^ip dhcp snooping vlan (.+)$/))) g.snoopingVlans.push(...vlanList(m[1]));
    else if ((m = l.match(/^ip arp inspection vlan (.+)$/))) g.dai.push(...vlanList(m[1]));
    else if (l === 'dot1x system-auth-control') g.dot1x = true;
    else if (l === 'aaa new-model') g.aaa = true;
  }
  return { ...g, ports };
}

// Feature states for one device. `unsupported` lists features the platform cannot run (from a capability probe or the
// vendor datasheet); `collected` false means no configuration was exported.
export function assessL2Posture(cfg, { unsupported = [], collected = true } = {}) {
  if (!collected) return FEATURES.map(feature => ({ feature, state: 'not-collected', detail: 'No configuration export', detail_ar: 'لم يُصدَّر الإعداد', findings: [] }));
  const access = cfg.ports.filter(p => p.mode === 'access' && !p.shutdown), uplinks = cfg.ports.filter(p => p.mode === 'trunk'), vlans = [...new Set(access.map(p => p.vlan))].sort((a, b) => a - b);
  const out = [], push = (feature, state, detail, detail_ar, findings = [], data = {}) => out.push({ feature, state, detail, detail_ar, findings, ...data });
  const f = (id, severity, title, title_ar, detail) => ({ id, severity, title, title_ar, detail });
  for (const feature of FEATURES) {
    if (unsupported.includes(feature)) { push(feature, 'unsupported', 'The platform does not support this feature', 'المنصة لا تدعم هذه الميزة'); continue; }
    if (feature === 'dhcp-snooping') {
      const covered = vlans.filter(v => cfg.snoopingVlans.includes(v)), missing = vlans.filter(v => !covered.includes(v)), untrustedUp = uplinks.filter(p => !p.snooping_trust).map(p => p.interface);
      if (!cfg.snooping || !cfg.snoopingVlans.length) push(feature, 'disabled', 'DHCP snooping is off: any device can answer DHCP', 'تطفل DHCP معطل: يستطيع أي جهاز الرد على DHCP', [f('l2-dhcp-snooping-off', 'medium', 'DHCP snooping disabled', 'تطفل DHCP معطل', `Access VLANs ${vlans.join(', ') || 'none'} are unprotected`)], { vlans_covered: [], vlans_missing: vlans });
      else push(feature, missing.length || untrustedUp.length ? 'partial' : 'enabled', `Snooping on VLANs ${covered.join(', ') || 'none'}${missing.length ? `; not on ${missing.join(', ')}` : ''}${untrustedUp.length ? `; uplinks not trusted: ${untrustedUp.join(', ')}` : ''}`, `التطفل على الشبكات ${covered.join('، ') || 'لا شيء'}${missing.length ? `؛ وليس على ${missing.join('، ')}` : ''}${untrustedUp.length ? `؛ وصلات صاعدة غير موثوقة: ${untrustedUp.join('، ')}` : ''}`,
        [...(missing.length ? [f('l2-dhcp-snooping-vlans', 'low', 'DHCP snooping misses access VLANs', 'تطفل DHCP لا يغطي كل الشبكات', missing.join(', '))] : []), ...(untrustedUp.length ? [f('l2-dhcp-snooping-untrusted-uplink', 'medium', 'Uplink not trusted for DHCP snooping: legitimate DHCP replies will be dropped', 'وصلة صاعدة غير موثوقة لتطفل DHCP: ستُسقط ردود DHCP الشرعية', untrustedUp.join(', '))] : [])], { vlans_covered: covered, vlans_missing: missing });
    } else if (feature === 'dai') {
      const covered = vlans.filter(v => cfg.dai.includes(v)), missing = vlans.filter(v => !covered.includes(v)), noBindings = covered.filter(v => !cfg.snooping || !cfg.snoopingVlans.includes(v));
      if (!cfg.dai.length) push(feature, 'disabled', 'Dynamic ARP Inspection is off: ARP replies are not validated', 'فحص ARP الديناميكي معطل: ردود ARP غير متحقق منها', [f('l2-dai-off', 'low', 'Dynamic ARP Inspection disabled', 'فحص ARP الديناميكي معطل', `Access VLANs ${vlans.join(', ') || 'none'}`)], { vlans_covered: [], vlans_missing: vlans });
      else push(feature, missing.length || noBindings.length ? 'partial' : 'enabled', `ARP inspection on VLANs ${covered.join(', ')}${missing.length ? `; not on ${missing.join(', ')}` : ''}${noBindings.length ? `; without DHCP snooping bindings on ${noBindings.join(', ')}` : ''}`, `فحص ARP على الشبكات ${covered.join('، ')}${missing.length ? `؛ وليس على ${missing.join('، ')}` : ''}${noBindings.length ? `؛ دون روابط تطفل DHCP على ${noBindings.join('، ')}` : ''}`,
        noBindings.length ? [f('l2-dai-without-snooping', 'medium', 'ARP inspection without DHCP snooping bindings drops legitimate ARP', 'فحص ARP دون روابط تطفل DHCP يُسقط ARP الشرعي', noBindings.join(', '))] : [], { vlans_covered: covered, vlans_missing: missing });
    } else {
      const key = feature === 'ip-source-guard' ? 'ipsg' : 'dot1x', on = access.filter(p => p[key]), off = access.filter(p => !p[key]).map(p => p.interface);
      const globalOff = feature === '802.1x' && on.length && !(cfg.aaa && cfg.dot1x);
      const state = !access.length ? 'not-applicable' : !on.length ? 'disabled' : off.length || globalOff ? 'partial' : 'enabled';
      const label = feature === 'ip-source-guard' ? ['IP Source Guard', 'حارس مصدر IP'] : ['802.1X', '802.1X'];
      push(feature, state, `${label[0]} on ${on.length} of ${access.length} access ports${off.length ? ` (missing: ${off.slice(0, 20).join(', ')})` : ''}${globalOff ? '; aaa new-model or dot1x system-auth-control is missing, so port settings do nothing' : ''}`, `${label[1]} على ${on.length} من ${access.length} منفذ وصول${off.length ? ` (غير مفعّل: ${off.slice(0, 20).join('، ')})` : ''}${globalOff ? '؛ ينقص aaa new-model أو dot1x system-auth-control فلا أثر لإعداد المنافذ' : ''}`,
        state === 'disabled' ? [f(`l2-${feature === 'ip-source-guard' ? 'ipsg' : 'dot1x'}-off`, 'low', `${label[0]} disabled on all access ports`, `${label[1]} معطل على كل منافذ الوصول`, `${access.length} access ports`)] : globalOff ? [f('l2-dot1x-global-missing', 'medium', '802.1X configured on ports but not enabled globally', '802.1X مضبوط على المنافذ وغير مفعّل عامًّا', 'aaa new-model / dot1x system-auth-control')] : [], { ports_enabled: on.length, ports_total: access.length });
    }
  }
  return out;
}

// Signals from Cisco syslog lines (show logging or a syslog file).
export function parseL2Syslog(textIn) {
  const out = [];
  for (const [i, l] of String(textIn).split(/\r?\n/).entries()) {
    let m;
    if ((m = l.match(/%SW_MATM-4-MACFLAP_NOTIF: Host ([0-9a-f.]{14}) in vlan (\d+) is flapping between port (\S+) and port (\S+)/i))) out.push({ type: 'mac-move', subject: mac(m[1]), vlan: Number(m[2]), ports: [iface(m[3]), iface(m[4])], source: 'switch-log', line: i + 1 });
    else if ((m = l.match(/%IP-4-DUPADDR: Duplicate address (\d+\.\d+\.\d+\.\d+) on (\S+), sourced by ([0-9a-f.]{14})/i))) out.push({ type: 'arp-conflict', subject: m[1], macs: [mac(m[3])], source: 'switch-log', line: i + 1 });
    else if ((m = l.match(/%SW_DAI-4-(?:DHCP_SNOOPING_DENY|ACL_DENY): .*?on (\S+), vlan (\d+)\.\(\[([0-9a-f.]{14})\/(\d+\.\d+\.\d+\.\d+)/i))) out.push({ type: 'arp-conflict', subject: m[4], macs: [mac(m[3])], ports: [iface(m[1].replace(/,$/, ''))], vlan: Number(m[2]), source: 'arp-inspection', line: i + 1 });
    else if ((m = l.match(/%DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT: .*message type: (DHCPOFFER|DHCPACK|DHCPNAK)(?:, MAC sa: ([0-9a-f.]{14}))?/i))) out.push({ type: 'rogue-dhcp', subject: m[2] ? mac(m[2]) : 'unknown-server', message: m[1].toUpperCase(), source: 'dhcp-snooping', line: i + 1 });
  }
  return out;
}

// Combine signals from every source into per-subject findings with a confidence level.
export function correlateL2({ events = [], portMapHistory = [], flows = [], authorizedDhcp = [] }) {
  const sig = [];
  for (const e of events) for (const s of e.signals || []) sig.push({ ...s, device_ref: e.device_ref, at: e.observed_at });
  // ARP tables: one IP answered by several MACs.
  const latest = new Map(); for (const m of portMapHistory) latest.set(m.switch_ref, m);
  for (const m of latest.values()) { const by = new Map(); for (const a of m.arp || []) by.set(a.ip, [...new Set([...(by.get(a.ip) || []), a.mac])]); for (const [ip, macs] of by) if (macs.length > 1) sig.push({ type: 'arp-conflict', subject: ip, macs, source: 'arp-table', device_ref: m.switch_ref, at: m.observed_at || null }); }
  // Port map history: a MAC learned on one access port, then on another.
  const bySwitch = new Map(); for (const m of portMapHistory) bySwitch.set(m.switch_ref, [...(bySwitch.get(m.switch_ref) || []), m]);
  for (const [sw, snaps] of bySwitch) for (let i = 1; i < snaps.length; i++) {
    const where = s => { const r = new Map(); for (const e of s.mac_table || []) if (!/^(Po|Vl|CPU)/i.test(e.interface) && (s.switchports || []).find(p => p.interface === e.interface)?.mode === 'access') r.set(e.mac, e.interface); return r; };
    const a = where(snaps[i - 1]), b = where(snaps[i]);
    for (const [m, p] of b) if (a.has(m) && a.get(m) !== p) sig.push({ type: 'mac-move', subject: m, ports: [a.get(m), p], source: 'port-map-history', device_ref: sw, at: snaps[i].observed_at || null, hypervisor: [a.get(m), p].some(x => (snaps[i].lldp || []).find(n => n.interface === x)?.hypervisor) });
  }
  // Flow records: DHCP server replies (UDP 67 to 68) from a server that is not authorized.
  const allowed = new Set(authorizedDhcp);
  if (allowed.size) for (const r of flows) if (r.src_port === 67 && r.dst_port === 68 && r.src_ip && !allowed.has(r.src_ip)) sig.push({ type: 'rogue-dhcp', subject: r.src_ip, source: 'dhcp-traffic', at: r.time || null });
  // A rogue server is known by MAC in switch logs and by IP in flows; ARP tables join the two.
  const ipOfMac = new Map(); for (const m of latest.values()) for (const a of m.arp || []) ipOfMac.set(a.mac, a.ip);
  const key = s => s.type === 'rogue-dhcp' && ipOfMac.has(s.subject) ? ipOfMac.get(s.subject) : s.subject;
  const groups = new Map(); for (const s of sig) { const k = `${s.type}|${key(s)}`; groups.set(k, [...(groups.get(k) || []), s]); }
  return [...groups.entries()].map(([k, list]) => {
    const [type, subject] = k.split('|'), sources = [...new Set(list.map(s => s.source))], hyper = list.some(s => s.hypervisor), confidence = sources.length >= 2 ? 'corroborated' : 'single-signal';
    const severity = confidence === 'single-signal' ? 'low' : type === 'rogue-dhcp' ? 'high' : hyper ? 'low' : 'medium';
    const macs = [...new Set(list.flatMap(s => s.macs || (type !== 'arp-conflict' && /:/.test(s.subject) ? [s.subject] : [])))], ports = [...new Set(list.flatMap(s => s.ports || []))];
    return { rule: RULE[type], type, subject, confidence, severity, sources, signals: list.length, devices: [...new Set(list.map(s => s.device_ref).filter(Boolean))], macs, ports, hypervisor_port: hyper,
      possible_benign: BENIGN[type], possible_benign_ar: BENIGN_AR[type], last_at: list.map(s => s.at).filter(Boolean).sort().at(-1) || null,
      verdict: confidence === 'corroborated' ? 'Independent sources agree; investigate the device' : 'One source only: needs corroboration before it is treated as an attack',
      verdict_ar: confidence === 'corroborated' ? 'مصادر مستقلة متفقة؛ افحص الجهاز' : 'مصدر واحد فقط: يحتاج تأكيدًا قبل اعتباره هجومًا' };
  }).sort((a, b) => (b.confidence === 'corroborated') - (a.confidence === 'corroborated') || a.type.localeCompare(b.type));
}

// Everything stored: the latest posture per device, port map history, recent DHCP flow records.
export function l2Evidence(store, now = Date.now()) {
  const parse = s => JSON.parse(s), latest = new Map();
  for (const r of store.all("SELECT observed_at,payload FROM events WHERE kind='network.l2_security' ORDER BY observed_at,received_at")) { const d = parse(r.payload).details; latest.set(d.device_ref, { ...d, observed_at: r.observed_at }); }
  const portMapHistory = store.all("SELECT observed_at,payload FROM events WHERE kind='network.port_map' ORDER BY observed_at,received_at LIMIT 2000").map(r => ({ ...parse(r.payload).details, observed_at: r.observed_at }));
  const since = new Date(now - 7 * 86400000).toISOString(), flows = [];
  for (const r of store.all("SELECT payload FROM events WHERE kind='log.batch' AND observed_at>=? LIMIT 5000", since)) for (const x of parse(r.payload).details.records || []) if (x.src_port === 67 && x.dst_port === 68) flows.push(x);
  const events = [...latest.values()], authorizedDhcp = [...new Set(events.flatMap(e => e.authorized_dhcp || []))];
  return { events, portMapHistory, flows, authorizedDhcp };
}
export function l2View(store, now = Date.now()) {
  const ev = l2Evidence(store, now), findings = correlateL2(ev);
  return { devices: ev.events.map(e => ({ device_ref: e.device_ref, hostname: e.hostname, observed_at: e.observed_at, features: e.features, signals: (e.signals || []).length })), authorized_dhcp: ev.authorizedDhcp, findings,
    summary: { corroborated: findings.filter(f => f.confidence === 'corroborated').length, single_signal: findings.filter(f => f.confidence === 'single-signal').length },
    claim: 'Feature states come from authorized read-only configuration exports. Rogue DHCP, MAC move and ARP conflict signals from one source are reported as needing corroboration, never as proof of an attack.',
    claim_ar: 'حالة الميزات من تصدير إعدادات مصرح به للقراءة فقط. وإشارات DHCP الدخيل وتنقل MAC وتعارض ARP من مصدر واحد تُعرض على أنها تحتاج تأكيدًا، ولا تُعد دليل هجوم.' };
}
