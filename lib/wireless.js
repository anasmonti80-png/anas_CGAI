// CG-136 Wireless and guest network assurance from an authorized wireless controller export: SSID inventory with
// security (open, PSK, WPA2/WPA3 Enterprise), 802.1X and RADIUS, management frame protection, guest isolation and guest
// VLAN separation; rogue AP signals the controller already collected; and the RF coverage limits of those signals.
// Nothing is transmitted: no deauthentication, containment or active wireless testing.
const mac = m => String(m || '').toLowerCase().replace(/[^0-9a-f]/g, '').replace(/(..)(?!$)/g, '$1:');
const GUEST = /guest|visitor|public|ضيوف|زوار/i;

// Cisco Catalyst 9800 running configuration.
export function parseWlcConfig(textIn) {
  const out = { wlans: [], policies: new Map(), tags: [], aaa: new Map(), radiusGroups: new Map(), radiusServers: [], hostname: null }; let cur = null, mode = null;
  for (const raw of String(textIn).split(/\r?\n/)) {
    const l = raw.replace(/\s+$/, ''), t = l.trim(); let m;
    if (/^\S/.test(l)) { cur = null; mode = null; }
    if ((m = l.match(/^hostname (\S+)/))) out.hostname = m[1];
    else if ((m = l.match(/^wlan (\S+) (\d+) (.+)$/))) { cur = { profile: m[1], id: Number(m[2]), ssid: m[3].trim(), lines: [] }; out.wlans.push(cur); mode = 'wlan'; continue; }
    else if ((m = l.match(/^wireless profile policy (\S+)/))) { cur = { name: m[1], vlan: null }; out.policies.set(m[1], cur); mode = 'policy'; continue; }
    else if ((m = l.match(/^wireless tag policy (\S+)/))) { mode = 'tag'; continue; }
    else if ((m = l.match(/^aaa authentication dot1x (\S+) group (\S+)/))) out.aaa.set(m[1], m[2]);
    else if ((m = l.match(/^aaa group server radius (\S+)/))) { cur = { name: m[1], servers: [] }; out.radiusGroups.set(m[1], cur); mode = 'radius-group'; continue; }
    else if ((m = l.match(/^radius server (\S+)/))) { out.radiusServers.push(m[1]); continue; }
    if (mode === 'wlan' && cur) cur.lines.push(t);
    else if (mode === 'policy' && cur && (m = t.match(/^vlan (\S+)/))) cur.vlan = m[1];
    else if (mode === 'tag' && (m = t.match(/^wlan (\S+) policy (\S+)/))) out.tags.push({ wlan: m[1], policy: m[2] });
    else if (mode === 'radius-group' && cur && (m = t.match(/^server name (\S+)/))) cur.servers.push(m[1]);
  }
  return out;
}

export function assessWlans(cfg) {
  const ssids = cfg.wlans.map(w => {
    const has = re => w.lines.some(x => re.test(x)), no = re => w.lines.some(x => new RegExp(`^no ${re.source.replace(/^\^/, '')}`).test(x));
    const wpaOff = has(/^no security wpa$/), wpa2 = !wpaOff && !no(/^security wpa wpa2$/), wpa3 = !wpaOff && has(/^security wpa wpa3$/);
    const dot1x = !wpaOff && !no(/^security wpa akm dot1x$/) && !has(/^security wpa akm psk$/) && !has(/^security wpa akm sae$/), psk = !wpaOff && (has(/^security wpa akm psk$/) || has(/^security wpa akm sae$/));
    const webAuth = has(/^security web-auth/), aaaList = w.lines.map(x => x.match(/^security dot1x authentication-list (\S+)/)?.[1]).find(Boolean) || null;
    const policy = cfg.tags.find(tg => tg.wlan === w.profile)?.policy || null, vlan = policy ? cfg.policies.get(policy)?.vlan ?? null : null;
    const group = aaaList ? cfg.aaa.get(aaaList) : null, servers = group ? cfg.radiusGroups.get(group)?.servers.length ?? 0 : 0;
    const security = wpaOff ? (webAuth ? 'open-web-auth' : 'open') : `${wpa3 && wpa2 ? 'wpa2-wpa3' : wpa3 ? 'wpa3' : 'wpa2'}-${dot1x ? 'enterprise' : psk ? 'personal' : 'unknown'}`;
    return { profile: w.profile, ssid: w.ssid, enabled: !has(/^shutdown$/), security, guest: GUEST.test(w.ssid) || GUEST.test(w.profile) || webAuth, aaa_list: aaaList, radius_servers: servers,
      pmf: has(/^security pmf mandatory$/) ? 'mandatory' : has(/^security pmf optional$/) ? 'optional' : 'off', peer_blocking: has(/^peer-blocking (drop|forward-upstream)$/), vlan, policy };
  });
  const findings = [], f = (id, severity, title, title_ar, subject) => findings.push({ id: `${id}:${subject}`, severity, title, title_ar, subject });
  const corpVlans = new Set(ssids.filter(s => !s.guest && s.vlan).map(s => s.vlan));
  for (const s of ssids.filter(x => x.enabled)) {
    if (!s.guest && s.security.startsWith('open')) f('wifi-open-corporate', 'high', `Corporate SSID ${s.ssid} is open`, `الشبكة اللاسلكية للمؤسسة ${s.ssid} مفتوحة`, s.ssid);
    if (!s.guest && s.security.endsWith('-personal')) f('wifi-psk-corporate', 'medium', `Corporate SSID ${s.ssid} uses a shared key instead of 802.1X`, `الشبكة اللاسلكية للمؤسسة ${s.ssid} تستخدم مفتاحًا مشتركًا بدل 802.1X`, s.ssid);
    if (s.security.endsWith('-enterprise') && !s.security.includes('wpa3')) f('wifi-no-wpa3', 'low', `SSID ${s.ssid} offers WPA2 only`, `الشبكة ${s.ssid} تقدم WPA2 فقط`, s.ssid);
    if (s.security.includes('wpa3') && s.pmf !== 'mandatory') f('wifi-pmf-not-mandatory', 'low', `SSID ${s.ssid} uses WPA3 without mandatory management frame protection`, `الشبكة ${s.ssid} تستخدم WPA3 دون حماية إطارات الإدارة الإلزامية`, s.ssid);
    if (s.security.endsWith('-enterprise') && (!s.aaa_list || !cfg.aaa.has(s.aaa_list))) f('wifi-aaa-missing', 'high', `SSID ${s.ssid} uses 802.1X without a defined authentication list`, `الشبكة ${s.ssid} تستخدم 802.1X دون قائمة مصادقة معرّفة`, s.ssid);
    else if (s.security.endsWith('-enterprise') && s.radius_servers < 2) f('wifi-radius-single', 'low', `SSID ${s.ssid} depends on ${s.radius_servers} RADIUS server`, `الشبكة ${s.ssid} تعتمد على ${s.radius_servers} خادم RADIUS`, s.ssid);
    if (s.guest && !s.peer_blocking) f('wifi-guest-no-isolation', 'medium', `Guest SSID ${s.ssid} lets clients reach each other (no peer blocking)`, `شبكة الضيوف ${s.ssid} تسمح بوصول العملاء لبعضهم (دون عزل)`, s.ssid);
    if (s.guest && s.vlan && corpVlans.has(s.vlan)) f('wifi-guest-shares-vlan', 'high', `Guest SSID ${s.ssid} shares VLAN ${s.vlan} with a corporate SSID`, `شبكة الضيوف ${s.ssid} تشارك VLAN ${s.vlan} مع شبكة المؤسسة`, s.ssid);
  }
  return { ssids, findings };
}

// Rogue APs from the controller (normalized JSON), joined with switch MAC tables. A rogue broadcasting one of our SSIDs
// over the air is one signal; the same radio found on our wired network is an independent second one.
export function assessRogues({ rogues = [], ssids = [], portMaps = [], aps = [] }) {
  const ours = new Set(ssids.map(s => s.ssid)), wired = portMaps.flatMap(m => (m.mac_table || []).filter(e => !/^(Po|Vl|CPU)/i.test(e.interface)).map(e => ({ mac: e.mac, switch: m.switch_ref, interface: e.interface, mode: (m.switchports || []).find(p => p.interface === e.interface)?.mode || null })));
  const near = b => { const x = mac(b); return wired.find(w => w.mac.slice(0, 15) === x.slice(0, 15) && Math.abs(parseInt(w.mac.slice(15), 16) - parseInt(x.slice(15), 16)) <= 16); };
  const items = rogues.map(r => {
    const bssid = mac(r.bssid), impersonating = r.ssid && ours.has(r.ssid), w = near(bssid), sources = [...(impersonating ? ['rf-ssid-match'] : []), ...(w ? ['wired-match'] : [])];
    const kind = impersonating && w ? 'rogue-on-network-impersonating' : w ? 'rogue-on-network' : impersonating ? 'ssid-impersonation' : 'neighbour';
    const confidence = sources.length >= 2 ? 'corroborated' : sources.length === 1 ? 'single-signal' : 'none';
    const severity = kind === 'neighbour' ? null : confidence === 'corroborated' ? 'high' : kind === 'rogue-on-network' ? 'medium' : 'low';
    return { bssid, ssid: r.ssid || null, rssi: r.rssi ?? null, channel: r.channel ?? null, clients: r.clients ?? 0, detected_by: r.detected_by || [], last_heard: r.last_heard || null, kind, sources, confidence, severity, wired: w || null,
      note: kind === 'neighbour' ? 'Another SSID not seen on our wired network: most likely a neighbour' : kind === 'ssid-impersonation' ? 'Broadcasts one of our SSIDs but is not on our wired network: possible evil twin, needs corroboration (could be a misconfigured AP of a neighbour)' : 'Seen on our wired network by an adjacent MAC address',
      note_ar: kind === 'neighbour' ? 'شبكة أخرى غير مرصودة على شبكتنا السلكية: غالبًا جار' : kind === 'ssid-impersonation' ? 'تبث إحدى شبكاتنا وليست على شبكتنا السلكية: توأم شرير محتمل يحتاج تأكيدًا (قد تكون نقطة جار مضبوطة خطأً)' : 'مرصودة على شبكتنا السلكية بعنوان MAC متجاور' };
  });
  const sites = [...new Set(aps.map(a => a.site).filter(Boolean))], scanning = aps.filter(a => a.rogue_detection !== false && a.mode !== 'sniffer');
  const coverage = { aps: aps.length, scanning_aps: scanning.length, blind_sites: sites.filter(s => !scanning.some(a => a.site === s)),
    limits: 'Rogue detection only covers the air around managed APs that scan; a site without scanning APs, a channel or band the APs do not scan, and radios out of range are not seen. No active wireless testing is done.',
    limits_ar: 'كشف النقاط الدخيلة يغطي فقط محيط نقاط الوصول المُدارة التي تمسح؛ الموقع الخالي من نقاط ماسحة، والقنوات أو النطاقات غير الممسوحة، والأجهزة خارج المدى لا تُرى. ولا يُجرى أي اختبار لاسلكي نشط.' };
  return { rogues: items, coverage };
}

// Latest export per controller with rogue signals joined to the current switch port maps.
export function wirelessView(store, portMaps) {
  const latest = new Map(); for (const r of store.all("SELECT observed_at,payload FROM events WHERE kind='wireless.assurance' ORDER BY observed_at,received_at")) { const d = JSON.parse(r.payload).details; latest.set(d.controller_ref, { ...d, observed_at: r.observed_at }); }
  const controllers = [...latest.values()].map(c => ({ ...c, ...assessRogues({ rogues: c.rogues, ssids: c.ssids, portMaps, aps: c.aps }) }));
  return { controllers, claim: 'From authorized read-only controller exports. Rogue APs are signals the controller already collected; one seen on our wired network and broadcasting our SSID is corroborated, one only heard over the air needs corroboration. No active wireless testing.',
    claim_ar: 'من تصدير متحكمات مصرح به للقراءة فقط. النقاط الدخيلة إشارات جمعها المتحكم؛ والمرصودة على شبكتنا السلكية وتبث شبكتنا مؤكدة، والمسموعة هوائيًّا فقط تحتاج تأكيدًا. ولا يُجرى أي اختبار لاسلكي نشط.' };
}
