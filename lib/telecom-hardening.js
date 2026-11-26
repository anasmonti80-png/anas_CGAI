// CG-140 Telecom / Salt Typhoon defensive study. Applies the CISA/NSA/FBI "Enhanced Visibility and Hardening Guidance
// for Communications Infrastructure" (4 December 2024) and joint advisory AA25-239A (August 2025) to authorized,
// read-only configuration exports of the organisation's own network devices (or carrier devices only with the carrier's
// written authorization). Hardening: Smart Install, web UI, Guest Shell, SSH on non-standard ports, off-box flow export.
// Actor techniques: undeclared traffic mirroring (SPAN/RSPAN/ERSPAN), undeclared GRE tunnels, ACL entries and static
// routes added between exports. Device syslog alone is not relied upon. Nothing is scanned.
export const REFERENCES = [
  { id: 'CISA/NSA/FBI Enhanced Visibility and Hardening Guidance for Communications Infrastructure', date: '2024-12-04', url: 'https://www.cisa.gov/resources-tools/resources/enhanced-visibility-and-hardening-guidance-communications-infrastructure' },
  { id: 'CISA AA25-239A Countering Chinese State-Sponsored Actors Compromise of Networks Worldwide', date: '2025-08-27', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a' },
];
// CVEs named in AA25-239A as exploited for initial access.
export const ADVISORY_CVES = [
  { cve: 'CVE-2018-0171', product: 'Cisco IOS / IOS XE Smart Install' }, { cve: 'CVE-2023-20198', product: 'Cisco IOS XE web UI' }, { cve: 'CVE-2023-20273', product: 'Cisco IOS XE web UI' },
  { cve: 'CVE-2024-3400', product: 'Palo Alto PAN-OS GlobalProtect' }, { cve: 'CVE-2023-46805', product: 'Ivanti Connect Secure' }, { cve: 'CVE-2024-21887', product: 'Ivanti Connect Secure' },
];
export const SCOPES = ['customer-owned', 'carrier-managed-authorized'];

export function parseTelecomConfig(textIn) {
  const lines = String(textIn).split(/\r?\n/).map(l => l.replace(/\s+$/, '')), top = lines.filter(l => /^\S/.test(l));
  const blocks = re => { const out = []; let cur = null; for (const l of lines) { if (/^\S/.test(l)) { cur = re.test(l) ? { head: l, body: [] } : null; if (cur) out.push(cur); } else if (cur) cur.body.push(l.trim()); } return out; };
  const tunnels = blocks(/^interface Tunnel\d+/i).map(b => ({ name: b.head.replace(/^interface /i, ''), mode: (b.body.find(x => /^tunnel mode /.test(x)) || 'tunnel mode gre ip').replace('tunnel mode ', ''), destination: b.body.map(x => x.match(/^tunnel destination (\S+)/)?.[1]).find(Boolean) || null })).filter(t => /gre/i.test(t.mode));
  const mirroring = [...new Set(top.map(l => l.match(/^monitor session (\d+)(?: type (\S+))?/)).filter(Boolean).map(m => `monitor session ${m[1]}${m[2] ? ` ${m[2]}` : ''}`))];
  const acl = []; let name = null; for (const l of lines) { let m; if ((m = l.match(/^ip access-list (?:extended|standard) (\S+)/))) { name = m[1]; continue; } if (/^\S/.test(l)) name = null; if ((m = l.match(/^access-list (\S+) (permit|deny) (.+)$/))) acl.push(`${m[1]}: ${m[2]} ${m[3].trim()}`); else if (name && (m = l.trim().match(/^(?:\d+ )?(permit|deny) (.+)$/))) acl.push(`${name}: ${m[1]} ${m[2].trim()}`); }
  return {
    hostname: top.map(l => l.match(/^hostname (\S+)/)?.[1]).find(Boolean) || null,
    switch: lines.some(l => /^\s*switchport/.test(l)), smart_install_disabled: top.includes('no vstack'), smart_install_enabled: top.includes('vstack'),
    http_server: top.includes('ip http server'), https_server: top.includes('ip http secure-server'), guest_shell: top.some(l => /^(iox|guestshell|app-hosting appid guestshell)/.test(l)),
    ssh_ports: [...new Set(top.map(l => l.match(/^ip ssh port (\d+)/)?.[1]).filter(Boolean).map(Number))], flow_export: top.some(l => /^(flow exporter |ip flow-export destination |sampler |flow monitor )/.test(l)),
    tunnels, mirroring, acl: [...new Set(acl)], static_routes: [...new Set(top.filter(l => /^ip route /.test(l)))],
  };
}

const DETAIL_AR = { 'no "no vstack" line': 'لا يوجد سطر no vstack', 'vstack is enabled': 'vstack مفعّل', 'Monitor container logs and AAA command accounting': 'راقب سجلات الحاوية ومحاسبة أوامر AAA', 'Undeclared non-standard SSH ports are reported in AA25-239A': 'منافذ SSH غير القياسية غير المصرّح بها مذكورة في النشرة AA25-239A', 'Do not rely on device syslog alone; export flows to an off-box collector': 'لا تعتمد على syslog الجهاز وحده؛ صدّر التدفقات إلى مجمّع خارج الجهاز', 'SPAN/RSPAN/ERSPAN on compromised devices is reported in AA25-239A': 'نسخ الحركة SPAN/RSPAN/ERSPAN على الأجهزة المخترقة مذكور في النشرة AA25-239A' };
const F = (id, kind, severity, title, title_ar, detail) => ({ id, kind, severity, title, title_ar, detail, detail_ar: DETAIL_AR[detail] || detail });
export function assessTelecom(cfg, { declared = {}, previous = null } = {}) {
  const out = [], dm = declared.mirroring || [], dt = declared.tunnels || [], dp = declared.ssh_ports || [];
  if (cfg.switch && !cfg.smart_install_disabled) out.push(F('smart-install-not-disabled', 'hardening', 'high', 'Smart Install is not disabled (no vstack missing): CVE-2018-0171 is exploited by these actors', 'Smart Install غير معطّل (ينقص no vstack): الثغرة CVE-2018-0171 يستغلها هؤلاء المهاجمون', cfg.smart_install_enabled ? 'vstack is enabled' : 'no "no vstack" line'));
  if (cfg.http_server || cfg.https_server) out.push(F('web-ui-enabled', 'hardening', 'high', 'The device web UI is enabled: CVE-2023-20198 and CVE-2023-20273 target it', 'واجهة الويب للجهاز مفعّلة: تستهدفها الثغرتان CVE-2023-20198 وCVE-2023-20273', [cfg.http_server && 'ip http server', cfg.https_server && 'ip http secure-server'].filter(Boolean).join(', ')));
  if (cfg.guest_shell && !declared.guest_shell) out.push(F('guest-shell-enabled', 'hardening', 'medium', 'Guest Shell / IOx is enabled without being declared: actors use it to evade monitoring', 'Guest Shell أو IOx مفعّل دون تصريح: يستخدمه المهاجمون للتهرب من المراقبة', 'Monitor container logs and AAA command accounting'));
  for (const p of cfg.ssh_ports.filter(p => p !== 22 && !dp.includes(p))) out.push(F(`ssh-nonstandard-port:${p}`, 'hardening', 'medium', `SSH listens on non-standard port ${p}`, `SSH يستمع على منفذ غير قياسي ${p}`, 'Undeclared non-standard SSH ports are reported in AA25-239A'));
  if (!cfg.flow_export) out.push(F('no-off-box-flow-export', 'visibility', 'low', 'No flow telemetry is exported off the device', 'لا يُصدَّر قياس التدفقات خارج الجهاز', 'Do not rely on device syslog alone; export flows to an off-box collector'));
  for (const m of cfg.mirroring.filter(m => !dm.includes(m))) out.push(F(`undeclared-mirroring:${m}`, 'technique', 'high', `Undeclared traffic mirroring: ${m}`, `نسخ حركة غير مصرّح به: ${m}`, 'SPAN/RSPAN/ERSPAN on compromised devices is reported in AA25-239A'));
  for (const t of cfg.tunnels.filter(t => !dt.includes(t.name))) out.push(F(`undeclared-gre:${t.name}`, 'technique', 'high', `Undeclared GRE tunnel ${t.name}${t.destination ? ` to ${t.destination}` : ''}`, `نفق GRE غير مصرّح به ${t.name}${t.destination ? ` إلى ${t.destination}` : ''}`, t.mode));
  if (previous) {
    const addedAcl = cfg.acl.filter(a => !previous.acl.includes(a) && /permit/.test(a)), addedRoutes = cfg.static_routes.filter(r => !previous.static_routes.includes(r));
    if (addedAcl.length) out.push(F('acl-entries-added', 'technique', 'high', `${addedAcl.length} permit entr${addedAcl.length === 1 ? 'y' : 'ies'} added to access lists since the previous export`, `أُضيف ${addedAcl.length} سطر سماح إلى قوائم الوصول منذ التصدير السابق`, addedAcl.slice(0, 10).join(' | ')));
    if (addedRoutes.length) out.push(F('static-routes-added', 'technique', 'medium', `${addedRoutes.length} static route(s) added since the previous export`, `أُضيف ${addedRoutes.length} مسار ثابت منذ التصدير السابق`, addedRoutes.slice(0, 10).join(' | ')));
  }
  return out;
}

export function telecomView(store) {
  const by = new Map(); for (const r of store.all("SELECT observed_at,payload FROM events WHERE kind='network.telecom_hardening' ORDER BY observed_at,received_at")) { const d = JSON.parse(r.payload).details; by.set(d.device_ref, [...(by.get(d.device_ref) || []), { ...d, observed_at: r.observed_at }]); }
  return { devices: [...by.values()].map(l => { const cur = l.at(-1), prev = l.at(-2) || null; return { ...cur, exports: l.length, previous_at: prev?.observed_at || null, findings: assessTelecom(cur.config, { declared: cur.declared, previous: prev?.config || null }) }; }), references: REFERENCES, advisory_cves: ADVISORY_CVES,
    claim: 'Built from authorized read-only exports of the organisation\'s own devices, or carrier devices with the carrier\'s written authorization. Public operators and carrier equipment are never scanned. Device syslog alone is not trusted: AAA command accounting and off-box flow telemetry are required.',
    claim_ar: 'مبني على تصديرات مصرّح بها للقراءة فقط من أجهزة الجهة نفسها، أو أجهزة المشغّل بتصريح مكتوب منه. لا يُفحص أي مشغّل عمومي أو معدات اتصالات أبدًا. ولا يُعتمد على syslog الجهاز وحده: محاسبة أوامر AAA وتصدير التدفقات خارج الجهاز مطلوبان.' };
}
