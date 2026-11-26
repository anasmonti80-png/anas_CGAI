// CG-137 Infrastructure management-plane audit. An authorized, read-only configuration export of a network device is
// compared with a baseline chosen by vendor and software version (NTP, AAA, TACACS+/RADIUS, SSH, SNMPv3, syslog,
// management access lists, local secrets and configuration backup). The owner can add organisation values (approved NTP,
// syslog, AAA servers and backup method). Controls that passed before and fail now are reported as regressions.
import { compareVersions } from './device-config.js';

export const AREAS = ['ntp', 'aaa', 'ssh', 'snmp', 'syslog', 'access', 'secrets', 'backup'];
export const AREA_AR = { ntp: 'NTP', aaa: 'AAA وTACACS+/RADIUS', ssh: 'SSH', snmp: 'SNMP', syslog: 'Syslog', access: 'قوائم الوصول الإدارية', secrets: 'الأسرار المحلية', backup: 'النسخ الاحتياطي للإعداد' };
// Baselines per vendor and version range. Type 8/9 secrets exist from IOS 15.3(3)M and in every IOS-XE 16+ release.
export const BASELINES = [
  { id: 'cisco-ios-xe-17', vendor: 'cisco', min: '17.0', max: null, strong_secret: true },
  { id: 'cisco-ios-xe-16', vendor: 'cisco', min: '16.0', max: '17.0', strong_secret: true },
  { id: 'cisco-ios-15', vendor: 'cisco', min: '15.0', max: '16.0', strong_secret: 'from-15.3' },
  { id: 'cisco-ios-legacy', vendor: 'cisco', min: '0', max: '15.0', strong_secret: false },
];
export function selectBaseline(vendor, version) { if (vendor !== 'cisco' || !version) return null; return BASELINES.find(b => b.vendor === vendor && compareVersions(version, b.min) >= 0 && (!b.max || compareVersions(version, b.max) < 0)) || null; }

export function parseMgmtConfig(textIn) {
  const lines = String(textIn).split(/\r?\n/), top = lines.filter(l => /^\S/.test(l)), all = re => top.map(l => l.match(re)).filter(Boolean);
  const blocks = (re) => { const out = []; let cur = null; for (const l of lines) { if (/^\S/.test(l)) { cur = re.test(l) ? { head: l, body: [] } : null; if (cur) out.push(cur); } else if (cur) cur.body.push(l.trim()); } return out; };
  const vty = blocks(/^line vty/), tacacs = blocks(/^tacacs server /).map(b => b.body.map(x => x.match(/^address ipv4 (\S+)/)?.[1]).find(Boolean)).filter(Boolean), radius = blocks(/^radius server /).map(b => b.body.map(x => x.match(/^address ipv4 (\S+)/)?.[1]).find(Boolean)).filter(Boolean);
  const archive = blocks(/^archive$/)[0];
  return {
    hostname: all(/^hostname (\S+)/)[0]?.[1] || null, version: all(/^version (\S+)/)[0]?.[1] || null,
    ntp_servers: [...new Set(all(/^ntp server (?:vrf \S+ )?(\S+)/).map(m => m[1]))], ntp_authenticate: top.includes('ntp authenticate'), ntp_trusted_key: top.some(l => /^ntp trusted-key \d+/.test(l)),
    aaa_new_model: top.includes('aaa new-model'), aaa_login: all(/^aaa authentication login default (.+)$/)[0]?.[1] || null, aaa_accounting: top.some(l => /^aaa accounting (commands 15|exec) /.test(l)),
    tacacs_servers: [...new Set([...tacacs, ...all(/^tacacs-server host (\S+)/).map(m => m[1])])], radius_servers: [...new Set([...radius, ...all(/^radius-server host (\S+)/).map(m => m[1])])],
    ssh_v2: top.includes('ip ssh version 2'), vty_transport: vty.map(b => (b.body.find(x => x.startsWith('transport input')) || 'transport input all').replace('transport input', '').trim()), vty_acl: vty.length > 0 && vty.every(b => b.body.some(x => /^access-class \S+ in/.test(x))),
    exec_timeout: vty.map(b => { const m = b.body.map(x => x.match(/^exec-timeout (\d+)(?: (\d+))?/)).find(Boolean); return m ? Number(m[1]) + Number(m[2] || 0) / 60 : 10; }), vty_count: vty.length,
    snmp_communities: all(/^snmp-server community (\S+)/).length, snmp_v3: all(/^snmp-server group \S+ v3 (\S+)/).map(m => m[1]), snmp_acl: top.filter(l => /^snmp-server (community|group)/.test(l)).every(l => /\saccess \S+|\s(RO|RW)\s+\S+\s*$/.test(l)),
    syslog_hosts: [...new Set(all(/^logging (?:host )?(\d+\.\d+\.\d+\.\d+)/).map(m => m[1]))], log_timestamps: top.some(l => /^service timestamps log datetime/.test(l)),
    enable_secret: (() => { const m = all(/^enable (?:algorithm-type (\S+) )?secret (?:(\d) )?/)[0]; if (!m) return top.some(l => /^enable password /.test(l)) ? 'password' : 'none'; return m[1] === 'scrypt' ? '9' : m[1] === 'sha256' ? '8' : m[1] === 'md5' ? '5' : m[2] || '5'; })(),
    password_encryption: top.includes('service password-encryption'), http_server: top.includes('ip http server'), login_block: top.some(l => /^login block-for /.test(l)),
    archive_path: archive?.body.map(x => x.match(/^path (\S+)/)?.[1]).find(Boolean) || null, archive_write: !!archive?.body.includes('write-memory'),
  };
}

const EXPECTED_AR = { 'ntp-servers': 'خادما NTP على الأقل', 'ntp-authentication': 'ntp authenticate مع مفتاح موثوق', 'aaa-new-model': 'aaa new-model', 'aaa-central-login': 'دخول عبر مجموعة TACACS+/RADIUS مع بديل محلي', 'aaa-servers': 'خادما TACACS+/RADIUS على الأقل', 'aaa-accounting': 'محاسبة الأوامر أو الجلسات', 'ssh-v2': 'ip ssh version 2', 'vty-ssh-only': 'transport input ssh على كل خطوط vty', 'vty-exec-timeout': 'exec-timeout خمس عشرة دقيقة أو أقل', 'management-acl': 'access-class على كل خطوط vty', 'http-server-off': 'no ip http server', 'login-block': 'login block-for', 'snmp-v3-priv': 'SNMPv3 مع التشفير فقط ودون سلاسل community', 'snmp-acl': 'قائمة وصول على كل community أو مجموعة SNMP', 'syslog-hosts': 'مضيف syslog بعيد واحد على الأقل', 'log-timestamps': 'service timestamps log datetime', 'password-encryption': 'service password-encryption', 'config-backup': 'مسار archive إلى موقع بعيد' };
const C = (id, area, severity, ok, expected, observed, title, title_ar) => ({ id, area, severity, status: ok === null ? 'not-applicable' : ok ? 'pass' : 'fail', expected, observed: String(observed), title, title_ar });
export function auditMgmtPlane(cfg, { vendor = 'cisco', version = null, org = {} } = {}) {
  const v = version || cfg.version, base = selectBaseline(vendor, v);
  if (!base) return { baseline: null, version: v, controls: [], score: null, reason: vendor !== 'cisco' ? `No management-plane baseline for vendor ${vendor} yet` : 'Software version unknown: the baseline cannot be chosen', reason_ar: vendor !== 'cisco' ? `لا يوجد خط أساس لمستوى الإدارة للمورّد ${vendor} بعد` : 'إصدار البرنامج غير معروف: لا يمكن اختيار خط الأساس' };
  const missing = (want, have) => (want || []).filter(x => !have.includes(x)), extra = (want, have) => want?.length ? have.filter(x => !want.includes(x)) : [];
  const strong = base.strong_secret === true || (base.strong_secret === 'from-15.3' && compareVersions(v, '15.3') >= 0), aaaServers = [...cfg.tacacs_servers, ...cfg.radius_servers];
  const controls = [
    C('ntp-servers', 'ntp', 'medium', cfg.ntp_servers.length >= 2 && !missing(org.ntp_servers, cfg.ntp_servers).length && !extra(org.ntp_servers, cfg.ntp_servers).length, org.ntp_servers?.length ? org.ntp_servers.join(', ') : 'at least 2 NTP servers', cfg.ntp_servers.join(', ') || 'none', 'NTP servers', 'خوادم NTP'),
    C('ntp-authentication', 'ntp', 'low', cfg.ntp_servers.length ? cfg.ntp_authenticate && cfg.ntp_trusted_key : null, 'ntp authenticate with a trusted key', cfg.ntp_authenticate ? (cfg.ntp_trusted_key ? 'on' : 'no trusted key') : 'off', 'NTP authentication', 'مصادقة NTP'),
    C('aaa-new-model', 'aaa', 'high', cfg.aaa_new_model, 'aaa new-model', cfg.aaa_new_model ? 'on' : 'off', 'AAA enabled', 'تفعيل AAA'),
    C('aaa-central-login', 'aaa', 'high', !!cfg.aaa_login && /group /.test(cfg.aaa_login) && /local/.test(cfg.aaa_login), 'login through a TACACS+/RADIUS group with local fallback', cfg.aaa_login || 'none', 'Central login with local fallback', 'دخول مركزي مع بديل محلي'),
    C('aaa-servers', 'aaa', 'medium', aaaServers.length >= 2 && !missing(org.aaa_servers, aaaServers).length, org.aaa_servers?.length ? org.aaa_servers.join(', ') : 'at least 2 TACACS+/RADIUS servers', aaaServers.join(', ') || 'none', 'Redundant AAA servers', 'خوادم AAA احتياطية'),
    C('aaa-accounting', 'aaa', 'medium', cfg.aaa_accounting, 'command or exec accounting', cfg.aaa_accounting ? 'on' : 'off', 'Administrative command accounting', 'محاسبة أوامر الإدارة'),
    C('ssh-v2', 'ssh', 'medium', cfg.ssh_v2, 'ip ssh version 2', cfg.ssh_v2 ? 'version 2' : 'not set', 'SSH version 2 only', 'SSH الإصدار 2 فقط'),
    C('vty-ssh-only', 'ssh', 'high', cfg.vty_count ? cfg.vty_transport.every(t => t === 'ssh' || t === 'none') : null, 'transport input ssh on every vty line', cfg.vty_transport.join(' | '), 'Remote management over SSH only', 'الإدارة عن بعد عبر SSH فقط'),
    C('vty-exec-timeout', 'access', 'low', cfg.vty_count ? cfg.exec_timeout.every(x => x > 0 && x <= 15) : null, 'exec-timeout of 15 minutes or less', cfg.exec_timeout.map(x => `${x} min`).join(' | '), 'Idle session timeout', 'مهلة الجلسة الخاملة'),
    C('management-acl', 'access', 'high', cfg.vty_count ? cfg.vty_acl : null, 'access-class on every vty line', cfg.vty_acl ? 'on' : 'missing', 'Management access list', 'قائمة وصول الإدارة'),
    C('http-server-off', 'access', 'medium', !cfg.http_server, 'no ip http server', cfg.http_server ? 'on' : 'off', 'Plain HTTP management off', 'إيقاف الإدارة عبر HTTP غير المشفر'),
    C('login-block', 'access', 'low', cfg.login_block, 'login block-for', cfg.login_block ? 'on' : 'off', 'Login brute-force protection', 'الحماية من تخمين الدخول'),
    C('snmp-v3-priv', 'snmp', 'high', cfg.snmp_communities || cfg.snmp_v3.length ? cfg.snmp_communities === 0 && cfg.snmp_v3.every(x => x === 'priv') : null, 'SNMPv3 with privacy only, no community strings', `${cfg.snmp_communities} communities; v3 ${cfg.snmp_v3.join(', ') || 'none'}`, 'SNMPv3 with encryption', 'SNMPv3 مع التشفير'),
    C('snmp-acl', 'snmp', 'medium', cfg.snmp_communities || cfg.snmp_v3.length ? cfg.snmp_acl : null, 'an access list on every SNMP community or group', cfg.snmp_acl ? 'on' : 'missing', 'SNMP access list', 'قائمة وصول SNMP'),
    C('syslog-hosts', 'syslog', 'high', cfg.syslog_hosts.length >= 1 && !missing(org.syslog_hosts, cfg.syslog_hosts).length, org.syslog_hosts?.length ? org.syslog_hosts.join(', ') : 'at least 1 remote syslog host', cfg.syslog_hosts.join(', ') || 'none', 'Logs sent off the device', 'إرسال السجلات خارج الجهاز'),
    C('log-timestamps', 'syslog', 'low', cfg.log_timestamps, 'service timestamps log datetime', cfg.log_timestamps ? 'on' : 'off', 'Timestamps on logs', 'طوابع زمنية للسجلات'),
    C('enable-secret', 'secrets', 'high', cfg.enable_secret === 'none' || cfg.enable_secret === 'password' ? false : strong ? ['8', '9'].includes(cfg.enable_secret) : ['5', '8', '9'].includes(cfg.enable_secret), strong ? `enable secret type 8 or 9 (supported by ${v})` : 'enable secret (type 5 is the strongest this version supports)', cfg.enable_secret === 'password' ? 'enable password (reversible)' : cfg.enable_secret === 'none' ? 'none' : `type ${cfg.enable_secret}`, 'Strong enable secret for this version', 'سر تمكين قوي لهذا الإصدار'),
    C('password-encryption', 'secrets', 'low', cfg.password_encryption, 'service password-encryption', cfg.password_encryption ? 'on' : 'off', 'Stored passwords obscured', 'إخفاء كلمات المرور المخزنة'),
    C('config-backup', 'backup', 'medium', org.backup === 'external' ? true : !!cfg.archive_path, org.backup === 'external' ? 'external backup declared by the owner' : 'archive path to a remote location', org.backup === 'external' ? 'external' : cfg.archive_path ? `${cfg.archive_path}${cfg.archive_write ? ' (write-memory)' : ''}` : 'none', 'Configuration backup', 'النسخ الاحتياطي للإعداد'),
  ];
  const listed = { 'ntp-servers': org.ntp_servers, 'aaa-servers': org.aaa_servers, 'syslog-hosts': org.syslog_hosts };
  for (const c of controls) c.expected_ar = listed[c.id]?.length ? listed[c.id].join('، ') : c.id === 'enable-secret' ? (strong ? `سر تمكين من النوع 8 أو 9 (يدعمه ${v})` : 'سر تمكين (النوع 5 أقوى ما يدعمه هذا الإصدار)') : c.id === 'config-backup' && org.backup === 'external' ? 'نسخ احتياطي خارجي صرّح به المالك' : EXPECTED_AR[c.id];
  const scored = controls.filter(c => c.status !== 'not-applicable');
  return { baseline: base.id, version: v, controls, score: scored.length ? Math.round(100 * scored.filter(c => c.status === 'pass').length / scored.length) : null };
}

// Controls that passed in the previous export and fail now.
export function regressions(prev, cur) { if (!prev) return []; const before = new Map(prev.controls.map(c => [c.id, c.status])); return cur.controls.filter(c => c.status === 'fail' && before.get(c.id) === 'pass'); }

export function mgmtView(store) {
  const by = new Map(); for (const r of store.all("SELECT observed_at,payload FROM events WHERE kind='network.mgmt_plane' ORDER BY observed_at,received_at")) { const d = JSON.parse(r.payload).details; by.set(d.device_ref, [...(by.get(d.device_ref) || []), { ...d, observed_at: r.observed_at }]); }
  const devices = [...by.values()].map(list => { const cur = list.at(-1), prev = list.at(-2) || null; return { ...cur, regressions: regressions(prev, cur).map(c => c.id), previous_at: prev?.observed_at || null }; });
  return { devices, baselines: BASELINES.map(b => b.id), areas: AREAS.map(a => ({ area: a, area_ar: AREA_AR[a] })),
    claim: 'Configuration is compared with a baseline for the device vendor and software version plus the owner\'s approved servers; nothing is changed on the device. Vendors without a baseline are shown as such.',
    claim_ar: 'يُقارن الإعداد بخط أساس حسب مورّد الجهاز وإصدار برنامجه مع الخوادم المعتمدة من المالك؛ ولا يُغيَّر شيء على الجهاز. والمورّدون بلا خط أساس يظهرون كذلك.' };
}
