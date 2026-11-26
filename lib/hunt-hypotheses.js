// CG-143 Hypothesis-based threat hunting. A library of hunts per stage (initial access, persistence, lateral movement,
// exfiltration). Each states the data it needs, a safe declarative query run by the CG-116 hunt workbench (no free-form
// SQL), legitimate cases that are excluded and why, and the retention it needs. The result is one of: found (rows that
// survive the exclusions), not found with sufficient visibility, or insufficient visibility (missing sources or retention
// shorter than the hunt window), so an empty result is never presented as "no threat" when the data is not there.
import { fail, text, integer } from './common.js';

const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fc|fd|fe80)/i;
const UPDATERS = /(googleupdate|microsoftedgeupdate|edgeupdate|adobearm|onedrive|teams|zoom|mozillamaintenance|dell|hp|lenovo)/i;
export const STAGES = { 'initial-access': ['الوصول الأولي', 'Initial access'], persistence: ['الاستمرار', 'Persistence'], 'lateral-movement': ['التنقل الجانبي', 'Lateral movement'], exfiltration: ['تهريب البيانات', 'Exfiltration'] };
export const LIBRARY = [
  { id: 'H-IA-01', stage: 'initial-access', title: 'Password guessing followed by a successful logon', title_ar: 'تخمين كلمات المرور يليه دخول ناجح', attack: ['T1110', 'T1078'], retention_days: 14,
    data: [{ label: 'Failed logons', label_ar: 'محاولات الدخول الفاشلة', kinds: ['auth.failed', 'identity.signin_activity'] }, { label: 'Successful logons', label_ar: 'الدخول الناجح', kinds: ['identity.signin_activity', 'remote.authenticated'] }],
    query: { entity: 'account' }, exclusions: [['Users mistyping after a password change (fewer than 5 failures)', 'مستخدمون يخطئون بعد تغيير كلمة المرور (أقل من 5 محاولات)'], ['Service accounts with a stale stored password from internal addresses', 'حسابات خدمة بكلمة مرور قديمة مخزنة من عناوين داخلية']],
    select: rows => { const by = new Map(); for (const r of rows) { const k = `${String(r.account || '').toLowerCase()}|${r.ip || ''}`; const g = by.get(k) || { fail: 0, success: null, rows: [] }; if (r.outcome === 'failure') g.fail++; else if (r.outcome === 'success' || /authenticated/.test(r.kind || '')) g.success = g.success || r; g.rows.push(r); by.set(k, g); } return [...by.values()].filter(g => g.fail >= 5 && g.success && !(PRIVATE.test(g.success.ip || '') && /^svc[-_]/i.test(g.success.account || ''))).map(g => ({ ...g.success, summary: `${g.fail} failures then success: ${g.success.summary}` })); } },
  { id: 'H-IA-02', stage: 'initial-access', title: 'Remote administration session from the internet', title_ar: 'جلسة إدارة عن بعد من الإنترنت', attack: ['T1133', 'T1021'], retention_days: 30,
    data: [{ label: 'Remote session logs', label_ar: 'سجلات الجلسات عن بعد', kinds: ['remote.authenticated', 'remote.active'] }], query: { entity: 'movement' },
    exclusions: [['Sessions through the approved VPN or jump host addresses', 'الجلسات عبر عناوين VPN أو الخادم الوسيط المعتمد'], ['Vendor relays already reviewed in CG-141', 'وسطاء المورّدين المراجعون في CG-141']],
    select: (rows, x) => rows.filter(r => /authenticated|active/.test(r.kind) && r.ip && !PRIVATE.test(r.ip) && !(x.approved_sources || []).includes(r.ip)) },
  { id: 'H-P-01', stage: 'persistence', title: 'New service or scheduled task outside known updaters', title_ar: 'خدمة أو مهمة مجدولة جديدة خارج برامج التحديث المعروفة', attack: ['T1543.003', 'T1053.005'], retention_days: 30,
    data: [{ label: 'Process causality with service and task changes', label_ar: 'سلسلة العمليات مع تغييرات الخدمات والمهام', kinds: ['endpoint.process_causality'] }], query: { entity: 'change', filters: { contains: 'created' } },
    exclusions: [['Signed vendor updaters (Google, Edge, Adobe, OneDrive, Teams, Zoom, OEM tools)', 'برامج التحديث الموقعة من المورّدين (Google وEdge وAdobe وOneDrive وTeams وZoom وأدوات الشركات المصنعة)'], ['Changes inside an approved change window', 'التغييرات ضمن نافذة تغيير معتمدة']],
    select: rows => rows.filter(r => /^(service|task) /.test(r.summary) && !UPDATERS.test(r.summary)) },
  { id: 'H-P-02', stage: 'persistence', title: 'Mailbox forwarding to an external domain', title_ar: 'تحويل البريد إلى نطاق خارجي', attack: ['T1114.003'], retention_days: 90,
    data: [{ label: 'Mailbox rule and forwarding audit', label_ar: 'تدقيق قواعد البريد والتحويل', kinds: ['email.forwarding_change'] }], query: { entity: 'change', filters: { contains: 'to ' } },
    exclusions: [['Forwarding to approved partner domains', 'التحويل إلى نطاقات شركاء معتمدة']],
    select: (rows, x) => rows.filter(r => r.change === 'mail-forwarding' && !(x.forwarding_domains || []).some(d => r.summary.toLowerCase().includes(d.toLowerCase()))) },
  { id: 'H-LM-01', stage: 'lateral-movement', title: 'Administrative protocols between internal hosts not from a jump host', title_ar: 'بروتوكولات إدارية بين أجهزة داخلية من غير الخادم الوسيط', attack: ['T1021.001', 'T1021.002', 'T1021.006'], retention_days: 14,
    data: [{ label: 'Internal flow or firewall logs', label_ar: 'سجلات التدفق أو الجدار الناري الداخلية', kinds: ['log.batch'] }], query: { entity: 'movement' },
    exclusions: [['Approved jump hosts and management networks', 'الخوادم الوسيطة وشبكات الإدارة المعتمدة'], ['Domain controller to domain controller replication (RPC/SMB)', 'التكرار بين وحدات التحكم بالدليل (RPC/SMB)']],
    select: (rows, x) => rows.filter(r => r.kind === 'log.batch' && !(x.jump_hosts || []).includes(r.ip)) },
  { id: 'H-LM-02', stage: 'lateral-movement', title: 'One account authenticating to three or more hosts in an hour', title_ar: 'حساب واحد يدخل إلى ثلاثة أجهزة أو أكثر خلال ساعة', attack: ['T1078', 'T1021'], retention_days: 14,
    data: [{ label: 'Remote session logs', label_ar: 'سجلات الجلسات عن بعد', kinds: ['remote.authenticated'] }], query: { entity: 'account' },
    exclusions: [['Helpdesk and administrator accounts working from the jump host', 'حسابات الدعم والمديرين العاملة من الخادم الوسيط']],
    select: (rows, x) => { const out = []; const by = new Map(); for (const r of rows.filter(r => /authenticated/.test(r.kind) && r.account && !(x.admin_accounts || []).includes(r.account.toLowerCase()))) by.set(r.account.toLowerCase(), [...(by.get(r.account.toLowerCase()) || []), r]);
      for (const [acct, list] of by) for (const r of list) { const hosts = new Set(list.filter(y => Math.abs(Date.parse(y.time) - Date.parse(r.time)) <= 3600000).map(y => y.host)); if (hosts.size >= 3) { out.push({ ...r, summary: `${acct} on ${hosts.size} hosts within an hour: ${[...hosts].join(', ')}` }); break; } } return out; } },
  { id: 'H-EX-01', stage: 'exfiltration', title: 'Large outbound transfer to an internet address', title_ar: 'نقل كبير إلى عنوان على الإنترنت', attack: ['T1048', 'T1567'], retention_days: 30,
    data: [{ label: 'Flow logs with byte counts', label_ar: 'سجلات التدفق مع عدد البايتات', kinds: ['log.batch'] }], query: { entity: 'connection' },
    exclusions: [['Approved backup and cloud sync destinations', 'وجهات النسخ الاحتياطي والمزامنة السحابية المعتمدة'], ['Software update downloads (inbound, not outbound)', 'تنزيلات التحديثات (واردة لا صادرة)']],
    select: (rows, x) => rows.filter(r => r.dst_ip && !PRIVATE.test(r.dst_ip) && PRIVATE.test(r.ip || '') && (r.bytes || 0) >= (x.bytes_threshold || 500000000) && !(x.backup_destinations || []).includes(r.dst_ip)) },
  { id: 'H-EX-02', stage: 'exfiltration', title: 'Server process connecting out to an internet address', title_ar: 'عملية على خادم تتصل بعنوان على الإنترنت', attack: ['T1041', 'T1071'], retention_days: 30,
    data: [{ label: 'Process causality with connections', label_ar: 'سلسلة العمليات مع الاتصالات', kinds: ['endpoint.process_causality'] }], query: { entity: 'connection' },
    exclusions: [['Signed updaters and security agents contacting their vendor', 'برامج التحديث الموقعة ووكلاء الحماية التي تتصل بمورّدها'], ['Approved proxies', 'الوكلاء (proxy) المعتمدون']],
    select: rows => rows.filter(r => r.kind === 'endpoint.process_causality' && r.dst_ip && !PRIVATE.test(r.dst_ip) && !UPDATERS.test(r.process || '') && /\\(powershell|pwsh|cmd|rundll32|regsvr32|mshta|certutil|bitsadmin|curl|wget)\.exe$/i.test(r.process || '')) },
];

export class HuntHypotheses {
  constructor(store, { workbench, clock }) { Object.assign(this, { s: store, wb: workbench, clock: clock || (() => Date.now()) }); }
  visibility(h, from, to) {
    return h.data.map(src => { const inWin = this.s.get(`SELECT COUNT(*) n FROM events WHERE kind IN (${src.kinds.map(() => '?').join(',')}) AND observed_at BETWEEN ? AND ?`, ...src.kinds, from, to).n, oldest = this.s.get(`SELECT MIN(observed_at) t FROM events WHERE kind IN (${src.kinds.map(() => '?').join(',')})`, ...src.kinds).t;
      const needed = new Date(this.clock() - h.retention_days * 86400000).toISOString();
      return { label: src.label, label_ar: src.label_ar, kinds: src.kinds, events_in_window: inWin, oldest: oldest || null, retention_ok: !!oldest && oldest <= needed, state: !inWin ? 'missing' : oldest > needed ? 'short-retention' : 'ok' }; });
  }
  list() { const to = new Date(this.clock()).toISOString(); return LIBRARY.map(h => { const from = new Date(this.clock() - h.retention_days * 86400000).toISOString(), v = this.visibility(h, from, to); return { ...this.describe(h), visibility: v, ready: v.every(x => x.state !== 'missing') }; }); }
  describe(h) { return { id: h.id, stage: h.stage, stage_label: STAGES[h.stage], title: h.title, title_ar: h.title_ar, attack: h.attack, retention_days: h.retention_days, data: h.data, query: h.query, exclusions: h.exclusions.map(([en, ar]) => ({ en, ar })) }; }
  run(id, input = {}) {
    const h = LIBRARY.find(x => x.id === id); fail(h, 404, 'hunt_hypothesis_not_found');
    const days = integer(input.days ?? h.retention_days, 1, 90, 'hunt_days'), to = new Date(this.clock()).toISOString(), from = new Date(this.clock() - days * 86400000).toISOString();
    const list = (k, max = 50) => { const v = input.exclusions?.[k]; if (v === undefined) return []; fail(Array.isArray(v) && v.length <= max, 400, `invalid_hunt_exclusion_${k}`); return v.map(x => text(String(x), `hunt_exclusion_${k}`, 200).toLowerCase()); };
    const x = { approved_sources: list('approved_sources'), forwarding_domains: list('forwarding_domains'), jump_hosts: list('jump_hosts'), admin_accounts: list('admin_accounts'), backup_destinations: list('backup_destinations'), bytes_threshold: input.exclusions?.bytes_threshold === undefined ? undefined : integer(input.exclusions.bytes_threshold, 1000000, 1e13, 'hunt_bytes_threshold') };
    const r = this.wb.run({ ...h.query, from, to, limit: 5000 }), rows = h.select(r.rows, x), visibility = this.visibility(h, from, to);
    const missing = visibility.filter(v => v.state === 'missing'), short = visibility.filter(v => v.state === 'short-retention');
    const outcome = rows.length ? 'found' : missing.length ? 'insufficient-visibility' : 'not-found';
    return { hypothesis: this.describe(h), window: { from, to, days }, outcome, partial_window: short.length > 0, rows: rows.slice(0, 200), total: rows.length, visibility, query_sha256: r.result_sha256, ran_at: to,
      verdict: outcome === 'found' ? `${rows.length} row(s) match after the exclusions; review them before concluding` : outcome === 'not-found' ? `Not found in ${days} days with the required data present${short.length ? '; retention is shorter than the hunt window for some sources' : ''}` : `Visibility is insufficient: no ${missing.map(m => m.label).join(', ')} in the window; the absence of results proves nothing`,
      verdict_ar: outcome === 'found' ? `${rows.length} نتيجة بعد الاستثناءات؛ راجعها قبل الاستنتاج` : outcome === 'not-found' ? `لم يُعثر على شيء خلال ${days} يومًا مع توفر البيانات المطلوبة${short.length ? '؛ ومدة الاحتفاظ أقصر من نافذة الصيد لبعض المصادر' : ''}` : `الرؤية غير كافية: لا توجد ${missing.map(m => m.label_ar).join('، ')} في النافذة؛ وغياب النتائج لا يثبت شيئًا` };
  }
}
