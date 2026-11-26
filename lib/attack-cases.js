// CG-139 Multi-signal attack case: SharePoint "ToolShell" (2025). One case per SharePoint server joins independent
// evidence: internet exposure, a vulnerable SharePoint build for the ToolShell CVEs, POST requests to ToolPane.aspx,
// a web-shell file or signature finding, w3wp.exe starting a shell, a protection change, a new scheduled task or a
// policy (GPO) change. A file signature on its own is never proof; the case is never marked confirmed automatically.
// Sources: Microsoft Security Blog, 22 July 2025 ("Disrupting active exploitation of on-premises SharePoint
// vulnerabilities"); MSRC guidance of 19 July 2025; Canadian Centre for Cyber Security (a missing spinstall0.aspx does
// not rule out compromise).
const parse = s => JSON.parse(s);
export const TOOLSHELL = {
  id: 'toolshell-2025', rule: 'CG-TOOLSHELL-139', title: 'SharePoint ToolShell (2025)', title_ar: 'ثغرة ToolShell في SharePoint (2025)',
  cves: ['CVE-2025-53770', 'CVE-2025-53771', 'CVE-2025-49704', 'CVE-2025-49706'],
  references: [
    { title: 'Microsoft Security Blog, 22 July 2025: Disrupting active exploitation of on-premises SharePoint vulnerabilities', url: 'https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/' },
    { title: 'Canadian Centre for Cyber Security: Threat detection for SharePoint vulnerabilities', url: 'https://cyber.gc.ca/en/news-events/threat-detection-sharepoint-vulnerabilities' },
  ],
  steps: [
    ['Apply the SharePoint security updates for CVE-2025-53770 and CVE-2025-53771', 'ثبّت تحديثات SharePoint الأمنية للثغرتين CVE-2025-53770 وCVE-2025-53771'],
    ['Enable AMSI in Full Mode with Defender Antivirus or an equivalent product', 'فعّل AMSI بوضع Full Mode مع Defender Antivirus أو ما يعادله'],
    ['Rotate the SharePoint ASP.NET machine keys, then restart IIS', 'دوّر مفاتيح ASP.NET لخادم SharePoint ثم أعد تشغيل IIS'],
    ['Hunt for spinstall*.aspx under TEMPLATE\\LAYOUTS, w3wp.exe child processes, new scheduled tasks, IIS module changes and GPO edits since the server was exposed', 'ابحث عن spinstall*.aspx في TEMPLATE\\LAYOUTS، والعمليات التي أطلقها w3wp.exe، والمهام المجدولة الجديدة، وتغييرات وحدات IIS وGPO منذ أن كان الخادم مكشوفًا'],
    ['Patching does not remove an earlier compromise: investigate before closing', 'الترقيع لا يزيل اختراقًا سابقًا: حقّق قبل الإغلاق'],
  ],
};
const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|f[cd][0-9a-f]{2}:|fe80:)/i;
const SHELLS = /\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|certutil)\.exe$/i, LAYOUTS = /\/_layouts\/1[56]\//i;
export const SIGNAL_AR = { exposure: 'مكشوف على الإنترنت', vulnerable: 'إصدار معرّض للثغرة', 'toolpane-post': 'طلب POST إلى ToolPane.aspx', 'file-signature': 'ملف أو توقيع web shell', 'w3wp-shell': 'w3wp.exe أطلق صدفة أوامر', 'protection-change': 'تغيير في الحماية', 'scheduled-task': 'مهمة مجدولة جديدة', 'policy-change': 'تغيير سياسة (GPO)' };
const ACTIVITY = ['toolpane-post', 'file-signature', 'w3wp-shell', 'protection-change', 'scheduled-task', 'policy-change'], HOST = ['w3wp-shell', 'protection-change', 'scheduled-task', 'policy-change'];

export function evaluateToolShell(domain, { assetRef = null, now = Date.now(), windowDays = 30 } = {}) {
  const s = domain.s, since = new Date(now - windowDays * 86400000).toISOString(), rows = (kind, extra = '') => s.all(`SELECT e.id,e.observed_at,e.payload,a.external_id,a.hostname FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind=? AND e.observed_at>=?${extra}`, kind, since);
  const servers = new Map(), exposedFrom = new Set(), sig = (ref, host, signal, at, detail, eventId, detail_ar = detail) => { if (assetRef && ref !== assetRef) return; const c = servers.get(ref) || { asset_ref: ref, hostname: host, sharepoint: [], signals: [] }; c.signals.push({ signal, at, detail, detail_ar, event_id: eventId }); servers.set(ref, c); };
  const mark = (ref, host, why) => { if (assetRef && ref !== assetRef) return; const c = servers.get(ref) || { asset_ref: ref, hostname: host, sharepoint: [], signals: [] }; if (!c.sharepoint.includes(why)) c.sharepoint.push(why); servers.set(ref, c); };
  // Identify SharePoint servers: installed software, asset context or SharePoint layout paths in their web logs.
  for (const r of s.all("SELECT e.payload,a.external_id,a.hostname FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind='software.inventory'")) if (parse(r.payload).details.software.some(x => /sharepoint/i.test(x.name))) mark(r.external_id, r.hostname, 'software-inventory');
  for (const r of s.all("SELECT e.payload,a.external_id,a.hostname FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind='asset.context'")) { const d = parse(r.payload).details; if (/sharepoint/i.test(`${d.business_service} ${d.service_name || ''}`)) mark(r.external_id, r.hostname, 'asset-context'); }
  for (const r of rows('log.batch')) { const d = parse(r.payload).details; if (d.category !== 'web') continue; let seen = false;
    for (const x of d.records || []) { if (!LAYOUTS.test(x.query || '')) continue; seen = true;
      if (x.src_ip && !PRIVATE.test(x.src_ip) && !exposedFrom.has(`${r.external_id}|${x.src_ip}`)) { exposedFrom.add(`${r.external_id}|${x.src_ip}`); sig(r.external_id, r.hostname, 'exposure', x.time, `Requests to SharePoint pages from internet address ${x.src_ip}`, r.id, `طلبات إلى صفحات SharePoint من عنوان على الإنترنت ${x.src_ip}`); }
      if (x.action === 'POST' && /\/_layouts\/1[56]\/ToolPane\.aspx$/i.test(x.query)) sig(r.external_id, r.hostname, 'toolpane-post', x.time, `POST ${x.query} from ${x.src_ip || 'unknown'}${x.signature ? ` (referer ${x.signature})` : ''}`, r.id, `POST ${x.query} من ${x.src_ip || 'مصدر غير معروف'}${x.signature ? ` (المُحيل ${x.signature})` : ''}`);
      if (/\/spinstall\d*\.aspx$/i.test(x.query) && Number(x.outcome) < 400) sig(r.external_id, r.hostname, 'file-signature', x.time, `Request to ${x.query} answered ${x.outcome}`, r.id, `طلب إلى ${x.query} أجاب ${x.outcome}`); }
    if (seen) mark(r.external_id, r.hostname, 'web-logs'); }
  // Vulnerable build from the software inventory matched against imported catalogs.
  for (const item of domain.softwareVulnerabilities({ limit: 5000 }).items) for (const m of item.matches || []) if (TOOLSHELL.cves.includes(m.vuln_id) && m.status !== 'fixed-by-update') sig(item.asset.external_id, item.asset.hostname, 'vulnerable', item.observed_at, `${m.vuln_id} on ${m.product} ${m.installed_version || '(version unknown)'}${m.kev ? ', in CISA KEV' : ''}`, item.event_id, `${m.vuln_id} على ${m.product} ${m.installed_version || '(إصدار غير معروف)'}${m.kev ? '، ضمن قائمة CISA KEV' : ''}`);
  for (const r of rows('security.finding')) { const d = parse(r.payload).details; if (/spinstall\d*\.aspx|toolshell|CVE-2025-5377[01]/i.test(`${d.title} ${d.description || ''}`)) sig(r.external_id, r.hostname, 'file-signature', r.observed_at, d.title, r.id); }
  for (const r of rows('endpoint.process_causality')) { const d = parse(r.payload).details, byId = new Map(d.processes.map(p => [p.process_id, p]));
    for (const p of d.processes) { const parent = byId.get(p.parent_process_id); if (parent && /\\w3wp\.exe$/i.test(parent.image_path) && SHELLS.test(p.image_path)) sig(r.external_id, r.hostname, 'w3wp-shell', p.started_at, `w3wp.exe started ${p.image_path.split('\\').pop()}${/-e(nc|ncodedcommand)?\s/i.test(p.command_line || '') ? ' with an encoded command' : ''}`, r.id, `w3wp.exe أطلق ${p.image_path.split('\\').pop()}${/-e(nc|ncodedcommand)?\s/i.test(p.command_line || '') ? ' بأمر مشفر' : ''}`); }
    for (const t of d.scheduled_task_changes || []) if (['created', 'modified'].includes(t.action)) sig(r.external_id, r.hostname, 'scheduled-task', t.occurred_at, `Scheduled task ${t.task_name} ${t.action}`, r.id, `المهمة المجدولة ${t.task_name} ${t.action === 'created' ? 'أُنشئت' : 'عُدّلت'}`); }
  for (const r of rows('endpoint.defense_tamper')) { const d = parse(r.payload).details;
    sig(r.external_id, r.hostname, d.control.type === 'policy' ? 'policy-change' : 'protection-change', d.change.occurred_at, `${d.control.name}: ${d.change.action}`, r.id); }
  return [...servers.values()].filter(c => c.sharepoint.length).map(c => {
    const kinds = [...new Set(c.signals.map(x => x.signal))], activity = kinds.filter(k => ACTIVITY.includes(k)), host = kinds.filter(k => HOST.includes(k));
    const exposed = kinds.includes('exposure'), vulnerable = kinds.includes('vulnerable');
    const state = activity.length >= 2 && host.length >= 1 ? 'probable-compromise' : activity.length >= 1 ? 'suspected' : exposed && vulnerable ? 'at-risk' : vulnerable ? 'vulnerable-not-seen-exposed' : 'no-evidence';
    const severity = { 'probable-compromise': 'critical', suspected: 'high', 'at-risk': 'high', 'vulnerable-not-seen-exposed': 'medium', 'no-evidence': null }[state];
    const note = state === 'suspected' && activity.length === 1 ? (activity[0] === 'file-signature' ? 'A single web-shell file or signature is not proof on its own; look for host behaviour from w3wp.exe and persistence' : 'One activity signal only; it needs corroboration from another independent source') : state === 'probable-compromise' ? 'Several independent signals agree, including host behaviour; an analyst must confirm before it is called a compromise' : state === 'no-evidence' ? 'No exposure, vulnerability or activity evidence in the collected data; this is not proof the server is safe if logs are missing' : 'Exposure and vulnerability without observed activity: patch, enable AMSI, rotate machine keys and hunt';
    const note_ar = state === 'suspected' && activity.length === 1 ? (activity[0] === 'file-signature' ? 'ملف أو توقيع web shell وحده ليس إثباتًا؛ ابحث عن سلوك w3wp.exe على الخادم والاستمرار' : 'إشارة نشاط واحدة فقط؛ تحتاج تأكيدًا من مصدر مستقل آخر') : state === 'probable-compromise' ? 'عدة إشارات مستقلة متفقة منها سلوك على الخادم؛ يجب أن يؤكد المحلل قبل وصفها بالاختراق' : state === 'no-evidence' ? 'لا دليل على انكشاف أو ثغرة أو نشاط في البيانات المجمّعة؛ وهذا ليس إثباتًا لسلامة الخادم إن كانت السجلات ناقصة' : 'انكشاف وثغرة دون نشاط مرصود: رقّع وفعّل AMSI ودوّر مفاتيح الآلة وابحث';
    const collected = { web_logs: c.sharepoint.includes('web-logs') || kinds.some(k => ['exposure', 'toolpane-post'].includes(k)), process: c.signals.some(x => ['w3wp-shell', 'scheduled-task'].includes(x.signal)) || s.get("SELECT 1 FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind='endpoint.process_causality' AND a.external_id=? LIMIT 1", c.asset_ref) !== undefined, inventory: c.sharepoint.includes('software-inventory') };
    return { case: TOOLSHELL.id, rule: TOOLSHELL.rule, asset_ref: c.asset_ref, hostname: c.hostname, identified_by: c.sharepoint, state, severity, signals: c.signals.sort((a, b) => String(a.at).localeCompare(String(b.at))), kinds, activity, host_behaviour: host, note, note_ar, confirmed: false,
      missing_visibility: Object.entries(collected).filter(([, v]) => !v).map(([k]) => k) };
  });
}

export function attackCasesView(domain) {
  return { cases: [{ ...TOOLSHELL, servers: evaluateToolShell(domain) }], signal_ar: SIGNAL_AR,
    claim: 'Each case joins independent evidence per server. One signal, and especially a single file signature, is never proof; no case is confirmed automatically.',
    claim_ar: 'تجمع كل حالة أدلة مستقلة لكل خادم. الإشارة الواحدة، وخاصة توقيع ملف واحد، ليست إثباتًا أبدًا؛ ولا تُؤكد أي حالة آليًا.' };
}
