// CG-141 Remote-access session correlation. For each device and remote tool (RDP, SSH, VPN, AnyDesk, TeamViewer and
// other remote-control software) the stages are kept apart, each with its own evidence: installed (inventory), started
// (a running process or created service), connected (connection attempt or the tool's network connection), authenticated
// session (an authentication log), and the peer (internal, internet address, or hidden behind a vendor relay). A session
// is called suspected misuse only when an identity signal (failed logons before success, or a session outside the
// management policy) and a behaviour signal on the device after it (shells or tools started from the session, protection
// changes, new services or scheduled tasks) both exist. It is never called a compromise automatically.
const parse = s => JSON.parse(s);
export const TOOLS = { anydesk: /anydesk/i, teamviewer: /teamviewer/i, screenconnect: /screenconnect|connectwise control/i, splashtop: /splashtop/i, rustdesk: /rustdesk/i, 'chrome-remote-desktop': /chrome remote desktop|remoting_host/i, logmein: /logmein/i };
export const STAGES = ['installed', 'started', 'connected', 'authenticated'];
export const STAGE_AR = { installed: 'مثبّت', started: 'مُشغَّل', connected: 'اتصال', authenticated: 'جلسة موثّقة' };
const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|f[cd][0-9a-f]{2}:|fe80:)/i;
const toolOf = name => Object.entries(TOOLS).find(([, re]) => re.test(name || ''))?.[0] || null;
const SHELL = /\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|certutil|whoami|net1?|nltest|reg)\.exe$/i;

export function correlateRemote(domain, { now = Date.now(), windowDays = 7 } = {}) {
  const s = domain.s, since = new Date(now - windowDays * 86400000).toISOString(), groups = new Map();
  const get = (ref, host, tool) => { const k = `${ref}|${tool}`; if (!groups.has(k)) groups.set(k, { asset_ref: ref, hostname: host, tool, stages: Object.fromEntries(STAGES.map(x => [x, []])), peers: [], sessions: [], identity: [], behaviour: [] }); return groups.get(k); };
  const rows = kind => s.all("SELECT e.id,e.asset_id,e.observed_at,e.payload,a.external_id,a.hostname FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind=? AND e.observed_at>=? ORDER BY e.observed_at", kind, since);
  for (const r of s.all("SELECT e.id,e.observed_at,e.payload,a.external_id,a.hostname FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind='software.inventory'")) for (const sw of parse(r.payload).details.software) { const t = toolOf(sw.name); if (t) get(r.external_id, r.hostname, t).stages.installed.push({ at: r.observed_at, detail: `${sw.name} ${sw.version || ''}`.trim(), event_id: r.id }); }
  const procByAsset = new Map();
  for (const r of rows('endpoint.process_causality')) { const d = parse(r.payload).details, byId = new Map(d.processes.map(p => [p.process_id, p])); procByAsset.set(r.external_id, [...(procByAsset.get(r.external_id) || []), { ...d, event_id: r.id }]);
    for (const p of d.processes) { const t = toolOf(p.image_path); if (t) get(r.external_id, r.hostname, t).stages.started.push({ at: p.started_at, detail: p.image_path.split('\\').pop(), event_id: r.id }); }
    for (const c of d.service_changes || []) { const t = toolOf(`${c.service_name} ${c.binary_path || ''}`); if (t && ['created', 'started'].includes(c.action)) get(r.external_id, r.hostname, t).stages.started.push({ at: c.occurred_at, detail: `service ${c.service_name} ${c.action}`, event_id: r.id }); }
    for (const c of d.connections || []) { const p = byId.get(c.process_id), t = p && toolOf(p.image_path); if (t && c.direction === 'outbound') get(r.external_id, r.hostname, t).stages.connected.push({ at: c.occurred_at, detail: `${p.image_path.split('\\').pop()} to ${c.remote_address}:${c.remote_port}`, event_id: r.id }); } }
  for (const kind of ['remote.application_present', 'remote.attempt', 'remote.authenticated', 'remote.active']) for (const r of rows(kind)) {
    const d = parse(r.payload).details, tool = d.protocol, g = get(r.external_id, r.hostname, tool), stage = { 'remote.application_present': 'installed', 'remote.attempt': 'connected', 'remote.authenticated': 'authenticated', 'remote.active': 'authenticated' }[kind];
    g.stages[stage].push({ at: r.observed_at, detail: `${kind.slice(7)} ${d.session_id}`, event_id: r.id });
    if (stage !== 'installed') { const ip = d.source_a?.ip || null, peer = d.relay ? 'relay' : !ip ? 'unknown' : PRIVATE.test(ip) ? 'internal' : 'internet'; if (!g.peers.some(p => p.peer === peer && p.ip === ip)) g.peers.push({ peer, ip }); }
    if (stage === 'authenticated') { const violations = domain.managementViolations({ asset_id: r.asset_id, details: d, observed_at: r.observed_at }); g.sessions.push({ session_id: d.session_id, at: r.observed_at, account: d.target_b?.account || d.source_a?.account || null, source_ip: d.source_a?.ip || null, relay: d.relay, authorization_ref: d.authorization_ref, violations: violations.map(v => v.id) });
      if (violations.length) g.identity.push({ at: r.observed_at, detail: `Session ${d.session_id} outside the management policy (${violations.map(v => v.id).join(', ')})`, detail_ar: `الجلسة ${d.session_id} خارج سياسة الإدارة` });
      const ip = d.source_a?.ip; if (ip) { const fails = s.all("SELECT 1 FROM events WHERE kind='auth.failed' AND asset_id=? AND observed_at<=? AND observed_at>=? AND json_extract(payload,'$.details.source_ip')=?", r.asset_id, r.observed_at, new Date(Date.parse(r.observed_at) - 3600000).toISOString(), ip).length; if (fails >= 5) g.identity.push({ at: r.observed_at, detail: `${fails} failed logons from ${ip} in the hour before the successful session`, detail_ar: `${fails} محاولة دخول فاشلة من ${ip} في الساعة التي سبقت الجلسة الناجحة` }); } } }
  // Behaviour on the device within two hours after an authenticated session started.
  for (const g of groups.values()) for (const sess of g.sessions) { const start = Date.parse(sess.at), end = start + 2 * 3600000, inWin = t => { const x = Date.parse(t); return x >= start && x <= end; };
    for (const pc of procByAsset.get(g.asset_ref) || []) { for (const p of pc.processes) if (SHELL.test(p.image_path) && inWin(p.started_at)) g.behaviour.push({ at: p.started_at, detail: `${p.image_path.split('\\').pop()} started after the session`, detail_ar: `بدأ ${p.image_path.split('\\').pop()} بعد الجلسة` });
      for (const c of [...(pc.service_changes || []), ...(pc.scheduled_task_changes || [])]) if (c.action === 'created' && inWin(c.occurred_at)) g.behaviour.push({ at: c.occurred_at, detail: `${c.service_name ? `Service ${c.service_name}` : `Scheduled task ${c.task_name}`} created after the session`, detail_ar: `${c.service_name ? `الخدمة ${c.service_name}` : `المهمة المجدولة ${c.task_name}`} أُنشئت بعد الجلسة` }); }
    for (const r of s.all("SELECT e.payload FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind='endpoint.defense_tamper' AND a.external_id=?", g.asset_ref)) { const d = parse(r.payload).details; if (inWin(d.change.occurred_at)) g.behaviour.push({ at: d.change.occurred_at, detail: `${d.control.name} ${d.change.action} after the session`, detail_ar: `${d.control.name}: ${d.change.action} بعد الجلسة` }); } }
  return [...groups.values()].map(g => {
    const reached = STAGES.filter(x => g.stages[x].length), highest = reached.at(-1) || null, external = g.peers.some(p => p.peer === 'internet'), relay = g.peers.some(p => p.peer === 'relay');
    const authorized = g.sessions.length > 0 && g.sessions.every(x => x.authorization_ref && !x.violations.length);
    const classification = g.identity.length && g.behaviour.length ? 'suspected-misuse' : authorized ? 'authorized' : highest === 'authenticated' && (external || relay) ? 'external-session-needs-review' : highest === 'authenticated' ? 'session-needs-review' : highest ? `${highest}-only` : 'no-evidence';
    const severity = { 'suspected-misuse': 'high', 'external-session-needs-review': 'medium' }[classification] || null;
    const note = classification === 'suspected-misuse' ? 'Identity and behaviour signals agree; an analyst must confirm before calling it a compromise' : classification === 'external-session-needs-review' ? 'An authenticated session from the internet or a relay without an authorization reference; it is not proof of compromise' : classification.endsWith('-only') ? 'The tool is present but no authenticated session is proven' : classification === 'authorized' ? 'Every session carries an authorization reference and follows the management policy' : 'Authenticated session without identity or behaviour evidence of misuse';
    const note_ar = classification === 'suspected-misuse' ? 'إشارات الهوية والسلوك متفقة؛ يجب أن يؤكد المحلل قبل وصفها بالاختراق' : classification === 'external-session-needs-review' ? 'جلسة موثّقة من الإنترنت أو عبر وسيط دون مرجع تصريح؛ وليست إثباتًا للاختراق' : classification.endsWith('-only') ? 'الأداة موجودة لكن لا جلسة موثّقة مثبتة' : classification === 'authorized' ? 'كل الجلسات تحمل مرجع تصريح وتتبع سياسة الإدارة' : 'جلسة موثّقة دون دليل هوية أو سلوك على سوء الاستخدام';
    return { ...g, reached, highest, external_peer: external, relay_peer: relay, classification, severity, note, note_ar, compromise_confirmed: false };
  }).sort((a, b) => (b.severity ? 1 : 0) - (a.severity ? 1 : 0) || a.asset_ref.localeCompare(b.asset_ref));
}

export function remoteCorrelationView(domain) {
  return { items: correlateRemote(domain), stages: STAGES.map(s => ({ stage: s, stage_ar: STAGE_AR[s] })),
    claim: 'Installed, started, connected and authenticated are separate stages with their own evidence; a peer behind a vendor relay is shown as hidden. Misuse needs both an identity and a behaviour signal, and nothing is called a compromise automatically.',
    claim_ar: 'التثبيت والتشغيل والاتصال والجلسة الموثّقة مراحل منفصلة لكل منها دليلها؛ والطرف خلف وسيط المورّد يظهر مخفيًا. وسوء الاستخدام يتطلب إشارة هوية وإشارة سلوك معًا، ولا يوصف شيء بالاختراق آليًا.' };
}
