// CG-012 versioned detection rules. Each rule reads one stored evidence kind and returns hits with a
// stable key and a short evidence summary. Rules raise alerts for analyst review; they never act.
const lolbins = [
  { id: 'shadow-copy-delete', re: /vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|Get-WmiObject\s+Win32_Shadowcopy[^|]*\|\s*ForEach-Object\s*\{\s*\$_\.Delete/i },
  { id: 'backup-catalog-delete', re: /wbadmin(\.exe)?\s+delete\s+(catalog|backup|systemstatebackup)/i },
  { id: 'recovery-disabled', re: /bcdedit(\.exe)?\s+\/set\s+\{?\w*\}?\s*recoveryenabled\s+no/i },
  { id: 'encoded-powershell', re: /powershell(\.exe)?[^\n]*\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/i },
  { id: 'certutil-download', re: /certutil(\.exe)?[^\n]*-urlcache[^\n]*https?:\/\//i },
  { id: 'mshta-remote', re: /mshta(\.exe)?\s+(https?:|javascript:|vbscript:)/i },
  { id: 'rundll32-script', re: /rundll32(\.exe)?[^\n]*javascript:/i },
  { id: 'regsvr32-remote', re: /regsvr32(\.exe)?[^\n]*\/i:https?:\/\//i },
];
const userWritable = /\\Users\\[^\\]+\\(Downloads|AppData|Desktop)\\|\\Windows\\Temp\\|\\ProgramData\\(?!Microsoft\\)|\/tmp\/|\/dev\/shm\//i;
const privateAddress = value => /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|::1$|fe80:|f[cd][0-9a-f]{2}:)/i.test(value);
const deliberateMethods = new Set(['user-command', 'service-control', 'registry', 'group-policy', 'script']);

export const detectionRules = [
  {
    id: 'CG-MAL-LOLBIN-001', version: '1.0.0', severity: 'high', kind: 'endpoint.process_causality',
    title: ['Known malicious command pattern', 'نمط أمر خبيث معروف'],
    description: 'Shadow-copy or backup deletion, disabled recovery, encoded PowerShell, certutil download, remote mshta/rundll32/regsvr32 in a process or scheduled-task command line.',
    match: d => [...d.processes.map(p => ({ ref: p.process_id, text: p.command_line })), ...d.scheduled_task_changes.map(t => ({ ref: t.change_id, text: t.command }))]
      .flatMap(item => lolbins.filter(rule => item.text && rule.re.test(item.text)).map(rule => ({ key: `${d.causality_id}:${item.ref}:${rule.id}`, summary: `${rule.id} in ${item.ref}` }))),
  },
  {
    id: 'CG-MAL-PERSIST-002', version: '1.0.0', severity: 'high', kind: 'endpoint.process_causality',
    title: ['Unsigned process created persistence', 'عملية غير موقّعة أنشأت استمرارية'],
    description: 'An unsigned or invalidly signed process created or modified a service or scheduled task.',
    match: d => { const bad = new Set(d.processes.filter(p => ['unsigned', 'invalid'].includes(p.signer.status)).map(p => p.process_id)); return [...d.service_changes, ...d.scheduled_task_changes].filter(c => ['created', 'modified'].includes(c.action) && bad.has(c.process_id)).map(c => ({ key: `${d.causality_id}:${c.change_id}`, summary: `${c.service_name || c.task_name} ${c.action} by unsigned ${c.process_id}` })); },
  },
  {
    id: 'CG-MAL-USERPATH-003', version: '1.0.0', severity: 'medium', kind: 'endpoint.process_causality',
    title: ['Unsigned user-path process contacted the Internet', 'عملية غير موقّعة من مسار المستخدم اتصلت بالإنترنت'],
    description: 'An unsigned process started from a user-writable path made an outbound connection to a public address.',
    match: d => d.processes.filter(p => ['unsigned', 'invalid', 'unknown'].includes(p.signer.status) && userWritable.test(p.image_path)).flatMap(p => d.connections.filter(c => c.process_id === p.process_id && c.direction === 'outbound' && !privateAddress(c.remote_address)).map(c => ({ key: `${d.causality_id}:${p.process_id}:${c.remote_address}:${c.remote_port}`, summary: `${p.image_path} -> ${c.remote_address}:${c.remote_port}` }))),
  },
  {
    id: 'CG-TAMPER-004', version: '1.0.0', severity: 'critical', kind: 'endpoint.defense_tamper',
    title: ['Attempt to disable protection', 'محاولة تعطيل الحماية'],
    description: 'AV, EDR, firewall, logging or agent disabled, removed, cleared or excluded by a deliberate method without authorization, change ticket or maintenance window.',
    match: d => { const authorized = d.context.authorization_ref || d.context.change_ticket_ref || d.context.maintenance_window; const deliberate = deliberateMethods.has(d.change.method) || ['cleared', 'exclusion-added'].includes(d.change.action); return !authorized && deliberate && ['antivirus', 'edr', 'firewall', 'logging', 'agent'].includes(d.control.type) ? [{ key: d.tamper_id, summary: `${d.control.type} ${d.change.action} via ${d.change.method}` }] : []; },
  },
  {
    id: 'CG-RAN-005', version: '1.0.0', severity: 'critical', kind: 'endpoint.ransomware_posture',
    title: ['Ransomware indicators', 'مؤشرات برامج فدية'],
    description: 'Ransom-note files, mass extension renames, deleted shadow copies or high-entropy writes during a modification spike.',
    match: d => { const a = d.file_activity, found = []; if (a.ransom_note_files > 0) found.push('ransom-notes'); if (a.renamed_extensions >= 20) found.push('mass-rename'); if (d.recovery_store.shadow_copies === 'deleted') found.push('shadow-copies-deleted'); if (a.high_entropy_writes >= 50 && a.observed_modifications >= 100) found.push('high-entropy-writes'); return found.length ? [{ key: d.posture_id, summary: found.join(', ') }] : []; },
  },
  {
    id: 'CG-AGENT-NOAV-006', version: '1.0.0', severity: 'high', kind: 'agent.inventory_report',
    title: ['Managed device without active AV/EDR', 'جهاز مُدار بلا حماية AV/EDR تعمل'],
    description: 'An agent report lists no antivirus or EDR product in the on state.',
    match: d => d.protection.some(p => ['av', 'edr'].includes(p.type) && p.state === 'on') ? [] : [{ key: d.agent_id, summary: `${d.protection.length} protection products, none active` }],
  },
];

export function evaluateDetections(kind, details) {
  return detectionRules.filter(rule => rule.kind === kind).flatMap(rule => rule.match(details).map(hit => ({ rule, ...hit })));
}

export function detectionCatalog() {
  return detectionRules.map(({ id, version, severity, kind, title, description }) => ({ id, version, severity, evidence_kind: kind, title_en: title[0], title_ar: title[1], description }));
}
