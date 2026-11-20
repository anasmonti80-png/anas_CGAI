// CG-100 OT/ICS safety mode. Operational technology (PLC, RTU, SCADA/HMI, BMS, safety systems, medical and other
// critical devices) is observed passively first. Active scanning and active validation of OT addresses are refused,
// no response action runs on an OT asset without a separate safety approval by a designated safety approver who is
// neither the requester nor the approver of the action, and disruptive actions on safety systems are never allowed.
// Guidance follows NIST SP 800-82 Rev. 3 (Guide to Operational Technology Security).
import { fail, object, text, choice } from './common.js';
import { ipInCidr } from './vulnerability-intel.js';

export const OT_CLASSES = ['plc', 'rtu', 'scada-hmi', 'historian', 'engineering-workstation', 'bms', 'safety-system', 'medical', 'other-ot'];
export const OT_PROTOCOLS = ['modbus', 'dnp3', 's7', 'bacnet', 'ethernet-ip', 'opc-ua', 'profinet', 'iec-104', 'iec-61850', 'mqtt', 'other'];
export const DISRUPTIVE = new Set(['endpoint.isolate-device', 'endpoint.shutdown-host', 'network.switch-port-admin-down', 'endpoint.stop-service', 'endpoint.disable-service', 'endpoint.remove-service', 'endpoint.change-service-permanent', 'network.nac-quarantine-endpoint', 'network.block-ip', 'network.block-port', 'endpoint.quarantine-file']);
export const NIST_800_82 = { reference: 'NIST SP 800-82 Rev. 3, Guide to Operational Technology (OT) Security (September 2023)', url: 'https://csrc.nist.gov/pubs/sp/800/82/r3/final',
  guidance: [['Segment OT from IT by zones and conduits with a demilitarised zone; no direct IT-to-control-network paths.', 'افصل شبكة التشغيل عن تقنية المعلومات بمناطق وقنوات ومنطقة منزوعة السلاح؛ لا مسارات مباشرة من تقنية المعلومات إلى شبكة التحكم.'],
    ['Prefer passive monitoring of industrial protocols; active scanning can disrupt controllers.', 'فضّل المراقبة السلبية للبروتوكولات الصناعية؛ فالمسح النشط قد يعطل وحدات التحكم.'],
    ['Route remote access through a monitored jump host with MFA and time-limited, approved sessions.', 'مرر الوصول عن بعد عبر مضيف وسيط مراقب مع MFA وجلسات معتمدة محدودة المدة.'],
    ['Apply patches only after vendor qualification and testing in a representative environment, within planned outages.', 'طبّق التحديثات فقط بعد اعتماد المورد واختبارها في بيئة ممثلة، وضمن فترات توقف مخطط لها.'],
    ['Keep offline backups of controller logic and configurations and verify restore procedures.', 'احتفظ بنسخ احتياطية غير متصلة لمنطق وحدات التحكم وإعداداتها وتحقق من إجراءات الاستعادة.'],
    ['Never let automated response change safety instrumented systems; keep manual, engineered fallbacks.', 'لا تسمح للاستجابة الآلية بتغيير أنظمة السلامة؛ وأبقِ بدائل يدوية مصممة هندسيًا.']] };

export class OtSafety {
  constructor(store, { clock, domain }) { Object.assign(this, { s: store, clock: clock || (() => Date.now()), domain }); }
  now() { return new Date(this.clock()).toISOString(); }
  profiles() { const latest = new Map(); for (const r of this.s.all("SELECT e.asset_id,e.observed_at,e.payload,a.external_id,a.hostname,a.addresses FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind='ot.asset_profile' ORDER BY e.observed_at,e.received_at")) latest.set(r.asset_id, { asset_id: r.asset_id, external_id: r.external_id, hostname: r.hostname, addresses: JSON.parse(r.addresses || '[]'), observed_at: r.observed_at, ...JSON.parse(r.payload).details }); return [...latest.values()]; }
  profileOf(asset) { return this.profiles().find(p => p.asset_id === asset.id || p.external_id === asset.external_id) || null; }
  otAddresses() { return this.profiles().flatMap(p => p.addresses); }
  // Validation plans that would actively test an OT asset in production are refused (passive tier only).
  checkValidationPlan(plan) {
    if (plan.status !== 'approved' || plan.tier === 'passive' || plan.environment !== 'production') return;
    const ot = this.profiles(), hit = ot.filter(p => plan.targets.asset_refs.includes(p.external_id) || p.addresses.some(ip => plan.targets.networks.some(n => ipInCidr(ip, n))));
    fail(!hit.length, 400, 'ot_active_validation_blocked');
  }
  // Response guard: safety systems never take disruptive actions; any other OT action needs a separate safety approval.
  checkPreview(asset, type) { const p = this.profileOf(asset); if (!p) return null; fail(!(p.ot_class === 'safety-system' && DISRUPTIVE.has(type)), 403, 'ot_safety_system_action_blocked'); return p; }
  checkExecute(action) {
    const asset = this.s.get('SELECT * FROM assets WHERE id=?', action.asset_id), p = asset && this.profileOf(asset); if (!p) return;
    fail(this.s.get("SELECT 1 FROM ot_safety_approvals WHERE action_id=? AND decision='approved'", action.id), 409, 'ot_safety_approval_required');
  }
  designate(actor, input) {
    object(input, ['user_id', 'qualification_ref'], 'ot_safety_approver'); const u = this.s.get('SELECT id,role FROM users WHERE id=?', text(input.user_id, 'user_id', 64)); fail(u && ['admin', 'analyst'].includes(u.role), 400, 'invalid_ot_safety_approver');
    this.s.transaction(() => { this.s.run('INSERT INTO ot_safety_approvers(user_id,qualification_ref,designated_by,designated_at) VALUES (?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET qualification_ref=excluded.qualification_ref,designated_by=excluded.designated_by,designated_at=excluded.designated_at,revoked_at=NULL', u.id, text(input.qualification_ref, 'qualification_ref', 200), actor, this.now()); this.s.audit(actor, 'ot.safety_approver_designated', u.id, {}, this.now()); });
    return { user_id: u.id };
  }
  approve(actor, input) {
    object(input, ['action_id', 'decision', 'operator_on_site', 'manual_fallback_confirmed', 'process_state', 'note'], 'ot_safety_approval');
    fail(this.s.get('SELECT 1 FROM ot_safety_approvers WHERE user_id=? AND revoked_at IS NULL', actor), 403, 'not_a_designated_ot_safety_approver');
    const a = this.s.require('SELECT * FROM actions WHERE id=?', [text(input.action_id, 'action_id', 64)]); fail(a.requested_by !== actor && a.approved_by !== actor, 403, 'independent_ot_safety_approver_required');
    const asset = this.s.get('SELECT * FROM assets WHERE id=?', a.asset_id); fail(this.profileOf(asset), 409, 'action_is_not_on_an_ot_asset');
    const decision = choice(input.decision, ['approved', 'rejected'], 'ot_safety_decision'), state = choice(input.process_state, ['safe-to-change', 'maintenance-window', 'running-production', 'unknown'], 'ot_process_state');
    if (decision === 'approved') { fail(input.operator_on_site === true && input.manual_fallback_confirmed === true, 400, 'ot_approval_requires_operator_and_manual_fallback'); fail(['safe-to-change', 'maintenance-window'].includes(state), 409, 'ot_process_not_in_safe_state'); }
    this.s.transaction(() => { this.s.run('INSERT INTO ot_safety_approvals(action_id,decision,approver,operator_on_site,manual_fallback_confirmed,process_state,note,decided_at) VALUES (?,?,?,?,?,?,?,?)', a.id, decision, actor, input.operator_on_site === true ? 1 : 0, input.manual_fallback_confirmed === true ? 1 : 0, state, text(input.note, 'ot_note', 1000, true), this.now()); this.s.audit(actor, `ot.safety_${decision}`, a.id, { process_state: state }, this.now()); });
    return { action_id: a.id, decision, process_state: state };
  }
  overview() {
    const profiles = this.profiles(), approvers = this.s.all('SELECT user_id,qualification_ref,designated_at FROM ot_safety_approvers WHERE revoked_at IS NULL');
    const pending = this.s.all("SELECT x.id,x.type,x.status,x.requested_at,x.asset_id,a.hostname FROM actions x JOIN assets a ON a.id=x.asset_id WHERE x.status NOT IN ('verified','rolled-back','failed','expired','rejected')").filter(x => profiles.some(p => p.asset_id === x.asset_id) && !this.s.get('SELECT 1 FROM ot_safety_approvals WHERE action_id=?', x.id));
    const by = {}; for (const p of profiles) by[p.ot_class] = (by[p.ot_class] || 0) + 1;
    return { mode: 'passive-first', profiles: profiles.map(p => ({ ...p, findings: this.findings(p) })), by_class: by, approvers, pending_safety_approvals: pending, exclusions: this.otAddresses(), guidance: NIST_800_82,
      claim: 'OT safety mode: industrial and life-safety devices are read passively first. Active scanning and active validation of OT addresses are refused, every response action on an OT asset needs a separate safety approval from a designated approver with the operator on site and a manual fallback, and disruptive actions on safety systems are never allowed.',
      claim_ar: 'وضع سلامة التشغيل: تُقرأ أجهزة التحكم الصناعي وأجهزة السلامة قراءة سلبية أولًا. يُرفض المسح النشط والتحقق النشط لعناوين التشغيل، وكل إجراء استجابة على أصل تشغيلي يحتاج موافقة سلامة منفصلة من معتمد مُعيَّن بوجود المشغل في الموقع وبديل يدوي، ولا يُسمح أبدًا بإجراءات معطلة على أنظمة السلامة.' };
  }
  findings(p) {
    const f = [], add = (id, sev, en, ar) => f.push({ id, severity: sev, title: en, title_ar: ar });
    if (p.purdue_level <= 2 && p.reachable_from_it) add('it-reaches-control', 'high', 'Reachable directly from the IT network', 'يمكن الوصول إليه مباشرة من شبكة تقنية المعلومات');
    if (p.remote_access === 'direct') add('direct-remote-access', 'high', 'Remote access does not go through a monitored jump host', 'الوصول عن بعد لا يمر عبر مضيف وسيط مراقب');
    if (!p.passive_monitoring) add('no-passive-monitoring', 'medium', 'No passive industrial protocol monitoring covers this device', 'لا مراقبة سلبية للبروتوكولات الصناعية تغطي هذا الجهاز');
    if (p.logic_backup === 'none') add('no-logic-backup', 'medium', 'No offline backup of controller logic or configuration', 'لا نسخة احتياطية غير متصلة لمنطق وحدة التحكم أو إعداداتها');
    if (p.protocols.some(x => ['modbus', 'dnp3', 's7', 'bacnet'].includes(x)) && p.reachable_from_it) add('cleartext-control-protocol', 'medium', 'Unauthenticated control protocol reachable from IT', 'بروتوكول تحكم بلا مصادقة يمكن الوصول إليه من تقنية المعلومات');
    return f;
  }
}
