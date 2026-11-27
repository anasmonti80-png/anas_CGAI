// CG-163 Tamper-evident collection. When an agent or forwarder goes silent, an agent or logging is disabled, logs are
// cleared, the device clock is changed, or delivery fails, CyberGuard stores its own independent `visibility.loss`
// event (from an internal source that has no ingest credential). The event names the cause, when visibility was lost
// and regained, the detection rules that lose their input, and an assessment that is never "compromise":
//  - authorized-change: the change carries an authorization or ticket or happened in a maintenance window;
//  - suspicious-concurrent: another high or critical alert on the same asset or source around the loss;
//  - unexplained: neither.
// Because it is a stored event, detection content can use it: CG-CORR-TAMPER-THEN-LOSS-163 joins tampering and a
// following loss on the same asset, and CG-VISIBILITY-LOSS-163 alerts only on suspicious-concurrent losses.
import { MAPPINGS } from './attack-mapping.js';

export const INTERNAL_SOURCE_ID = '00000000-0000-4000-8000-000000000163';
export const INTERNAL_SOURCE_NAME = 'CyberGuard health (internal)';
export const CAUSES = ['agent-disconnected', 'agent-disabled', 'log-deletion', 'logging-disabled', 'clock-change', 'transport-failure', 'source-silent'];
export const CAUSE_AR = { 'agent-disconnected': 'انقطاع الوكيل', 'agent-disabled': 'تعطيل الوكيل أو الحماية', 'log-deletion': 'حذف السجلات', 'logging-disabled': 'إيقاف التسجيل', 'clock-change': 'تغيير ساعة الجهاز', 'transport-failure': 'فشل النقل', 'source-silent': 'صمت المصدر' };
// Visibility alerts that describe the loss itself and must not count as concurrent suspicious activity.
const OWN_RULES = new Set(['CG-AGENT-LOST', 'CG-LOST-COVERAGE', 'CG-LOG-DELIVERY-FAILED', 'CG-DELIVERY-BACKLOG-060', 'CG-VISIBILITY-GAP', 'CG-VISIBILITY-LOSS-163', 'CG-TAMPER-004', 'CG-CORR-TAMPER-THEN-LOSS-163', 'CG-PROTECTION-NOT-RUNNING']);

export function causeFromTamper(d) {
  const { type } = d.control, { action } = d.change;
  if (type === 'logging') return action === 'cleared' ? 'log-deletion' : ['disabled', 'stopped', 'policy-changed'].includes(action) ? 'logging-disabled' : null;
  if (['agent', 'edr', 'antivirus'].includes(type) && ['stopped', 'uninstalled', 'disabled'].includes(action)) return 'agent-disabled';
  if (type === 'time' && action === 'time-changed') return 'clock-change';
  return null;
}
export const causeFromHealth = sourceType => sourceType === 'managed-agent' ? 'agent-disconnected' : sourceType === 'log-forwarder' ? 'transport-failure' : 'source-silent';

export function rulesAffected(store, { sourceId = null, assetId = null }) {
  const since = new Date(Date.now() - 30 * 86400000).toISOString();
  const kinds = new Set(store.all(`SELECT DISTINCT kind FROM events WHERE received_at>=? AND kind!='visibility.loss' AND ${sourceId ? 'source_id=?' : 'asset_id=?'}`, since, sourceId || assetId).map(r => r.kind));
  return MAPPINGS.filter(m => m.sensor_kinds.some(k => kinds.has(k))).map(m => m.rule).slice(0, 100);
}

export function assess(store, { sourceId = null, assetId = null, startedAt, authorized = false }) {
  const from = new Date(Date.parse(startedAt) - 3600000).toISOString();
  const concurrent = store.all(`SELECT rule_id,severity FROM alerts WHERE severity IN ('high','critical') AND status!='resolved' AND last_seen>=? AND (${assetId ? 'asset_id=?' : '0'} OR ${sourceId ? 'source_id=?' : '0'})`, from, ...(assetId ? [assetId] : []), ...(sourceId ? [sourceId] : [])).filter(a => !OWN_RULES.has(a.rule_id));
  return { assessment: concurrent.length ? 'suspicious-concurrent' : authorized ? 'authorized-change' : 'unexplained', concurrent_rules: [...new Set(concurrent.map(a => a.rule_id))].slice(0, 20) };
}

export function lossView(store) {
  const latest = new Map();
  for (const r of store.all("SELECT id,observed_at,payload FROM events WHERE kind='visibility.loss' ORDER BY observed_at,received_at")) { const p = JSON.parse(r.payload); latest.set(p.details.loss_id, { ...p.details, asset: p.asset?.hostname || p.asset?.external_id || null, event_id: r.id, recorded_at: r.observed_at }); }
  const items = [...latest.values()].sort((a, b) => (a.ended_at ? 1 : 0) - (b.ended_at ? 1 : 0) || b.started_at.localeCompare(a.started_at));
  const by = {}; for (const i of items) by[i.assessment] = (by[i.assessment] || 0) + 1;
  return { items: items.slice(0, 500), open: items.filter(i => !i.ended_at).length, by_assessment: by, causes: CAUSES,
    claim: 'Each loss of visibility (agent silent or disabled, logs cleared or logging stopped, device clock changed, delivery failed) is stored as an independent visibility.loss event with its cause, start and end, the detection rules that lose their input, and an assessment. A loss is never treated as a confirmed compromise: it is unexplained, an authorized change, or concurrent with other suspicious alerts.',
    claim_ar: 'كل فقد للرؤية (وكيل صامت أو معطل، أو سجلات ممسوحة أو تسجيل متوقف، أو ساعة جهاز متغيرة، أو فشل نقل) يُخزن حدثًا مستقلًا من نوع visibility.loss بسببه وبدايته ونهايته والقواعد التي تفقد مدخلاتها وتقييمه. ولا يُعامل فقد الرؤية أبدًا كاختراق مؤكد: فهو غير مفسَّر، أو تغيير مصرح، أو متزامن مع تنبيهات مريبة أخرى.' };
}
