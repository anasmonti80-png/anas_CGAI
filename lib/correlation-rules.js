// CG-161 Stateful correlation rules. A rule is a declarative multi-event pattern in the spirit of Google SecOps YARA-L
// 2.0 (events, match over a key and a time window, condition with counts), evaluated by CyberGuard itself:
//  - stages, each over one evidence kind (optionally over the items of a batch such as identity sign-ins), with field
//    conditions, a key that joins the stages (e.g. the source address) and a threshold: a count or a distinct count;
//  - a time window that all stages must fall in, optionally ordered (stage 1 completes before stage 2 starts);
//  - allow-lists: key values that never match (an authorised scanner) and per-stage exclusions.
// Every rule carries labelled samples: each malicious sample must fire and each benign sample must not. Built-in rules
// are tested in CI; a custom rule runs only after its samples pass and a different administrator with recent MFA
// approves it. Replay over the last seven days shows how often it would have fired. Rules raise alerts; they never act.
import { fail, object, text, choice, integer } from './common.js';
import { matchCondition, validateLogic } from './hypotheses.js';

const FIELD = /^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*){0,4}$/i;
const get = (obj, p) => p.split('.').reduce((v, k) => (v && typeof v === 'object' ? v[k] : undefined), obj);
const ip = n => `203.0.113.${n}`, at = (m, s = 0) => new Date(Date.UTC(2026, 10, 1, 8, m, s)).toISOString();
const fails = (n, src, start = 0, acct = 'svc-app') => Array.from({ length: n }, (_, i) => ({ kind: 'auth.failed', observed_at: at(start + i), details: { account: acct, source_ip: src, protocol: 'rdp' } }));
const authOk = (m, src) => ({ kind: 'remote.authenticated', observed_at: at(m), details: { session_id: `s-${m}`, protocol: 'rdp', source_a: { hostname: null, ip: src, account: 'svc-app' }, target_b: { hostname: 'srv', ip: '192.0.2.10', account: 'svc-app' }, relay: false, evidence_type: 'authentication_log' } });
const signins = (list) => ({ kind: 'identity.signin_activity', observed_at: at(59), details: { batch_id: 'b', directory_ref: 'lab', window: { starts_at: at(0), ends_at: at(59) }, signins: list.map(([m, principal, result, src], i) => ({ signin_id: `si-${i}`, principal_ref: principal, at: at(m), result, failure_reason: null, source_ip: src, country: 'SA', client_app: 'browser', mfa: 'unknown' })) } });

export const BUILTIN_RULES = [
  { id: 'CG-CORR-BRUTE-SUCCESS-161', version: '1.0.0', severity: 'high', title: 'Repeated failures then a successful remote logon from the same source', title_ar: 'إخفاقات متكررة ثم دخول عن بُعد ناجح من المصدر نفسه',
    window_seconds: 900, ordered: true, allow_keys: [],
    stages: [{ name: 'failures', kind: 'auth.failed', key: 'source_ip', conditions: [], min_count: 5 }, { name: 'success', kind: 'remote.authenticated', key: 'source_a.ip', conditions: [], min_count: 1 }],
    samples: { malicious: [[...fails(6, ip(10)), authOk(8, ip(10))]], benign: [[...fails(6, ip(11))], [...fails(3, ip(12)), authOk(4, ip(12))], [authOk(0, ip(13)), ...fails(6, ip(13), 1)], [...fails(6, ip(14)), authOk(40, ip(14))]] } },
  { id: 'CG-CORR-SPRAY-SUCCESS-161', version: '1.0.0', severity: 'high', title: 'Password spraying across many accounts then a success from the same source', title_ar: 'رش كلمات مرور على حسابات كثيرة ثم دخول ناجح من المصدر نفسه',
    window_seconds: 3600, ordered: true, allow_keys: [],
    stages: [{ name: 'spray', kind: 'identity.signin_activity', items: 'signins', time_field: 'at', key: 'source_ip', conditions: [{ field: 'result', operator: 'equals', value: 'failure' }], distinct_field: 'principal_ref', min_distinct: 10 },
      { name: 'success', kind: 'identity.signin_activity', items: 'signins', time_field: 'at', key: 'source_ip', conditions: [{ field: 'result', operator: 'equals', value: 'success' }], min_count: 1 }],
    samples: { malicious: [[signins([...Array.from({ length: 12 }, (_, i) => [i, `user${i}`, 'failure', ip(20)]), [20, 'user7', 'success', ip(20)]])]],
      benign: [[signins([...Array.from({ length: 12 }, (_, i) => [i, 'user1', 'failure', ip(21)]), [20, 'user1', 'success', ip(21)]])], [signins([...Array.from({ length: 12 }, (_, i) => [i, `user${i}`, 'failure', ip(30 + i)]), [20, 'user7', 'success', ip(30)]])]] } },
];

export function validateRule(def, kinds) {
  object(def, ['title', 'title_ar', 'severity', 'window_seconds', 'ordered', 'allow_keys', 'stages', 'samples', 'technique_ids'], 'correlation_rule');
  fail(Array.isArray(def.stages) && def.stages.length >= 1 && def.stages.length <= 5, 400, 'correlation_requires_1_to_5_stages');
  const stages = def.stages.map((s, i) => { object(s, ['name', 'kind', 'items', 'time_field', 'key', 'conditions', 'exclude', 'min_count', 'distinct_field', 'min_distinct'], `correlation_stage_${i}`);
    const kind = choice(s.kind, kinds, `correlation_stage_${i}_kind`), path = (v, n) => { if (v === undefined || v === null) return null; fail(typeof v === 'string' && FIELD.test(v), 400, `invalid_correlation_${n}_${i}`); return v; };
    const cond = (list, n) => { fail(list === undefined || (Array.isArray(list) && list.length <= 10), 400, `invalid_correlation_${n}_${i}`); return list?.length ? validateLogic({ kind, match: 'all', conditions: list }, kinds).conditions : []; };
    const distinct = path(s.distinct_field, 'distinct_field');
    return { name: text(s.name, `correlation_stage_${i}_name`, 60), kind, items: path(s.items, 'items'), time_field: path(s.time_field, 'time_field'), key: path(s.key, 'key'), conditions: cond(s.conditions, 'conditions'), exclude: cond(s.exclude, 'exclude'),
      min_count: distinct ? null : integer(s.min_count ?? 1, 1, 10000, `correlation_min_count_${i}`), distinct_field: distinct, min_distinct: distinct ? integer(s.min_distinct, 2, 10000, `correlation_min_distinct_${i}`) : null }; });
  fail(stages.every(s => s.key), 400, 'correlation_stage_key_required');
  fail(Array.isArray(def.allow_keys ?? []) && (def.allow_keys ?? []).length <= 200, 400, 'invalid_correlation_allow_keys');
  const samples = object(def.samples, ['malicious', 'benign'], 'correlation_samples');
  for (const set of ['malicious', 'benign']) fail(Array.isArray(samples[set]) && samples[set].length >= 1 && samples[set].length <= 20 && samples[set].every(x => Array.isArray(x) && x.length >= 1 && x.length <= 500), 400, `correlation_requires_${set}_samples`);
  for (const ev of [...samples.malicious, ...samples.benign].flat()) { object(ev, ['kind', 'observed_at', 'details'], 'correlation_sample_event'); fail(kinds.includes(ev.kind) && !Number.isNaN(Date.parse(ev.observed_at)) && ev.details && typeof ev.details === 'object', 400, 'invalid_correlation_sample_event'); }
  return { title: text(def.title, 'correlation_title', 200), title_ar: text(def.title_ar, 'correlation_title_ar', 200, true) || null, severity: choice(def.severity, ['low', 'medium', 'high', 'critical'], 'severity'), window_seconds: integer(def.window_seconds, 60, 86400, 'correlation_window_seconds'),
    ordered: def.ordered === true, allow_keys: (def.allow_keys ?? []).map((k, i) => text(String(k), `correlation_allow_key_${i}`, 200)), stages, samples: { malicious: samples.malicious, benign: samples.benign },
    technique_ids: (def.technique_ids ?? []).map((t, i) => { fail(/^T\d{4}(\.\d{3})?$/.test(t), 400, `invalid_technique_${i}`); return t; }) };
}

function occurrences(rule, events) {
  const out = [];
  for (const e of events) rule.stages.forEach((s, i) => {
    if (s.kind !== e.kind) return;
    const items = s.items ? get(e.details, s.items) : [e.details]; if (!Array.isArray(items)) return;
    for (const item of items) {
      if (!s.conditions.every(c => matchCondition(c, item)) || (s.exclude?.length && s.exclude.some(c => matchCondition(c, item)))) continue;
      const key = get(item, s.key); if (key === undefined || key === null || key === '' || rule.allow_keys.includes(String(key))) continue;
      const t = Date.parse(s.time_field ? get(item, s.time_field) : e.observed_at); if (Number.isNaN(t)) continue;
      out.push({ stage: i, key: String(key), t, id: e.id || e.event_id || null, distinct: s.distinct_field ? String(get(item, s.distinct_field)) : null });
    }
  });
  return out;
}

export function evaluate(rule, events) {
  const W = rule.window_seconds * 1000, groups = new Map(), matches = [];
  for (const o of occurrences(rule, events)) groups.set(o.key, [...(groups.get(o.key) || []), o]);
  for (const [key, list] of groups) {
    list.sort((a, b) => a.t - b.t || a.stage - b.stage); let after = -Infinity;
    for (const start of list) {
      if (start.t <= after || (rule.ordered && start.stage !== 0)) continue;
      const acc = rule.stages.map(() => ({ n: 0, set: new Set(), ids: [] })), done = rule.stages.map(() => null); let cur = 0;
      const sat = i => rule.stages[i].distinct_field ? acc[i].set.size >= rule.stages[i].min_distinct : acc[i].n >= rule.stages[i].min_count;
      for (const o of list) {
        if (o.t < start.t) continue; if (o.t > start.t + W) break;
        if (rule.ordered) { if (o.stage !== cur) continue; } else if (done[o.stage] !== null) continue;
        const a = acc[o.stage]; a.n++; if (o.distinct !== null) a.set.add(o.distinct); if (o.id) a.ids.push(o.id);
        if (sat(o.stage)) { done[o.stage] = o.t; if (rule.ordered) cur++; }
        if (done.every(x => x !== null)) break;
      }
      if (done.every(x => x !== null)) { const end = Math.max(...done); matches.push({ key, start: new Date(start.t).toISOString(), end: new Date(end).toISOString(), event_ids: [...new Set(acc.flatMap(a => a.ids))], counts: acc.map((a, i) => rule.stages[i].distinct_field ? a.set.size : a.n) }); after = end; }
    }
  }
  return matches;
}

export function testRule(rule) {
  const malicious = rule.samples.malicious.map(s => evaluate(rule, s).length), benign = rule.samples.benign.map(s => evaluate(rule, s).length);
  return { passed: malicious.every(n => n > 0) && benign.every(n => n === 0), malicious_fired: malicious.filter(n => n > 0).length, malicious_total: malicious.length, benign_fired: benign.filter(n => n > 0).length, benign_total: benign.length };
}

export class CorrelationRules {
  constructor(store, { clock, kinds = [] } = {}) { Object.assign(this, { s: store, clock: clock || (() => Date.now()), kinds }); }
  now() { return new Date(this.clock()).toISOString(); }
  row(r) { const def = JSON.parse(r.definition); return { ...def, id: `CG-CORR-C${r.id}`, row_id: r.id, version: `${r.version}.0.0`, status: r.status, created_by: r.created_by, created_at: r.created_at, approved_by: r.approved_by, approved_at: r.approved_at, test: JSON.parse(r.test_json), builtin: false }; }
  custom() { return this.s.all('SELECT * FROM correlation_rules ORDER BY id').map(r => this.row(r)); }
  active() { return [...BUILTIN_RULES.map(r => ({ ...r, status: 'active', builtin: true })), ...this.custom().filter(r => r.status === 'active')]; }
  create(actor, input) {
    const def = validateRule(input, this.kinds), test = testRule(def), at = this.now();
    const id = this.s.transaction(() => { const r = this.s.run("INSERT INTO correlation_rules(definition,version,status,test_json,created_by,created_at) VALUES (?,1,'draft',?,?,?)", JSON.stringify(def), JSON.stringify(test), actor, at); const rid = Number(r.lastInsertRowid); this.s.audit(actor, 'correlation-rule.created', `CG-CORR-C${rid}`, { test }, at); return rid; });
    return this.row(this.s.require('SELECT * FROM correlation_rules WHERE id=?', [id]));
  }
  approve(actor, id) {
    const r = this.row(this.s.require('SELECT * FROM correlation_rules WHERE id=?', [id])); fail(r.status === 'draft', 409, 'correlation_rule_not_draft');
    fail(r.test.passed, 409, 'correlation_samples_must_pass'); fail(r.created_by !== actor, 409, 'correlation_rule_needs_second_approver');
    const at = this.now(); this.s.transaction(() => { this.s.run("UPDATE correlation_rules SET status='active',approved_by=?,approved_at=? WHERE id=?", actor, at, id); this.s.audit(actor, 'correlation-rule.approved', r.id, { test: r.test }, at); });
    return this.row(this.s.require('SELECT * FROM correlation_rules WHERE id=?', [id]));
  }
  disable(actor, id) {
    const r = this.row(this.s.require('SELECT * FROM correlation_rules WHERE id=?', [id])); fail(r.status !== 'disabled', 409, 'correlation_rule_already_disabled');
    const at = this.now(); this.s.transaction(() => { this.s.run("UPDATE correlation_rules SET status='disabled' WHERE id=?", id); this.s.audit(actor, 'correlation-rule.disabled', r.id, {}, at); });
    return this.row(this.s.require('SELECT * FROM correlation_rules WHERE id=?', [id]));
  }
  stored(rule, from, to) {
    const kinds = [...new Set(rule.stages.map(s => s.kind))];
    return this.s.all(`SELECT id,kind,observed_at,payload FROM events WHERE kind IN (${kinds.map(() => '?').join(',')}) AND observed_at BETWEEN ? AND ? ORDER BY observed_at LIMIT 20000`, ...kinds, from, to).map(r => ({ id: r.id, kind: r.kind, observed_at: r.observed_at, details: JSON.parse(r.payload).details }));
  }
  // Matches that include the new event, evaluated over the window around it (batches may carry earlier item times).
  onEvent(e) {
    const out = [];
    for (const rule of this.active().filter(r => r.stages.some(s => s.kind === e.kind))) {
      const t = Date.parse(e.observed_at), pad = rule.window_seconds * 1000 + 86400000;
      for (const m of evaluate(rule, this.stored(rule, new Date(t - pad).toISOString(), new Date(t + 86400000).toISOString()))) if (m.event_ids.includes(e.id)) out.push({ rule, match: m });
    }
    return out;
  }
  replay(rule, days = 7) { const to = this.now(), from = new Date(this.clock() - days * 86400000).toISOString(); const m = evaluate(rule, this.stored(rule, from, to)); return { days, matches: m.length, keys: [...new Set(m.map(x => x.key))].length }; }
  view() {
    const rules = [...BUILTIN_RULES.map(r => ({ ...r, status: 'active', builtin: true, test: testRule(r) })), ...this.custom()];
    return { rules: rules.map(({ samples, ...r }) => ({ ...r, samples: { malicious: samples.malicious.length, benign: samples.benign.length }, replay: this.replay(r) })),
      reference: { id: 'Google SecOps YARA-L 2.0', url: 'https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview' },
      claim: 'Stateful correlation rules join several events by a key within a time window, with counts, distinct counts, order and allow-lists. Each rule carries malicious and benign samples: malicious must fire and benign must not before a custom rule can be approved by a second administrator. Replay shows how often a rule would have fired in the last seven days. Rules raise alerts; they never act.',
      claim_ar: 'تربط قواعد الارتباط ذات الحالة عدة أحداث بمفتاح داخل نافذة زمنية، مع عدد وعدد مميز وترتيب وقوائم سماح. ولكل قاعدة عينات خبيثة وسليمة: يجب أن تُطلق على الخبيثة ولا تُطلق على السليمة قبل أن يعتمد مسؤول ثانٍ القاعدة المخصصة. وتُظهر إعادة التشغيل كم مرة كانت ستُطلق في الأيام السبعة الأخيرة. القواعد ترفع تنبيهات ولا تنفذ إجراءات.' };
  }
}
