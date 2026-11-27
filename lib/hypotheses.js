// CG-065 Detection hypotheses from published evidence. An analyst writes a hypothesis citing its source (an advisory or
// an incident study) as a declarative condition over one evidence kind; nothing from the source is executed. The
// hypothesis is tested against labelled samples (must match / must not match) and replayed over recent stored events to
// show how often it would fire, a person attests the manual review, and a different administrator with recent MFA
// approves it. Only approved hypotheses are evaluated on new evidence, raising alerts under their own rule ID.
import { fail, object, text, choice, integer } from './common.js';
import { incidentStudies } from './incident-studies.js';
import { fingerprint, verifySignature } from './rule-signing.js';
// CG-066 every approved version is kept and signed; edits create a new version while the approved one keeps running;
// rollback restores an earlier signed version; packs move between installations only signed by a trusted key.
// CG-165 lifecycle: the test needs a backtest on a lab source; an approved version first runs as a canary (evaluated in
// the shadow, no alerts) for at least an hour while the previous version keeps running; canary hits are reviewed and the
// false-positive rate must stay within budget before promotion; a published version that gets noisy (more alerts per day
// than its limit, or a false-positive rate over budget) is rolled back automatically to the last good signed version.

export const OPERATORS = ['equals', 'not-equals', 'contains', 'starts-with', 'ends-with', 'in', 'gte', 'lte', 'exists'];
const FIELD = /^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*){0,4}$/i;
const get = (obj, path) => path.split('.').reduce((v, k) => (v && typeof v === 'object' ? v[k] : undefined), obj);
const lower = v => typeof v === 'string' ? v.toLowerCase() : v;
export function matchCondition(cond, details) {
  const v = get(details, cond.field), x = cond.value;
  const one = value => { const a = lower(value), b = lower(x);
    switch (cond.operator) {
      case 'equals': return a === b; case 'not-equals': return a !== b; case 'exists': return value !== undefined && value !== null;
      case 'contains': return typeof a === 'string' && a.includes(b); case 'starts-with': return typeof a === 'string' && a.startsWith(b); case 'ends-with': return typeof a === 'string' && a.endsWith(b);
      case 'in': return Array.isArray(x) && x.map(lower).includes(a); case 'gte': return typeof value === 'number' && value >= x; case 'lte': return typeof value === 'number' && value <= x; default: return false; } };
  if (cond.operator === 'not-equals') return Array.isArray(v) ? v.every(one) : one(v);
  return Array.isArray(v) ? v.some(one) : one(v);
}
export const matches = (h, details) => {
  const base=h.logic.match === 'any' ? h.logic.conditions.some(c => matchCondition(c, details)) : h.logic.conditions.every(c => matchCondition(c, details));
  return base && !(h.environment_tuning?.exclusions||[]).some(x=>matchCondition(x,details));
};

export function validateEnvironmentTuning(value={}) {
  object(value,['environment','exclusions','false_positive_budget_percent','max_alerts_per_day'],'environment_tuning');
  const environment=choice(value.environment||'all',['all','production','staging','lab','development'],'detection_environment');
  const false_positive_budget_percent=integer(value.false_positive_budget_percent??20,0,100,'false_positive_budget_percent');
  fail(Array.isArray(value.exclusions||[])&&(value.exclusions||[]).length<=20,400,'invalid_tuning_exclusions');
  const exclusions=(value.exclusions||[]).map((x,i)=>{object(x,['field','operator','value','reason'],`tuning_exclusion_${i}`);const condition=validateLogic({kind:'auth.failed',match:'all',conditions:[{field:x.field,operator:x.operator,value:x.value}]},['auth.failed']).conditions[0];return {...condition,reason:text(x.reason,`tuning_exclusion_${i}_reason`,500)};});
  const max_alerts_per_day=integer(value.max_alerts_per_day??50,1,100000,'max_alerts_per_day');
  return {environment,exclusions,false_positive_budget_percent,max_alerts_per_day};
}

export function validateLogic(logic, evidenceKinds) {
  object(logic, ['kind', 'match', 'conditions'], 'hypothesis_logic');
  const kind = choice(logic.kind, evidenceKinds, 'hypothesis_kind'), match = choice(logic.match || 'all', ['all', 'any'], 'hypothesis_match');
  fail(Array.isArray(logic.conditions) && logic.conditions.length >= 1 && logic.conditions.length <= 10, 400, 'hypothesis_requires_1_to_10_conditions');
  const conditions = logic.conditions.map((c, i) => { object(c, ['field', 'operator', 'value'], `hypothesis_condition_${i}`);
    fail(typeof c.field === 'string' && FIELD.test(c.field), 400, `invalid_hypothesis_field_${i}`); const operator = choice(c.operator, OPERATORS, `hypothesis_operator_${i}`);
    let value = c.value ?? null;
    if (['gte', 'lte'].includes(operator)) fail(typeof value === 'number' && Number.isFinite(value), 400, `invalid_hypothesis_value_${i}`);
    else if (operator === 'in') fail(Array.isArray(value) && value.length >= 1 && value.length <= 50 && value.every(v => typeof v === 'string' && v.length <= 200), 400, `invalid_hypothesis_value_${i}`);
    else if (operator === 'exists') value = null;
    else fail(typeof value === 'string' && value.length >= 1 && value.length <= 300, 400, `invalid_hypothesis_value_${i}`);
    return { field: c.field, operator, value }; });
  return { kind, match, conditions };
}

export class Hypotheses {
  constructor(store, { clock, domain, evidenceKinds, signer }) { Object.assign(this, { s: store, clock: clock || (() => Date.now()), domain, evidenceKinds, signer }); this.cache = null; this.tamperReported = new Set(); }
  content(h) { return { id: h.id, version: h.version, title: h.title, severity: h.severity, technique_ids: h.technique_ids, source_type: h.source_type, source_ref: h.source_ref, logic: h.logic,environment_tuning:h.environment_tuning }; }
  versions(id) { return this.s.all('SELECT version,signer_fingerprint,approved_by,approved_at,signature,content FROM hypothesis_versions WHERE hypothesis_id=? ORDER BY version DESC', id).map(v => ({ version: v.version, signer_fingerprint: v.signer_fingerprint, approved_by: v.approved_by, approved_at: v.approved_at, signature_valid: this.signer ? this.signer.verify(JSON.parse(v.content), v.signature) : null, content: JSON.parse(v.content) })); }
  now() { return new Date(this.clock()).toISOString(); }
  row(r) { return r ? { ...r, technique_ids: JSON.parse(r.technique_ids), logic: JSON.parse(r.logic), environment_tuning:JSON.parse(r.environment_tuning), test: r.test_json ? JSON.parse(r.test_json) : null, rule_id: `CG-HYP-${String(r.id).padStart(4, '0')}`, test_json: undefined } : null; }
  get(id) { const r = this.row(this.s.get('SELECT * FROM detection_hypotheses WHERE id=?', id)); fail(r, 404, 'not_found'); return r; }
  quality(id) {const rule_id=`CG-HYP-${String(id).padStart(4,'0')}`,rows=this.s.all('SELECT disposition FROM alert_dispositions WHERE rule_id=?',rule_id),fp=rows.filter(x=>x.disposition==='false-positive').length;return {dispositioned:rows.length,false_positives:fp,false_positive_rate:rows.length?Math.round(fp/rows.length*1000)/1000:null};}
  list() { return this.s.all('SELECT * FROM detection_hypotheses ORDER BY id DESC LIMIT 200').map(r => {const row=this.row(r),quality=this.quality(r.id),budget=row.environment_tuning.false_positive_budget_percent/100;return {...row,lifecycle:this.lifecycle(row),quality:{...quality,budget_percent:row.environment_tuning.false_positive_budget_percent,state:quality.false_positive_rate===null?'not-measured':quality.false_positive_rate<=budget?'within-budget':'over-budget'},versions: this.versions(r.id).map(({ content, ...v }) => v)};}); }
  create(actor, input) {
    object(input, ['title', 'source_type', 'source_ref', 'technique_ids', 'severity', 'rationale', 'logic','environment_tuning'], 'hypothesis');
    const source_type = choice(input.source_type, ['advisory', 'incident-study', 'threat-report', 'internal-observation'], 'hypothesis_source_type');
    const source_ref = text(input.source_ref, 'hypothesis_source_ref', 500);
    if (source_type === 'incident-study') fail(incidentStudies.some(s => s.id === source_ref), 400, 'unknown_incident_study');
    if (source_type === 'advisory' || source_type === 'threat-report') fail(/^https:\/\/[^\s]+$/.test(source_ref), 400, 'hypothesis_source_must_be_https_url');
    fail(Array.isArray(input.technique_ids) && input.technique_ids.length <= 10 && input.technique_ids.every(t => /^T\d{4}(\.\d{3})?$/.test(t)), 400, 'invalid_hypothesis_technique_ids');
    const logic = validateLogic(input.logic, this.evidenceKinds),environment_tuning=validateEnvironmentTuning(input.environment_tuning||{}), severity = choice(input.severity, ['low', 'medium', 'high', 'critical'], 'severity');
    const r = this.s.transaction(() => { const res = this.s.run("INSERT INTO detection_hypotheses(title,source_type,source_ref,technique_ids,severity,rationale,logic,status,author,created_at,version,environment_tuning) VALUES (?,?,?,?,?,?,?,'draft',?,?,1,?)", text(input.title, 'hypothesis_title', 200), source_type, source_ref, JSON.stringify(input.technique_ids), severity, text(input.rationale, 'hypothesis_rationale', 2000), JSON.stringify(logic), actor, this.now(),JSON.stringify(environment_tuning));
      this.s.audit(actor, 'hypothesis.created', String(res.lastInsertRowid), { source_type, source_ref, kind: logic.kind }, this.now()); return Number(res.lastInsertRowid); });
    return this.get(r);
  }
  // Manual test: labelled samples must all behave as expected (at least one of each), the replay shows how often the
  // hypothesis would have fired on stored evidence of its kind, and the tester attests the manual review.
  test(actor, id, input) {
    object(input, ['samples', 'manual_review', 'notes', 'lab_source_id'], 'hypothesis_test');
    const h = this.get(id); fail(['draft', 'tested', 'rejected'].includes(h.status), 409, 'hypothesis_not_testable');
    fail(Array.isArray(input.samples) && input.samples.length >= 2 && input.samples.length <= 50, 400, 'hypothesis_test_requires_2_to_50_samples');
    const samples = input.samples.map((x, i) => { object(x, ['details', 'expect'], `hypothesis_sample_${i}`); fail(x.details && typeof x.details === 'object' && !Array.isArray(x.details), 400, `invalid_hypothesis_sample_${i}`); const expect = choice(x.expect, ['match', 'no-match'], `hypothesis_sample_expect_${i}`); const got = matches(h, x.details) ? 'match' : 'no-match'; return { expect, got, ok: expect === got }; });
    fail(input.manual_review === true, 400, 'manual_review_attestation_required');
    const since = new Date(this.clock() - 30 * 86400000).toISOString(), rows = this.s.all('SELECT payload FROM events WHERE kind=? AND received_at>=? ORDER BY received_at DESC LIMIT 5000', h.logic.kind, since);
    const hits = rows.filter(r => matches(h, JSON.parse(r.payload).details)).length;
    const passed = samples.every(x => x.ok) && samples.some(x => x.expect === 'match') && samples.some(x => x.expect === 'no-match');
    let backtest = null; if (input.lab_source_id !== undefined && input.lab_source_id !== null) { const lab = this.s.require('SELECT id,name FROM sources WHERE id=?', [text(input.lab_source_id, 'lab_source_id', 64)]);
      const labRows = this.s.all('SELECT payload FROM events WHERE kind=? AND source_id=? ORDER BY received_at DESC LIMIT 5000', h.logic.kind, lab.id); backtest = { source_id: lab.id, source_name: lab.name, events: labRows.length, would_alert: labRows.filter(r => matches(h, JSON.parse(r.payload).details)).length }; }
    const quality=this.quality(id),result = { passed, backtest, samples: samples.length, failures: samples.filter(x => !x.ok).length, replay: { window_days: 30, events: rows.length, would_alert: hits, rate: rows.length ? Math.round(hits / rows.length * 1000) / 1000 : null },quality_gate:{unit_samples_passed:passed,environment:h.environment_tuning.environment,tuning_exclusions:h.environment_tuning.exclusions.length,false_positive_analysis:{...quality,budget_percent:h.environment_tuning.false_positive_budget_percent,state:quality.false_positive_rate===null?'not-measured':quality.false_positive_rate<=h.environment_tuning.false_positive_budget_percent/100?'within-budget':'over-budget'}}, tested_by: actor, tested_at: this.now(), notes: text(input.notes, 'hypothesis_test_notes', 2000, true) };
    this.s.transaction(() => { this.s.run('UPDATE detection_hypotheses SET status=?,test_json=? WHERE id=?', passed ? 'tested' : 'draft', JSON.stringify(result), id); this.s.audit(actor, 'hypothesis.tested', String(id), { passed, samples: samples.length, would_alert: hits }, this.now()); });
    return this.get(id);
  }
  decide(actor, id, decision, note, { canary_hours = 24 } = {}) {
    choice(decision, ['approve', 'reject', 'retire'], 'hypothesis_decision'); const h = this.get(id);
    if (decision === 'approve') { fail(h.status === 'tested' && h.test?.passed, 409, 'hypothesis_requires_passing_manual_test'); fail(h.author !== actor && h.test.tested_by !== actor, 403, 'independent_hypothesis_approver_required'); fail(h.test.backtest && h.test.backtest.events > 0 && h.test.backtest.would_alert > 0, 409, 'hypothesis_requires_lab_backtest_that_fires'); }
    if (decision === 'retire') fail(h.status === 'approved', 409, 'hypothesis_not_approved');
    if (decision === 'approve') fail(h.lifecycle_stage !== 'canary', 409, 'hypothesis_already_in_canary');
    const status = { approve: 'approved', reject: 'rejected', retire: 'retired' }[decision], hours = decision === 'approve' ? integer(canary_hours, 1, 336, 'canary_hours') : null;
    this.s.transaction(() => { this.s.run('UPDATE detection_hypotheses SET status=?,decided_by=?,decided_at=?,decision_note=? WHERE id=?', status, actor, this.now(), text(note, 'hypothesis_decision_note', 1000, true), id);
      if (decision === 'approve') { const content = this.content(h), signature = this.signer.sign(content); this.s.run('INSERT INTO hypothesis_versions(hypothesis_id,version,content,signature,signer_fingerprint,approved_by,approved_at) VALUES (?,?,?,?,?,?,?)', id, h.version, JSON.stringify(content), signature, this.signer.fingerprint, actor, this.now()); this.s.run("UPDATE detection_hypotheses SET lifecycle_stage='canary',canary_version=?,canary_started_at=?,canary_until=? WHERE id=?", h.version, this.now(), new Date(this.clock() + hours * 3600000).toISOString(), id); }
      if (decision === 'reject') this.s.run('UPDATE detection_hypotheses SET lifecycle_stage=NULL,canary_version=NULL,canary_started_at=NULL,canary_until=NULL WHERE id=?', id);
      if (decision === 'retire') this.s.run("UPDATE detection_hypotheses SET active_version=NULL,lifecycle_stage='retired',canary_version=NULL,canary_until=NULL,canary_started_at=NULL WHERE id=?", id);
      this.s.audit(actor, `hypothesis.${status}`, String(id), { rule_id: h.rule_id, version: h.version }, this.now()); });
    this.cache = null; this.canaryCache = null; return this.get(id);
  }
  // The running version of each rule is read from its signed version record; a record whose signature does not verify
  // (changed outside CyberGuard) is not evaluated and raises CG-RULE-TAMPER-066 once.
  active() {
    if (this.cache) return this.cache;
    const out = [];
    for (const r of this.s.all("SELECT h.id,h.title,h.severity,h.active_version,v.content,v.signature FROM detection_hypotheses h JOIN hypothesis_versions v ON v.hypothesis_id=h.id AND v.version=h.active_version WHERE h.active_version IS NOT NULL AND h.status!='retired'")) {
      const content = JSON.parse(r.content), rule_id = `CG-HYP-${String(r.id).padStart(4, '0')}`;
      if (!this.signer.verify(content, r.signature) || content.id !== r.id || content.version !== r.active_version) { const key = `${r.id}:${r.active_version}`; if (!this.tamperReported.has(key)) { this.tamperReported.add(key); this.domain.alert({ key: `CG-RULE-TAMPER-066:${key}`, rule: 'CG-RULE-TAMPER-066', severity: 'critical', title: `Detection rule signature invalid; rule not evaluated / توقيع قاعدة كشف غير صالح؛ لم تُقيَّم: ${rule_id} v${r.active_version}` }); } continue; }
      out.push({ ...content, rule_id });
    }
    return (this.cache = out);
  }
  // A change to an approved rule becomes a new draft version; the approved version keeps running until the new one passes
  // its manual test and independent approval.
  revise(actor, id, input) {
    object(input, ['title', 'severity', 'rationale', 'logic','environment_tuning'], 'hypothesis_revision'); const h = this.get(id);
    fail(['approved', 'retired', 'rejected'].includes(h.status), 409, 'hypothesis_revise_requires_decided_rule');
    const logic = input.logic ? validateLogic(input.logic, this.evidenceKinds) : h.logic,environment_tuning=input.environment_tuning?validateEnvironmentTuning(input.environment_tuning):h.environment_tuning, severity = input.severity ? choice(input.severity, ['low', 'medium', 'high', 'critical'], 'severity') : h.severity;
    const title = input.title ? text(input.title, 'hypothesis_title', 200) : h.title, rationale = input.rationale ? text(input.rationale, 'hypothesis_rationale', 2000) : h.rationale, version = h.version + 1;
    this.s.transaction(() => { this.s.run("UPDATE detection_hypotheses SET title=?,severity=?,rationale=?,logic=?,environment_tuning=?,version=?,status='draft',test_json=NULL,author=?,decided_by=NULL,decided_at=NULL,decision_note=NULL WHERE id=?", title, severity, rationale, JSON.stringify(logic),JSON.stringify(environment_tuning), version, actor, id); this.s.audit(actor, 'hypothesis.revised', String(id), { version, active_version: h.active_version,environment:environment_tuning.environment,tuning_exclusions:environment_tuning.exclusions.length }, this.now()); });
    this.cache = null; this.canaryCache = null; return this.get(id);
  }
  // Rollback to an earlier signed version: immediate, administrator with recent MFA (checked by the route), audited.
  rollback(actor, id, version, reason) {
    const h = this.get(id), v = this.s.get('SELECT * FROM hypothesis_versions WHERE hypothesis_id=? AND version=?', id, version); fail(v, 404, 'hypothesis_version_not_found');
    const content = JSON.parse(v.content); fail(this.signer.verify(content, v.signature), 409, 'hypothesis_version_signature_invalid');
    const why = text(reason, 'hypothesis_rollback_reason', 1000);
    this.s.transaction(() => { this.s.run("UPDATE detection_hypotheses SET active_version=?,status='approved',title=?,severity=?,logic=?,environment_tuning=?,version=?,test_json=NULL WHERE id=?", version, content.title, content.severity, JSON.stringify(content.logic),JSON.stringify(content.environment_tuning||validateEnvironmentTuning()), Math.max(h.version, version), id); this.s.audit(actor, 'hypothesis.rolled_back', String(id), { from_version: h.active_version, to_version: version, reason: why }, this.now()); });
    this.cache = null; this.canaryCache = null; return this.get(id);
  }
  trustedKeys() { return [{ fingerprint: this.signer.fingerprint, label: 'this installation', public_key: this.signer.publicKeyPem, own: true }, ...this.s.all('SELECT fingerprint,label,public_key,added_by,added_at FROM trusted_rule_keys WHERE revoked_at IS NULL ORDER BY added_at').map(k => ({ ...k, own: false }))]; }
  trustKey(actor, input) {
    object(input, ['public_key', 'label'], 'rule_key'); let fp; try { fp = fingerprint(String(input.public_key)); } catch { fail(false, 400, 'invalid_rule_public_key'); }
    fail(String(input.public_key).includes('BEGIN PUBLIC KEY'), 400, 'invalid_rule_public_key'); const label = text(input.label, 'rule_key_label', 200);
    this.s.transaction(() => { this.s.run('INSERT INTO trusted_rule_keys(fingerprint,public_key,label,added_by,added_at) VALUES (?,?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET label=excluded.label,revoked_at=NULL', fp, String(input.public_key), label, actor, this.now()); this.s.audit(actor, 'rule_key.trusted', fp, { label }, this.now()); });
    return { fingerprint: fp, label };
  }
  // Export the running versions as a signed pack for another installation.
  exportPack() {
    const items = this.active().map(({ rule_id, id, ...c }) => ({ ...c, rationale: this.get(id).rationale, origin_rule_id: rule_id }));
    const pack = { schema_version: 'cg.rule-pack/1', created_at: this.now(), publisher_fingerprint: this.signer.fingerprint, items };
    return { pack, signature: this.signer.sign(pack), public_key: this.signer.publicKeyPem };
  }
  // Import: only packs signed by a trusted key; every item arrives as a draft that must pass the local manual test and approval.
  importPack(actor, input) {
    object(input, ['pack', 'signature', 'public_key'], 'rule_pack'); const pack = input.pack;
    fail(pack && pack.schema_version === 'cg.rule-pack/1' && Array.isArray(pack.items) && pack.items.length <= 200, 400, 'invalid_rule_pack');
    const key = this.s.get('SELECT * FROM trusted_rule_keys WHERE fingerprint=? AND revoked_at IS NULL', String(pack.publisher_fingerprint || ''));
    fail(key, 403, 'rule_pack_publisher_not_trusted'); fail(verifySignature(pack, input.signature, key.public_key), 403, 'rule_pack_signature_invalid');
    const created = pack.items.map(item => this.create(actor, { title: item.title, source_type: item.source_type, source_ref: item.source_ref, technique_ids: item.technique_ids, severity: item.severity, rationale: item.rationale || 'Imported from a signed rule pack', logic: item.logic,environment_tuning:item.environment_tuning||validateEnvironmentTuning() }).id);
    this.s.audit(actor, 'rule_pack.imported', key.fingerprint, { items: created.length, label: key.label }, this.now());
    return { imported: created.length, ids: created, status: 'draft', publisher: key.label };
  }
  // Called for every stored event: only approved hypotheses for the event kind are evaluated.
  evaluate(event) {
    for (const h of this.active().filter(x => x.logic.kind === event.kind)) if (matches(h, event.details || {})) {
      this.domain.alert({ key: `${h.rule_id}:v${h.version}:${event.asset_id}:${event.observed_at.slice(0, 10)}`, assetId: event.asset_id, sourceId: event.source_id, rule: h.rule_id, ruleVersion: `${h.version}.0.0`, severity: h.severity, title: `Detection hypothesis / فرضية كشف: ${h.title}`, eventId: event.id });
      this.checkNoise(h);
    }
    // CG-165 canary: evaluated in the shadow; hits are recorded for review, no alert is raised.
    for (const c of this.canaries().filter(x => x.logic.kind === event.kind)) if (matches(c, event.details || {})) this.s.run('INSERT OR IGNORE INTO canary_hits(hypothesis_id,version,event_id,at) VALUES (?,?,?,?)', c.id, c.version, event.id, this.now());
  }
  canaries() {
    if (this.canaryCache) return this.canaryCache;
    const out = [];
    for (const r of this.s.all("SELECT h.id,h.canary_version,v.content,v.signature FROM detection_hypotheses h JOIN hypothesis_versions v ON v.hypothesis_id=h.id AND v.version=h.canary_version WHERE h.lifecycle_stage='canary' AND h.canary_version IS NOT NULL AND h.status='approved'")) {
      const content = JSON.parse(r.content); if (this.signer.verify(content, r.signature) && content.version === r.canary_version) out.push({ ...content, rule_id: `CG-HYP-${String(r.id).padStart(4, '0')}` });
    }
    return (this.canaryCache = out);
  }
  canaryStats(h) {
    if (!h.canary_version) return null;
    const rows = this.s.all('SELECT disposition FROM canary_hits WHERE hypothesis_id=? AND version=?', h.id, h.canary_version), reviewed = rows.filter(r => r.disposition), fp = reviewed.filter(r => r.disposition === 'false-positive').length;
    const days = Math.max(1, (Math.min(this.clock(), Date.parse(h.canary_until)) - Date.parse(h.canary_started_at)) / 86400000); // canaries shorter than a day are compared with one day of the limit
    return { version: h.canary_version, started_at: h.canary_started_at, until: h.canary_until, hits: rows.length, reviewed: reviewed.length, false_positives: fp, false_positive_rate: reviewed.length ? Math.round(fp / reviewed.length * 1000) / 1000 : null, hits_per_day: Math.round(rows.length / days * 10) / 10 };
  }
  lifecycle(h) {
    const c = this.canaryStats(h), t = h.environment_tuning, budget = t.false_positive_budget_percent / 100, needed = c ? Math.min(c.hits, 10) : 0;
    const gates = c ? { canary_elapsed: this.now() >= c.until, reviewed_enough: c.reviewed >= needed, false_positives_within_budget: c.false_positive_rate === null || c.false_positive_rate <= budget, noise_within_limit: c.hits_per_day <= t.max_alerts_per_day } : null;
    return { stage: h.lifecycle_stage || h.status, backtest: h.test?.backtest || null, canary: c, gates, promotable: !!gates && Object.values(gates).every(Boolean), reviews_needed: needed, max_alerts_per_day: t.max_alerts_per_day, previous_version: h.previous_version ?? null,
      auto_rollbacks: this.s.all("SELECT at,details FROM audit WHERE action='hypothesis.auto_rolled_back' AND target=? ORDER BY seq DESC LIMIT 5", String(h.id)).map(r => ({ at: r.at, ...JSON.parse(r.details) })) };
  }
  canaryReview(actor, id, input) {
    object(input, ['event_id', 'disposition'], 'canary_review'); const h = this.get(id); fail(h.lifecycle_stage === 'canary', 409, 'hypothesis_not_in_canary');
    const disposition = choice(input.disposition, ['true-positive', 'false-positive'], 'canary_disposition'), ev = text(input.event_id, 'canary_event_id', 64);
    const r = this.s.run('UPDATE canary_hits SET disposition=?,reviewed_by=?,reviewed_at=? WHERE hypothesis_id=? AND version=? AND event_id=?', disposition, actor, this.now(), id, h.canary_version, ev); fail(r.changes === 1, 404, 'canary_hit_not_found');
    this.s.audit(actor, 'hypothesis.canary_reviewed', String(id), { version: h.canary_version, event_id: ev, disposition }, this.now()); return this.lifecycle(this.get(id));
  }
  promote(actor, id) {
    const h = this.get(id); fail(h.lifecycle_stage === 'canary', 409, 'hypothesis_not_in_canary'); const l = this.lifecycle(h);
    fail(l.gates.canary_elapsed, 409, 'canary_period_not_elapsed'); fail(l.gates.reviewed_enough, 409, 'canary_hits_need_review'); fail(l.gates.false_positives_within_budget, 409, 'canary_false_positives_over_budget'); fail(l.gates.noise_within_limit, 409, 'canary_too_noisy');
    this.s.transaction(() => { this.s.run("UPDATE detection_hypotheses SET previous_version=active_version,active_version=canary_version,lifecycle_stage='published',canary_version=NULL,canary_started_at=NULL,canary_until=NULL WHERE id=?", id); this.s.audit(actor, 'hypothesis.promoted', String(id), { version: h.canary_version, previous_version: h.active_version, canary: l.canary }, this.now()); });
    this.cache = null; this.canaryCache = null; return this.get(id);
  }
  // Noise guard: more alerts in 24 hours than the limit, or a false-positive rate over budget on at least five decided
  // alerts of the running version, rolls back to the last good signed version (or suspends a rule that has none).
  checkNoise(h) {
    const row = this.get(h.id), t = row.environment_tuning, since = new Date(this.clock() - 86400000).toISOString(), ver = `${h.version}.0.0`;
    const alerts = this.s.get('SELECT COUNT(*) n FROM alerts WHERE rule_id=? AND rule_version=? AND last_seen>=?', h.rule_id, ver, since).n;
    const d = this.s.all('SELECT d.disposition FROM alert_dispositions d JOIN alerts a ON a.id=d.alert_id WHERE a.rule_id=? AND a.rule_version=?', h.rule_id, ver), fp = d.filter(x => x.disposition === 'false-positive').length;
    const reason = alerts > t.max_alerts_per_day ? `${alerts} alerts in 24 hours (limit ${t.max_alerts_per_day})` : d.length >= 5 && fp / d.length > t.false_positive_budget_percent / 100 ? `false-positive rate ${Math.round(fp / d.length * 100)}% over budget ${t.false_positive_budget_percent}%` : null;
    if (!reason) return;
    const prev = row.previous_version && this.s.get('SELECT * FROM hypothesis_versions WHERE hypothesis_id=? AND version=?', h.id, row.previous_version), good = prev && this.signer.verify(JSON.parse(prev.content), prev.signature);
    this.s.run(good ? "UPDATE detection_hypotheses SET active_version=?,previous_version=NULL,lifecycle_stage='rolled-back' WHERE id=?" : "UPDATE detection_hypotheses SET active_version=NULL,lifecycle_stage='suspended' WHERE id=?", ...(good ? [row.previous_version, h.id] : [h.id]));
    this.s.audit('detection-lifecycle', 'hypothesis.auto_rolled_back', String(h.id), { from_version: h.version, to_version: good ? row.previous_version : null, reason }, this.now());
    this.domain.alert({ key: `CG-RULE-NOISE-165:${h.id}:${h.version}`, rule: 'CG-RULE-NOISE-165', severity: 'medium', title: `Noisy detection rule rolled back automatically / تراجع تلقائي عن قاعدة كشف كثيرة الضجيج: ${h.rule_id} v${h.version} → ${good ? 'v' + row.previous_version : 'suspended'} (${reason})`.slice(0, 300) });
    this.cache = null;
  }
}
