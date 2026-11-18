// CG-065 Detection hypotheses from published evidence. An analyst writes a hypothesis citing its source (an advisory or
// an incident study) as a declarative condition over one evidence kind; nothing from the source is executed. The
// hypothesis is tested against labelled samples (must match / must not match) and replayed over recent stored events to
// show how often it would fire, a person attests the manual review, and a different administrator with recent MFA
// approves it. Only approved hypotheses are evaluated on new evidence, raising alerts under their own rule ID.
import { fail, object, text, choice } from './common.js';
import { incidentStudies } from './incident-studies.js';
import { fingerprint, verifySignature } from './rule-signing.js';
// CG-066 every approved version is kept and signed; edits create a new version while the approved one keeps running;
// rollback restores an earlier signed version; packs move between installations only signed by a trusted key.

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
export const matches = (h, details) => h.logic.match === 'any' ? h.logic.conditions.some(c => matchCondition(c, details)) : h.logic.conditions.every(c => matchCondition(c, details));

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
  content(h) { return { id: h.id, version: h.version, title: h.title, severity: h.severity, technique_ids: h.technique_ids, source_type: h.source_type, source_ref: h.source_ref, logic: h.logic }; }
  versions(id) { return this.s.all('SELECT version,signer_fingerprint,approved_by,approved_at,signature,content FROM hypothesis_versions WHERE hypothesis_id=? ORDER BY version DESC', id).map(v => ({ version: v.version, signer_fingerprint: v.signer_fingerprint, approved_by: v.approved_by, approved_at: v.approved_at, signature_valid: this.signer ? this.signer.verify(JSON.parse(v.content), v.signature) : null, content: JSON.parse(v.content) })); }
  now() { return new Date(this.clock()).toISOString(); }
  row(r) { return r ? { ...r, technique_ids: JSON.parse(r.technique_ids), logic: JSON.parse(r.logic), test: r.test_json ? JSON.parse(r.test_json) : null, rule_id: `CG-HYP-${String(r.id).padStart(4, '0')}`, test_json: undefined } : null; }
  get(id) { const r = this.row(this.s.get('SELECT * FROM detection_hypotheses WHERE id=?', id)); fail(r, 404, 'not_found'); return r; }
  list() { return this.s.all('SELECT * FROM detection_hypotheses ORDER BY id DESC LIMIT 200').map(r => ({ ...this.row(r), versions: this.versions(r.id).map(({ content, ...v }) => v) })); }
  create(actor, input) {
    object(input, ['title', 'source_type', 'source_ref', 'technique_ids', 'severity', 'rationale', 'logic'], 'hypothesis');
    const source_type = choice(input.source_type, ['advisory', 'incident-study', 'threat-report', 'internal-observation'], 'hypothesis_source_type');
    const source_ref = text(input.source_ref, 'hypothesis_source_ref', 500);
    if (source_type === 'incident-study') fail(incidentStudies.some(s => s.id === source_ref), 400, 'unknown_incident_study');
    if (source_type === 'advisory' || source_type === 'threat-report') fail(/^https:\/\/[^\s]+$/.test(source_ref), 400, 'hypothesis_source_must_be_https_url');
    fail(Array.isArray(input.technique_ids) && input.technique_ids.length <= 10 && input.technique_ids.every(t => /^T\d{4}(\.\d{3})?$/.test(t)), 400, 'invalid_hypothesis_technique_ids');
    const logic = validateLogic(input.logic, this.evidenceKinds), severity = choice(input.severity, ['low', 'medium', 'high', 'critical'], 'severity');
    const r = this.s.transaction(() => { const res = this.s.run("INSERT INTO detection_hypotheses(title,source_type,source_ref,technique_ids,severity,rationale,logic,status,author,created_at,version) VALUES (?,?,?,?,?,?,?,'draft',?,?,1)", text(input.title, 'hypothesis_title', 200), source_type, source_ref, JSON.stringify(input.technique_ids), severity, text(input.rationale, 'hypothesis_rationale', 2000), JSON.stringify(logic), actor, this.now());
      this.s.audit(actor, 'hypothesis.created', String(res.lastInsertRowid), { source_type, source_ref, kind: logic.kind }, this.now()); return Number(res.lastInsertRowid); });
    return this.get(r);
  }
  // Manual test: labelled samples must all behave as expected (at least one of each), the replay shows how often the
  // hypothesis would have fired on stored evidence of its kind, and the tester attests the manual review.
  test(actor, id, input) {
    object(input, ['samples', 'manual_review', 'notes'], 'hypothesis_test');
    const h = this.get(id); fail(['draft', 'tested', 'rejected'].includes(h.status), 409, 'hypothesis_not_testable');
    fail(Array.isArray(input.samples) && input.samples.length >= 2 && input.samples.length <= 50, 400, 'hypothesis_test_requires_2_to_50_samples');
    const samples = input.samples.map((x, i) => { object(x, ['details', 'expect'], `hypothesis_sample_${i}`); fail(x.details && typeof x.details === 'object' && !Array.isArray(x.details), 400, `invalid_hypothesis_sample_${i}`); const expect = choice(x.expect, ['match', 'no-match'], `hypothesis_sample_expect_${i}`); const got = matches(h, x.details) ? 'match' : 'no-match'; return { expect, got, ok: expect === got }; });
    fail(input.manual_review === true, 400, 'manual_review_attestation_required');
    const since = new Date(this.clock() - 30 * 86400000).toISOString(), rows = this.s.all('SELECT payload FROM events WHERE kind=? AND received_at>=? ORDER BY received_at DESC LIMIT 5000', h.logic.kind, since);
    const hits = rows.filter(r => matches(h, JSON.parse(r.payload).details)).length;
    const passed = samples.every(x => x.ok) && samples.some(x => x.expect === 'match') && samples.some(x => x.expect === 'no-match');
    const result = { passed, samples: samples.length, failures: samples.filter(x => !x.ok).length, replay: { window_days: 30, events: rows.length, would_alert: hits, rate: rows.length ? Math.round(hits / rows.length * 1000) / 1000 : null }, tested_by: actor, tested_at: this.now(), notes: text(input.notes, 'hypothesis_test_notes', 2000, true) };
    this.s.transaction(() => { this.s.run('UPDATE detection_hypotheses SET status=?,test_json=? WHERE id=?', passed ? 'tested' : 'draft', JSON.stringify(result), id); this.s.audit(actor, 'hypothesis.tested', String(id), { passed, samples: samples.length, would_alert: hits }, this.now()); });
    return this.get(id);
  }
  decide(actor, id, decision, note) {
    choice(decision, ['approve', 'reject', 'retire'], 'hypothesis_decision'); const h = this.get(id);
    if (decision === 'approve') { fail(h.status === 'tested' && h.test?.passed, 409, 'hypothesis_requires_passing_manual_test'); fail(h.author !== actor && h.test.tested_by !== actor, 403, 'independent_hypothesis_approver_required'); }
    if (decision === 'retire') fail(h.status === 'approved', 409, 'hypothesis_not_approved');
    const status = { approve: 'approved', reject: 'rejected', retire: 'retired' }[decision];
    this.s.transaction(() => { this.s.run('UPDATE detection_hypotheses SET status=?,decided_by=?,decided_at=?,decision_note=? WHERE id=?', status, actor, this.now(), text(note, 'hypothesis_decision_note', 1000, true), id);
      if (decision === 'approve') { const content = this.content(h), signature = this.signer.sign(content); this.s.run('INSERT INTO hypothesis_versions(hypothesis_id,version,content,signature,signer_fingerprint,approved_by,approved_at) VALUES (?,?,?,?,?,?,?)', id, h.version, JSON.stringify(content), signature, this.signer.fingerprint, actor, this.now()); this.s.run('UPDATE detection_hypotheses SET active_version=? WHERE id=?', h.version, id); }
      if (decision === 'retire') this.s.run('UPDATE detection_hypotheses SET active_version=NULL WHERE id=?', id);
      this.s.audit(actor, `hypothesis.${status}`, String(id), { rule_id: h.rule_id, version: h.version }, this.now()); });
    this.cache = null; return this.get(id);
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
    object(input, ['title', 'severity', 'rationale', 'logic'], 'hypothesis_revision'); const h = this.get(id);
    fail(['approved', 'retired', 'rejected'].includes(h.status), 409, 'hypothesis_revise_requires_decided_rule');
    const logic = input.logic ? validateLogic(input.logic, this.evidenceKinds) : h.logic, severity = input.severity ? choice(input.severity, ['low', 'medium', 'high', 'critical'], 'severity') : h.severity;
    const title = input.title ? text(input.title, 'hypothesis_title', 200) : h.title, rationale = input.rationale ? text(input.rationale, 'hypothesis_rationale', 2000) : h.rationale, version = h.version + 1;
    this.s.transaction(() => { this.s.run("UPDATE detection_hypotheses SET title=?,severity=?,rationale=?,logic=?,version=?,status='draft',test_json=NULL,author=?,decided_by=NULL,decided_at=NULL,decision_note=NULL WHERE id=?", title, severity, rationale, JSON.stringify(logic), version, actor, id); this.s.audit(actor, 'hypothesis.revised', String(id), { version, active_version: h.active_version }, this.now()); });
    this.cache = null; return this.get(id);
  }
  // Rollback to an earlier signed version: immediate, administrator with recent MFA (checked by the route), audited.
  rollback(actor, id, version, reason) {
    const h = this.get(id), v = this.s.get('SELECT * FROM hypothesis_versions WHERE hypothesis_id=? AND version=?', id, version); fail(v, 404, 'hypothesis_version_not_found');
    const content = JSON.parse(v.content); fail(this.signer.verify(content, v.signature), 409, 'hypothesis_version_signature_invalid');
    const why = text(reason, 'hypothesis_rollback_reason', 1000);
    this.s.transaction(() => { this.s.run("UPDATE detection_hypotheses SET active_version=?,status='approved',title=?,severity=?,logic=?,version=?,test_json=NULL WHERE id=?", version, content.title, content.severity, JSON.stringify(content.logic), Math.max(h.version, version), id); this.s.audit(actor, 'hypothesis.rolled_back', String(id), { from_version: h.active_version, to_version: version, reason: why }, this.now()); });
    this.cache = null; return this.get(id);
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
    const created = pack.items.map(item => this.create(actor, { title: item.title, source_type: item.source_type, source_ref: item.source_ref, technique_ids: item.technique_ids, severity: item.severity, rationale: item.rationale || 'Imported from a signed rule pack', logic: item.logic }).id);
    this.s.audit(actor, 'rule_pack.imported', key.fingerprint, { items: created.length, label: key.label }, this.now());
    return { imported: created.length, ids: created, status: 'draft', publisher: key.label };
  }
  // Called for every stored event: only approved hypotheses for the event kind are evaluated.
  evaluate(event) {
    for (const h of this.active().filter(x => x.logic.kind === event.kind)) if (matches(h, event.details || {}))
      this.domain.alert({ key: `${h.rule_id}:v${h.version}:${event.asset_id}:${event.observed_at.slice(0, 10)}`, assetId: event.asset_id, sourceId: event.source_id, rule: h.rule_id, ruleVersion: `${h.version}.0.0`, severity: h.severity, title: `Detection hypothesis / فرضية كشف: ${h.title}`, eventId: event.id });
  }
}
