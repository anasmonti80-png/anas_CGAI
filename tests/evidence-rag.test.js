import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { EvidenceRag, redactForRole } from '../lib/evidence-rag.js';

test('secrets are always hidden and personal data is hidden according to the reader role (CG-122)', () => {
  const v = { account: 'ahmed.ali', note: 'contact ahmed@example.org or 0551234567, id 1012345678, host 10.0.4.7, key AKIAABCDEFGHIJKLMNOP password=Hunter2!' };
  const admin = redactForRole(v, 'admin').value, analyst = redactForRole(v, 'analyst').value, viewer = redactForRole(v, 'viewer');
  for (const out of [admin, analyst, viewer.value]) { assert.ok(!out.note.includes('AKIA') && !out.note.includes('Hunter2'), 'secrets never shown'); assert.ok(!out.note.includes('1012345678') && !out.note.includes('0551234567')); }
  assert.equal(admin.account, 'ahmed.ali'); assert.match(admin.note, /ahmed@example\.org/); assert.match(admin.note, /10\*{6}78/); assert.match(admin.note, /10\.0\.4\.7/);
  assert.equal(analyst.account, 'ahmed.ali'); assert.match(analyst.note, /a\*\*\*@example\.org/); assert.match(analyst.note, /\[national-id\]/); assert.match(analyst.note, /10\.0\.4\.7/);
  assert.equal(viewer.value.account, '[person]'); assert.match(viewer.value.note, /\[email\]/); assert.match(viewer.value.note, /\[internal-address\]/); assert.ok(viewer.redactions >= 6);
});

test('answers cite dated, hashed snapshots, are stored unchanged and show the uncertainty of each claim (CG-122)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.parse('2026-11-22T10:00:00.000Z'); const d = new Domain(s, { clock: () => now }), rag = new EvidenceRag(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'u', 'u', 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString());
  const src = d.createSource('u', { name: 'Logs', stale_seconds: 3600 }), asset = { external_id: 'srv-01', hostname: 'SRV-01', os_family: 'windows', device_type: 'server', addresses: ['10.0.0.5'] };
  for (let i = 0; i < 5; i++) { d.ingest('u', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: `f${i}`, kind: 'auth.failed', observed_at: new Date(now).toISOString(), asset, details: { account: 'ahmed.ali', source_ip: '203.0.113.99', protocol: 'rdp' } }] }); now += 20000; }
  const alertId = s.get("SELECT id FROM alerts WHERE rule_id='CG-AUTH-FAILURES-5-IN-5M'").id;
  const viewer = rag.ground({ id: 'v', role: 'viewer' }, d.aiAnalysis(alertId));
  assert.equal(viewer.redaction.role, 'viewer'); assert.equal(viewer.redaction.policy.accounts, 'hidden'); assert.ok(!JSON.stringify(viewer).includes('ahmed.ali'), 'the viewer never sees the account');
  const cited = viewer.grounded_claims.flatMap(c => c.citations).filter(c => c.snapshot_id); assert.ok(cited.length >= 4); assert.ok(cited.every(c => /^[a-f0-9]{64}$/.test(c.sha256) && c.captured_at));
  const what = viewer.grounded_claims.find(c => c.section === 'what_happened'); assert.equal(what.uncertainty.level, 'medium'); assert.deepEqual(what.uncertainty.reasons.map(r => r.id), ['single-source']);
  assert.equal(s.get('SELECT COUNT(*) n FROM ai_answers').n, 1); assert.throws(() => s.run("UPDATE ai_answers SET role='admin'"), /answer_immutable/); assert.throws(() => s.run("UPDATE ai_source_snapshots SET content='{}'"), /snapshot_immutable/);
  // Later, with stale evidence and a silent source, a new answer shows more uncertainty; the old one keeps its snapshots.
  now += 9 * 86400000; const later = rag.ground({ id: 'a', role: 'analyst' }, d.aiAnalysis(alertId));
  const reasons = later.grounded_claims.find(c => c.section === 'what_happened').uncertainty.reasons.map(r => r.id); assert.ok(reasons.includes('stale-evidence') && reasons.includes('silent-source')); assert.ok(later.uncertain_claims.includes('claim:what-happened'));
  assert.ok(later.grounded_claims.flatMap(c => c.citations).some(c => c.snapshot_id && cited.some(x => x.snapshot_id === c.snapshot_id)), 'unchanged sources reuse the same snapshot');
  const stored = rag.get({ id: 'x', role: 'admin' }, viewer.answer_id); assert.equal(stored.answer_intact, true); assert.equal(stored.snapshots_intact, true); assert.equal(stored.generated_for_role, 'viewer');
  const snap = rag.snapshotFor({ id: 'v', role: 'viewer' }, cited.find(c => c.source_id.startsWith('log:')).snapshot_id); assert.equal(snap.content.details.account, '[person]');
  assert.equal(rag.snapshotFor({ id: 'a', role: 'admin' }, cited.find(c => c.source_id.startsWith('log:')).snapshot_id).content.details.account, 'ahmed.ali');
  assert.equal(rag.recent({ role: 'admin' }).length, 2); assert.ok(viewer.grounding_claim_ar.includes('نسخة مؤرخة'));
});
