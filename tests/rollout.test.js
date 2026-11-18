import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../server.js';
import { totpCode } from '../lib/auth.js';

test('rollout moves from isolated lab to authorized pilot to expansion only on measured gates with a second administrator (CG-062)', async t => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg062-')); let now = Date.now();
  const app = createApp({ dataDir, setupToken: 'rollout-setup-token-0001', clock: () => now, remoteAccess: {} });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  // The gate reads the test evidence of the running build; this test uses its own passing evidence file.
  const evidenceFile = path.join(dataDir, 'verification.json'); fs.writeFileSync(evidenceFile, JSON.stringify({ passed: true, fail: 0, tests: 245, level: 'Unit Tested', at: new Date(now).toISOString() })); app.rollout.verificationFile = evidenceFile;
  const { port } = await app.listen(0), base = `http://127.0.0.1:${port}`, password = 'Rollout-Local-Test-2026!x';
  const req = async (p, { method = 'GET', data, user } = {}) => { const r = await fetch(base + p, { method, headers: { ...(data ? { 'Content-Type': 'application/json', Origin: base } : {}), ...(user ? { Cookie: user.cookie, 'X-CSRF-Token': user.csrf } : {}) }, body: data ? JSON.stringify(data) : undefined }); return { status: r.status, data: await r.json() }; };
  const seeds = {}, login = async u => { const r = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ username: u, password, ...(seeds[u] ? { mfa_code: totpCode(seeds[u], now) } : {}) }) }); assert.equal(r.status, 200); return { cookie: r.headers.get('set-cookie').split(';')[0], csrf: (await r.json()).csrf }; };
  await req('/api/auth/setup', { method: 'POST', data: { setup_token: 'rollout-setup-token-0001', username: 'admin', password } });
  const adminId = app.store.get("SELECT id FROM users WHERE username='admin'").id; await app.auth.createUser(adminId, { username: 'admin2', password, role: 'admin' });
  const mfa = async u => { const s = await login(u); seeds[u] = (await req('/api/auth/mfa/enroll', { method: 'POST', data: {}, user: s })).data.seed; await req('/api/auth/mfa/confirm', { method: 'POST', data: { code: totpCode(seeds[u], now) }, user: s }); return s; };
  let a = await mfa('admin'), b = await mfa('admin2');
  const source = app.domain.createSource(adminId, { name: 'Lab and pilot sensors', stale_seconds: 86400 });
  const host = (ref, ip) => ({ external_id: ref, hostname: ref.toUpperCase(), os_family: 'windows', device_type: 'workstation', addresses: [ip] });
  const ingest = events => app.domain.ingest(adminId, source.id, { schema_version: 'cg.telemetry/1', events: events.map(e => ({ observed_at: new Date(now).toISOString(), ...e })) });
  ingest([{ event_id: 'lab', kind: 'asset.observed', asset: host('lab-win-01', '192.0.2.50'), details: {} }, { event_id: 'branch', kind: 'asset.observed', asset: host('branch-01', '192.0.2.51'), details: {} }, { event_id: 'hq', kind: 'asset.observed', asset: host('hq-01', '192.0.2.52'), details: {} }]);
  const assetId = ref => app.store.get('SELECT id FROM assets WHERE external_id=?', ref).id;
  // Nothing declared: the first stage is the isolated lab; jumping to the pilot is refused by its gate.
  let st = (await req('/api/rollout', { user: a })).data; assert.equal(st.declared, false); assert.equal(st.next_stage, 'isolated-lab'); assert.equal(st.next_gate.ready, true); assert.ok(st.claim_ar.includes('مختبر معزول'));
  let r = await req('/api/rollout', { method: 'POST', data: { stage: 'limited-pilot', asset_refs: ['branch-01'], authorization_ref: 'CHG-PILOT-062' }, user: a }); assert.equal(r.data.error, 'rollout_gate_not_met');
  r = await req('/api/rollout', { method: 'POST', data: { stage: 'isolated-lab', asset_refs: ['lab-win-01'], authorization_ref: 'LAB-ISO-062' }, user: a }); assert.equal(r.status, 201); assert.equal(r.data.status, 'pending');
  assert.equal((await req(`/api/rollout/${r.data.id}/approve`, { method: 'POST', data: {}, user: a })).data.error, 'independent_rollout_approver_required');
  assert.equal((await req(`/api/rollout/${r.data.id}/approve`, { method: 'POST', data: {}, user: b })).data.status, 'active');
  // In the lab, response actions are refused outside the lab scope.
  const preview = (ref, user) => req('/api/actions/preview', { method: 'POST', data: { type: 'network.block-ip', asset_id: assetId(ref), target: { ip: '198.51.100.62' }, connector_id: 'SYNTHETIC-FW-062', authorization_ref: 'IR-062', reason: 'Rollout scope check', ttl_seconds: 600 }, user });
  assert.equal((await preview('hq-01', a)).data.error, 'outside_rollout_stage_scope');
  assert.notEqual((await preview('lab-win-01', a)).data.error, 'outside_rollout_stage_scope', 'inside the lab scope the normal response checks apply');
  // Pilot gate: a within-plan lab validation run and an explicit scope without wildcards.
  r = await req('/api/rollout', { method: 'POST', data: { stage: 'limited-pilot', asset_refs: ['branch-01'], authorization_ref: 'CHG-PILOT-062' }, user: a }); assert.equal(r.data.error, 'rollout_gate_not_met');
  const iso = m => new Date(now + m * 60000).toISOString();
  ingest([{ event_id: 'plan', kind: 'validation.test_plan', asset: host('lab-win-01', '192.0.2.50'), details: { plan_id: 'LAB-062', tier: 'low-impact-validation', title: 'Lab detection validation', authorization_ref: 'LAB-ISO-062', approved_by: 'ciso', second_approver: null, window_start: iso(-60), window_end: iso(60), environment: 'lab', targets: { asset_refs: ['lab-win-01'], networks: [] }, techniques: [{ id: 'credentialed-config-check', name: 'Read-only configuration check' }], safeguards: { rate_limit_per_minute: 6, stop_conditions: ['isolation lost'], rollback: null, isolation_evidence_ref: 'LAB-ISO' }, status: 'approved' } },
    { event_id: 'run', kind: 'validation.test_run', asset: host('lab-win-01', '192.0.2.50'), details: { run_id: 'RUN-062', plan_id: 'LAB-062', started_at: iso(-30), ended_at: iso(-20), executed_by: 'tester', results: [{ technique_id: 'credentialed-config-check', target_ref: 'lab-win-01', outcome: 'pass', observation: null, evidence_ref: null }] } }]);
  assert.equal((await req('/api/rollout', { method: 'POST', data: { stage: 'limited-pilot', asset_refs: ['*'], authorization_ref: 'CHG-PILOT-062' }, user: a })).data.error, 'rollout_gate_not_met', 'a wildcard pilot scope is refused');
  r = await req('/api/rollout', { method: 'POST', data: { stage: 'limited-pilot', asset_refs: ['branch-01', 'lab-win-01'], authorization_ref: 'CHG-PILOT-062' }, user: a }); assert.equal(r.status, 201, JSON.stringify(r.data));
  assert.equal((await req(`/api/rollout/${r.data.id}/approve`, { method: 'POST', data: {}, user: b })).data.stage, 'limited-pilot');
  assert.equal((await preview('hq-01', a)).data.error, 'outside_rollout_stage_scope'); assert.notEqual((await preview('branch-01', a)).data.error, 'outside_rollout_stage_scope');
  // Expansion gate: too early, then after 8 days with ten triaged alerts (precision 0.8) it opens.
  st = (await req('/api/rollout', { user: a })).data; assert.equal(st.next_stage, 'expansion'); assert.equal(st.next_gate.checks.find(c => c.id === 'pilot-duration').ok, false);
  now += 8 * 86400000; a = await login('admin'); b = await login('admin2');
  ingest(Array.from({ length: 50 }, (_, i) => ({ event_id: `fail-${i}`, kind: 'auth.failed', asset: host('branch-01', '192.0.2.51'), details: { account: `pilot-user-${Math.floor(i / 5)}`, source_ip: '198.51.100.70', protocol: 'rdp' } })));
  const alerts = app.store.all("SELECT id FROM alerts WHERE rule_id='CG-AUTH-FAILURES-5-IN-5M'"); assert.equal(alerts.length, 10);
  for (const [i, al] of alerts.entries()) await req(`/api/alerts/${al.id}/disposition`, { method: 'POST', data: { disposition: i < 8 ? 'true-positive' : 'false-positive' }, user: a });
  st = (await req('/api/rollout', { user: a })).data; assert.equal(st.next_gate.ready, true, JSON.stringify(st.next_gate.checks.filter(c => !c.ok)));
  assert.equal(st.next_gate.checks.find(c => c.id === 'precision').measured, '0.8');
  r = await req('/api/rollout', { method: 'POST', data: { stage: 'expansion', authorization_ref: 'CHG-EXPAND-062' }, user: b }); assert.equal(r.status, 201);
  assert.equal((await req(`/api/rollout/${r.data.id}/approve`, { method: 'POST', data: {}, user: a })).data.status, 'active');
  assert.notEqual((await preview('hq-01', a)).data.error, 'outside_rollout_stage_scope', 'after expansion every asset is in scope');
  // Moving back to the lab needs no gate but still a second administrator; history and audit keep every step.
  r = await req('/api/rollout', { method: 'POST', data: { stage: 'isolated-lab', asset_refs: ['lab-win-01'], authorization_ref: 'ROLLBACK-062' }, user: a }); assert.equal(r.status, 201);
  assert.equal((await req(`/api/rollout/${r.data.id}/reject`, { method: 'POST', data: {}, user: b })).data.status, 'rejected');
  st = (await req('/api/rollout', { user: a })).data; assert.equal(st.active.stage, 'expansion'); assert.deepEqual(st.history.map(x => x.status), ['rejected', 'active', 'superseded', 'superseded']);
  assert.equal(app.store.all("SELECT * FROM audit WHERE action LIKE 'rollout.%'").length, 8);
  // A failing build cannot open a stage.
  fs.writeFileSync(evidenceFile, JSON.stringify({ passed: false, fail: 3, tests: 245 })); assert.equal(app.rollout.gate('isolated-lab').ready, false);
});
