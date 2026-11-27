import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../server.js';
import { totpCode } from '../lib/auth.js';
import { matchCondition } from '../lib/hypotheses.js';

test('published evidence becomes a declarative hypothesis that alerts only after a passing manual test and independent approval (CG-065)', async t => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg065-')); let now = Date.now();
  const app = createApp({ dataDir, setupToken: 'hypothesis-setup-token-01', clock: () => now, remoteAccess: {} });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const { port } = await app.listen(0), base = `http://127.0.0.1:${port}`, password = 'Hypothesis-Local-2026!x';
  const req = async (p, { method = 'GET', data, user } = {}) => { const r = await fetch(base + p, { method, headers: { ...(data ? { 'Content-Type': 'application/json', Origin: base } : {}), ...(user ? { Cookie: user.cookie, 'X-CSRF-Token': user.csrf } : {}) }, body: data ? JSON.stringify(data) : undefined }); return { status: r.status, data: await r.json() }; };
  const login = async u => { const r = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ username: u, password }) }); return { cookie: r.headers.get('set-cookie').split(';')[0], csrf: (await r.json()).csrf }; };
  await req('/api/auth/setup', { method: 'POST', data: { setup_token: 'hypothesis-setup-token-01', username: 'admin', password } });
  const adminId = app.store.get("SELECT id FROM users WHERE username='admin'").id; await app.auth.createUser(adminId, { username: 'analyst', password, role: 'analyst' });
  const admin = await login('admin'), analyst = await login('analyst');
  const seed = (await req('/api/auth/mfa/enroll', { method: 'POST', data: {}, user: admin })).data.seed; await req('/api/auth/mfa/confirm', { method: 'POST', data: { code: totpCode(seed, now) }, user: admin });
  const source = app.domain.createSource(adminId, { name: 'VPN logs', stale_seconds: 86400 }), asset = { external_id: 'vpn-01', hostname: 'VPN-01', os_family: 'network', device_type: 'firewall', addresses: ['192.0.2.65'] };
  let n = 0; const ingest = details => app.domain.ingest(adminId, source.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: `e-${n++}`, kind: 'auth.failed', observed_at: new Date(now).toISOString(), asset, details }] });
  const hypAlerts = () => app.store.all("SELECT * FROM alerts WHERE rule_id LIKE 'CG-HYP-%'");
  ingest({ account: 'administrator', source_ip: '198.51.100.31', protocol: 'rdp' });
  // Only declarative logic is accepted; sources must be cited; nothing is executed.
  const body = { title: 'Remote desktop attempts on built-in admin accounts', source_type: 'incident-study', source_ref: 'volt-typhoon-2024', technique_ids: ['T1078'], severity: 'high', rationale: 'Volt Typhoon uses valid accounts; built-in admin accounts over RDP from outside deserve review.', logic: { kind: 'auth.failed', match: 'all', conditions: [{ field: 'protocol', operator: 'equals', value: 'rdp' }, { field: 'account', operator: 'in', value: ['administrator', 'admin'] }] } };
  assert.equal((await req('/api/hypotheses', { method: 'POST', data: { ...body, source_type: 'advisory', source_ref: 'http://example.org/x' }, user: analyst })).data.error, 'hypothesis_source_must_be_https_url');
  assert.equal((await req('/api/hypotheses', { method: 'POST', data: { ...body, source_ref: 'not-a-study' }, user: analyst })).data.error, 'unknown_incident_study');
  assert.equal((await req('/api/hypotheses', { method: 'POST', data: { ...body, logic: { ...body.logic, conditions: [{ field: 'x;require("fs")', operator: 'equals', value: 'a' }] } }, user: analyst })).data.error, 'invalid_hypothesis_field_0');
  assert.equal((await req('/api/hypotheses', { method: 'POST', data: { ...body, logic: { ...body.logic, conditions: [{ field: 'account', operator: 'eval', value: 'a' }] } }, user: analyst })).data.error, 'invalid_hypothesis_operator_0');
  assert.equal((await req('/api/hypotheses', { method: 'POST', data: { ...body, logic: { ...body.logic, script: 'return true' } }, user: analyst })).data.error, 'unknown_hypothesis_logic_field');
  const created = await req('/api/hypotheses', { method: 'POST', data: body, user: analyst }); assert.equal(created.status, 201); assert.equal(created.data.status, 'draft'); const id = created.data.id, rule = created.data.rule_id;
  assert.equal(rule, 'CG-HYP-0001');
  // A draft never alerts.
  ingest({ account: 'admin', source_ip: '198.51.100.32', protocol: 'rdp' }); assert.equal(hypAlerts().length, 0);
  // Manual test: attestation required; a wrong sample keeps it a draft; a passing test records the replay.
  const samples = [{ details: { account: 'Administrator', source_ip: '198.51.100.9', protocol: 'rdp' }, expect: 'match' }, { details: { account: 'svc-backup', source_ip: '198.51.100.9', protocol: 'rdp' }, expect: 'no-match' }];
  assert.equal((await req(`/api/hypotheses/${id}/test`, { method: 'POST', data: { samples }, user: analyst })).data.error, 'manual_review_attestation_required');
  let tested = await req(`/api/hypotheses/${id}/test`, { method: 'POST', data: { samples: [samples[0], { ...samples[1], expect: 'match' }], manual_review: true }, user: analyst });
  assert.deepEqual([tested.data.status, tested.data.test.passed, tested.data.test.failures], ['draft', false, 1]);
  tested = await req(`/api/hypotheses/${id}/test`, { method: 'POST', data: { samples, manual_review: true, notes: 'Checked against two weeks of VPN logs', lab_source_id: source.id }, user: analyst });
  assert.equal(tested.data.status, 'tested'); assert.deepEqual([tested.data.test.replay.events, tested.data.test.replay.would_alert], [2, 2], 'replay over stored evidence shows how often it would fire');
  // Approval: administrators only, with recent MFA; never the author or tester.
  assert.equal((await req(`/api/hypotheses/${id}/approve`, { method: 'POST', data: {}, user: analyst })).status, 403);
  const own = await req('/api/hypotheses', { method: 'POST', data: { ...body, title: 'Own hypothesis' }, user: admin });
  await req(`/api/hypotheses/${own.data.id}/test`, { method: 'POST', data: { samples, manual_review: true }, user: admin });
  assert.equal((await req(`/api/hypotheses/${own.data.id}/approve`, { method: 'POST', data: {}, user: admin })).data.error, 'independent_hypothesis_approver_required');
  assert.equal((await req(`/api/hypotheses/${id}/approve`, { method: 'POST', data: { note: 'Reviewed', canary_hours: 1 }, user: admin })).data.lifecycle_stage, 'canary');
  // CG-165: the canary runs in the shadow for an hour, then an administrator with recent MFA promotes it.
  now += 3600001; app.store.run('UPDATE sessions SET mfa_at=?,last_seen=?,expires_at=?', now, now, now + 28800000); assert.equal((await req(`/api/hypotheses/${id}/promote`, { method: 'POST', data: {}, user: admin })).data.lifecycle_stage, 'published');
  // Active: matching new evidence raises an alert under the hypothesis rule; other evidence does not.
  ingest({ account: 'svc-backup', source_ip: '198.51.100.33', protocol: 'rdp' }); assert.equal(hypAlerts().length, 0);
  ingest({ account: 'ADMIN', source_ip: '198.51.100.34', protocol: 'rdp' }); const alerts = hypAlerts(); assert.equal(alerts.length, 1); assert.equal(alerts[0].rule_id, 'CG-HYP-0001'); assert.equal(alerts[0].severity, 'high'); assert.equal(JSON.parse(alerts[0].evidence_ids).length, 1);
  // Retired: stops alerting. Every step is audited.
  assert.equal((await req(`/api/hypotheses/${id}/retire`, { method: 'POST', data: {}, user: admin })).data.status, 'retired');
  now += 86400000; ingest({ account: 'admin', source_ip: '198.51.100.35', protocol: 'rdp' }); assert.equal(hypAlerts().length, 1);
  const actions = app.store.all("SELECT action FROM audit WHERE action LIKE 'hypothesis.%' AND target=?", String(id)).map(r => r.action);
  assert.deepEqual(actions, ['hypothesis.created', 'hypothesis.tested', 'hypothesis.tested', 'hypothesis.approved', 'hypothesis.promoted', 'hypothesis.retired']);
  const list = (await req('/api/hypotheses', { user: await login('analyst') })).data; assert.ok(list.claim_ar.includes('لا يُنفذ شيء من المصدر'));
  // Operators are plain comparisons over values, case-insensitive for text.
  assert.equal(matchCondition({ field: 'a.b', operator: 'gte', value: 5 }, { a: { b: 7 } }), true); assert.equal(matchCondition({ field: 'tags', operator: 'contains', value: 'X' }, { tags: ['ax', 'b'] }), true);
  assert.equal(matchCondition({ field: 'missing', operator: 'exists', value: null }, {}), false);
});
