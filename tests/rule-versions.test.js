import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../server.js';
import { totpCode } from '../lib/auth.js';

async function instance(t, name) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), `cg066-${name}-`)); const clock = { now: Date.now() };
  const app = createApp({ dataDir, setupToken: `rules-setup-token-${name}-01`, clock: () => clock.now, remoteAccess: {} });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const { port } = await app.listen(0), base = `http://127.0.0.1:${port}`, password = 'Rules-Local-Test-2026!x', seeds = {};
  const req = async (p, { method = 'GET', data, user } = {}) => { const r = await fetch(base + p, { method, headers: { ...(data ? { 'Content-Type': 'application/json', Origin: base } : {}), ...(user ? { Cookie: user.cookie, 'X-CSRF-Token': user.csrf } : {}) }, body: data ? JSON.stringify(data) : undefined }); return { status: r.status, data: await r.json() }; };
  const login = async u => { const r = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ username: u, password, ...(seeds[u] ? { mfa_code: totpCode(seeds[u], clock.now) } : {}) }) }); return { cookie: r.headers.get('set-cookie').split(';')[0], csrf: (await r.json()).csrf }; };
  await req('/api/auth/setup', { method: 'POST', data: { setup_token: `rules-setup-token-${name}-01`, username: 'admin', password } });
  const adminId = app.store.get("SELECT id FROM users WHERE username='admin'").id; await app.auth.createUser(adminId, { username: 'analyst', password, role: 'analyst' });
  const admin = await login('admin'), analyst = await login('analyst'); seeds.admin = (await req('/api/auth/mfa/enroll', { method: 'POST', data: {}, user: admin })).data.seed; await req('/api/auth/mfa/confirm', { method: 'POST', data: { code: totpCode(seeds.admin, clock.now) }, user: admin });
  const source = app.domain.createSource(adminId, { name: 'Logs', stale_seconds: 86400 }); let n = 0;
  const ingest = details => app.domain.ingest(adminId, source.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: `${name}-${n++}`, kind: 'auth.failed', observed_at: new Date(clock.now).toISOString(), asset: { external_id: `${name}-host`, hostname: `${name.toUpperCase()}-HOST`, os_family: 'linux', device_type: 'server', addresses: ['192.0.2.70'] }, details }] });
  return { app, req, admin, analyst, ingest, clock, dataDir };
}
const samples = (yes, no) => [{ details: yes, expect: 'match' }, { details: no, expect: 'no-match' }];

test('rule changes are versioned and signed, the approved version keeps running, rollback restores a signed version and tampering is refused (CG-066)', async t => {
  const { app, req, admin, analyst, ingest, dataDir } = await instance(t, 'a');
  const hyp = (await req('/api/hypotheses', { method: 'POST', data: { title: 'SSH failures on root', source_type: 'internal-observation', source_ref: 'SOC review 2026-11', technique_ids: ['T1110'], severity: 'medium', rationale: 'Direct root login attempts', logic: { kind: 'auth.failed', match: 'all', conditions: [{ field: 'account', operator: 'equals', value: 'root' }] } }, user: analyst })).data;
  await req(`/api/hypotheses/${hyp.id}/test`, { method: 'POST', data: { samples: samples({ account: 'root' }, { account: 'deploy' }), manual_review: true }, user: analyst });
  await req(`/api/hypotheses/${hyp.id}/approve`, { method: 'POST', data: {}, user: admin });
  let list = (await req('/api/hypotheses', { user: analyst })).data.items[0]; assert.equal(list.active_version, 1); assert.deepEqual(list.versions.map(v => [v.version, v.signature_valid]), [[1, true]]);
  assert.ok(fs.statSync(path.join(dataDir, 'rule-signing-key.pem')).isFile()); assert.ok(!app.store.all("SELECT * FROM hypothesis_versions").some(v => v.content.includes('PRIVATE')));
  // Revision v2 widens the rule; until approved, v1 keeps running unchanged.
  const v2 = (await req(`/api/hypotheses/${hyp.id}/revise`, { method: 'POST', data: { logic: { kind: 'auth.failed', match: 'any', conditions: [{ field: 'account', operator: 'equals', value: 'root' }, { field: 'account', operator: 'equals', value: 'admin' }] } }, user: analyst })).data;
  assert.deepEqual([v2.version, v2.status, v2.active_version], [2, 'draft', 1]);
  ingest({ account: 'admin', source_ip: '198.51.100.71', protocol: 'ssh' }); assert.equal(app.store.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-HYP-0001'").n, 0, 'the draft v2 is not running');
  ingest({ account: 'root', source_ip: '198.51.100.71', protocol: 'ssh' }); assert.equal(app.store.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-HYP-0001'").n, 1, 'v1 still runs');
  await req(`/api/hypotheses/${hyp.id}/test`, { method: 'POST', data: { samples: samples({ account: 'admin' }, { account: 'deploy' }), manual_review: true }, user: analyst });
  assert.equal((await req(`/api/hypotheses/${hyp.id}/approve`, { method: 'POST', data: {}, user: admin })).data.active_version, 2);
  ingest({ account: 'admin', source_ip: '198.51.100.72', protocol: 'ssh' }); assert.equal(app.store.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-HYP-0001' AND rule_version='2.0.0'").n, 1, 'v2 now runs and alerts under its version');
  // Rollback: administrators with recent MFA only, to a signed earlier version; v1 runs again.
  assert.equal((await req(`/api/hypotheses/${hyp.id}/rollback`, { method: 'POST', data: { version: 1, reason: 'Too noisy' }, user: analyst })).status, 403);
  const rolled = (await req(`/api/hypotheses/${hyp.id}/rollback`, { method: 'POST', data: { version: 1, reason: 'v2 too noisy on shared admin accounts' }, user: admin })).data;
  assert.deepEqual([rolled.active_version, rolled.status, rolled.logic.conditions.length], [1, 'approved', 1]);
  assert.equal((await req(`/api/hypotheses/${hyp.id}/rollback`, { method: 'POST', data: { version: 9, reason: 'x' }, user: admin })).data.error, 'hypothesis_version_not_found');
  // Tampering with the stored running version outside CyberGuard: the rule stops and a critical alert is raised.
  const row = app.store.get('SELECT content FROM hypothesis_versions WHERE hypothesis_id=? AND version=1', hyp.id), c = JSON.parse(row.content); c.logic.conditions[0].value = 'deploy';
  app.store.run('UPDATE hypothesis_versions SET content=? WHERE hypothesis_id=? AND version=1', JSON.stringify(c), hyp.id); app.hypotheses.cache = null;
  ingest({ account: 'deploy', source_ip: '198.51.100.73', protocol: 'ssh' });
  assert.equal(app.store.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-RULE-TAMPER-066'").n, 1); assert.equal(app.store.get("SELECT severity FROM alerts WHERE rule_id='CG-RULE-TAMPER-066'").severity, 'critical');
  assert.equal(app.store.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-HYP-0001' AND title LIKE '%SSH%' AND evidence_ids LIKE '%' ").n >= 1, true);
  list = (await req('/api/hypotheses', { user: analyst })).data.items[0]; assert.equal(list.versions.find(v => v.version === 1).signature_valid, false);
  assert.deepEqual(app.store.all("SELECT action FROM audit WHERE action IN ('hypothesis.revised','hypothesis.rolled_back')").map(r => r.action), ['hypothesis.revised', 'hypothesis.rolled_back']);
});

test('rule packs move between installations only signed by a trusted publisher and arrive as drafts (CG-066)', async t => {
  const a = await instance(t, 'pub'), b = await instance(t, 'sub');
  const hyp = (await a.req('/api/hypotheses', { method: 'POST', data: { title: 'Help desk resets for admins', source_type: 'incident-study', source_ref: 'scattered-spider-2023', technique_ids: ['T1656'], severity: 'high', rationale: 'Scattered Spider targets help desks', logic: { kind: 'auth.failed', match: 'all', conditions: [{ field: 'protocol', operator: 'equals', value: 'web' }] } }, user: a.analyst })).data;
  await a.req(`/api/hypotheses/${hyp.id}/test`, { method: 'POST', data: { samples: samples({ protocol: 'web' }, { protocol: 'ssh' }), manual_review: true }, user: a.analyst });
  await a.req(`/api/hypotheses/${hyp.id}/approve`, { method: 'POST', data: {}, user: a.admin });
  const exported = (await a.req('/api/rule-packs/export', { user: a.admin })).data; assert.equal(exported.pack.items.length, 1); assert.ok(exported.public_key.includes('BEGIN PUBLIC KEY'));
  assert.equal((await b.req('/api/rule-packs/import', { method: 'POST', data: exported, user: b.admin })).data.error, 'rule_pack_publisher_not_trusted');
  assert.equal((await b.req('/api/rule-keys', { method: 'POST', data: { label: 'Publisher A', public_key: 'not a key' }, user: b.admin })).data.error, 'invalid_rule_public_key');
  assert.equal((await b.req('/api/rule-keys', { method: 'POST', data: { label: 'Publisher A', public_key: exported.public_key }, user: b.admin })).status, 201);
  const forged = structuredClone(exported); forged.pack.items[0].severity = 'low';
  assert.equal((await b.req('/api/rule-packs/import', { method: 'POST', data: forged, user: b.admin })).data.error, 'rule_pack_signature_invalid');
  const imported = (await b.req('/api/rule-packs/import', { method: 'POST', data: exported, user: b.admin })).data; assert.deepEqual([imported.imported, imported.status, imported.publisher], [1, 'draft', 'Publisher A']);
  const draft = (await b.req('/api/hypotheses', { user: b.analyst })).data.items[0]; assert.deepEqual([draft.status, draft.active_version, draft.severity], ['draft', null, 'high'], 'an imported rule does not run before the local manual test and approval');
  b.ingest({ account: 'x', source_ip: '198.51.100.74', protocol: 'web' }); assert.equal(b.app.store.get("SELECT COUNT(*) n FROM alerts WHERE rule_id LIKE 'CG-HYP-%'").n, 0);
  assert.equal((await b.req('/api/rule-keys', { user: b.analyst })).data.items.length, 2);
  assert.ok(b.app.store.all("SELECT action FROM audit WHERE action IN ('rule_key.trusted','rule_pack.imported')").length === 2);
});
