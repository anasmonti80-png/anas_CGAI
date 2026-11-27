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
  // CG-165: a lab source for the backtest, and publish = approve into a one-hour canary, then promote.
  const lab = app.domain.createSource(adminId, { name: `Lab replay ${name}`, stale_seconds: 86400 }); let ln = 0;
  const labIngest = details => app.domain.ingest(adminId, lab.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: `${name}-lab-${ln++}`, kind: 'auth.failed', observed_at: new Date(clock.now).toISOString(), asset: { external_id: `${name}-lab`, hostname: 'LAB-HOST', os_family: 'linux', device_type: 'server', addresses: ['192.0.2.71'] }, details }] });
  const publish = async (id, data = {}) => { const r = (await req(`/api/hypotheses/${id}/approve`, { method: 'POST', data: { canary_hours: 1, ...data }, user: admin })).data; if (r.lifecycle_stage !== 'canary') return r; clock.now += 3600001; app.store.run('UPDATE sessions SET mfa_at=?,last_seen=?,expires_at=?', clock.now, clock.now, clock.now + 28800000); return (await req(`/api/hypotheses/${id}/promote`, { method: 'POST', data: {}, user: admin })).data; };
  return { app, req, admin, analyst, ingest, clock, dataDir, lab, labIngest, publish };
}
const samples = (yes, no) => [{ details: yes, expect: 'match' }, { details: no, expect: 'no-match' }];

test('rule changes are versioned and signed, the approved version keeps running, rollback restores a signed version and tampering is refused (CG-066)', async t => {
  const { app, req, admin, analyst, ingest, dataDir, lab, labIngest, publish } = await instance(t, 'a');
  labIngest({ account: 'root', source_ip: '198.51.100.90', protocol: 'ssh' }); labIngest({ account: 'admin', source_ip: '198.51.100.91', protocol: 'ssh' });
  const hyp = (await req('/api/hypotheses', { method: 'POST', data: { title: 'SSH failures on root', source_type: 'internal-observation', source_ref: 'SOC review 2026-11', technique_ids: ['T1110'], severity: 'medium', rationale: 'Direct root login attempts', logic: { kind: 'auth.failed', match: 'all', conditions: [{ field: 'account', operator: 'equals', value: 'root' }] } }, user: analyst })).data;
  await req(`/api/hypotheses/${hyp.id}/test`, { method: 'POST', data: { samples: samples({ account: 'root' }, { account: 'deploy' }), manual_review: true, lab_source_id: lab.id }, user: analyst });
  await publish(hyp.id);
  let list = (await req('/api/hypotheses', { user: analyst })).data.items[0]; assert.equal(list.active_version, 1); assert.deepEqual(list.versions.map(v => [v.version, v.signature_valid]), [[1, true]]);
  assert.ok(fs.statSync(path.join(dataDir, 'rule-signing-key.pem')).isFile()); assert.ok(!app.store.all("SELECT * FROM hypothesis_versions").some(v => v.content.includes('PRIVATE')));
  // Revision v2 widens the rule; until approved, v1 keeps running unchanged.
  const v2 = (await req(`/api/hypotheses/${hyp.id}/revise`, { method: 'POST', data: { logic: { kind: 'auth.failed', match: 'any', conditions: [{ field: 'account', operator: 'equals', value: 'root' }, { field: 'account', operator: 'equals', value: 'admin' }] } }, user: analyst })).data;
  assert.deepEqual([v2.version, v2.status, v2.active_version], [2, 'draft', 1]);
  ingest({ account: 'admin', source_ip: '198.51.100.71', protocol: 'ssh' }); assert.equal(app.store.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-HYP-0001'").n, 0, 'the draft v2 is not running');
  ingest({ account: 'root', source_ip: '198.51.100.71', protocol: 'ssh' }); assert.equal(app.store.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-HYP-0001'").n, 1, 'v1 still runs');
  await req(`/api/hypotheses/${hyp.id}/test`, { method: 'POST', data: { samples: samples({ account: 'admin' }, { account: 'deploy' }), manual_review: true, lab_source_id: lab.id }, user: analyst });
  assert.equal((await publish(hyp.id)).active_version, 2);
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
  const a = await instance(t, 'pub'), b = await instance(t, 'sub'); a.labIngest({ account: 'helpdesk', source_ip: '198.51.100.92', protocol: 'web' });
  const hyp = (await a.req('/api/hypotheses', { method: 'POST', data: { title: 'Help desk resets for admins', source_type: 'incident-study', source_ref: 'scattered-spider-2023', technique_ids: ['T1656'], severity: 'high', rationale: 'Scattered Spider targets help desks', logic: { kind: 'auth.failed', match: 'all', conditions: [{ field: 'protocol', operator: 'equals', value: 'web' }] } }, user: a.analyst })).data;
  await a.req(`/api/hypotheses/${hyp.id}/test`, { method: 'POST', data: { samples: samples({ protocol: 'web' }, { protocol: 'ssh' }), manual_review: true, lab_source_id: a.lab.id }, user: a.analyst });
  await a.publish(hyp.id);
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

test('Detection-as-Code versions environment tuning, measures false positives and keeps the signed version active after a failed update (CG-111)',async t=>{
  const {app,req,admin,analyst,ingest,lab,labIngest,publish}=await instance(t,'dac');labIngest({account:'root',source_ip:'198.51.100.93',protocol:'ssh'});const tuning={environment:'production',exclusions:[{field:'account',operator:'equals',value:'svc-health',reason:'Approved production health probe'}],false_positive_budget_percent:10};
  const created=(await req('/api/hypotheses',{method:'POST',user:analyst,data:{title:'Production root authentication failures',source_type:'internal-observation',source_ref:'SOC-CG-111',technique_ids:['T1110'],severity:'high',rationale:'Detect root failures while excluding the documented health probe',logic:{kind:'auth.failed',match:'all',conditions:[{field:'account',operator:'in',value:['root','svc-health']}]},environment_tuning:tuning}})).data;
  const samples=[{details:{account:'root'},expect:'match'},{details:{account:'svc-health'},expect:'no-match'}];const tested=(await req(`/api/hypotheses/${created.id}/test`,{method:'POST',user:analyst,data:{samples,manual_review:true,notes:'Production tuning and exclusion reviewed',lab_source_id:lab.id}})).data;assert.equal(tested.test.quality_gate.unit_samples_passed,true);assert.equal(tested.test.quality_gate.environment,'production');assert.equal(tested.test.quality_gate.tuning_exclusions,1);assert.equal(tested.test.quality_gate.false_positive_analysis.state,'not-measured');await publish(created.id,{note:'Independent Detection-as-Code review'});
  ingest({account:'svc-health',source_ip:'198.51.100.111',protocol:'ssh'});assert.equal(app.store.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-HYP-0001'").n,0,'the signed environment exclusion is enforced');ingest({account:'root',source_ip:'198.51.100.112',protocol:'ssh'});const alert=app.store.get("SELECT id FROM alerts WHERE rule_id='CG-HYP-0001'");assert.ok(alert);await req(`/api/alerts/${alert.id}/disposition`,{method:'POST',user:analyst,data:{disposition:'false-positive',note:'Authorized production maintenance'}});let row=(await req('/api/hypotheses',{user:analyst})).data.items[0];assert.deepEqual([row.quality.false_positives,row.quality.dispositioned,row.quality.state],[1,1,'over-budget']);const signed=JSON.parse(app.store.get('SELECT content FROM hypothesis_versions WHERE hypothesis_id=? AND version=1',created.id).content);assert.deepEqual(signed.environment_tuning,{...tuning,max_alerts_per_day:50});
  const revision=(await req(`/api/hypotheses/${created.id}/revise`,{method:'POST',user:analyst,data:{environment_tuning:{...tuning,exclusions:[]}}})).data;assert.deepEqual([revision.version,revision.active_version,revision.status],[2,1,'draft']);const failed=(await req(`/api/hypotheses/${created.id}/test`,{method:'POST',user:analyst,data:{samples,manual_review:true,notes:'Update failed because the known production exclusion regressed'}})).data;assert.equal(failed.test.passed,false);assert.equal(failed.active_version,1,'failed update cannot replace the last signed version');row=(await req('/api/hypotheses',{user:analyst})).data.items[0];assert.equal(row.versions.length,1);assert.equal(row.versions[0].signature_valid,true);assert.equal(app.hypotheses.active()[0].environment_tuning.exclusions.length,1);assert.ok(app.store.all("SELECT action FROM audit WHERE action IN ('hypothesis.revised','hypothesis.tested')").length>=2);
});
