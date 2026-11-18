import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createApp } from '../server.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));

test('precision, false positives, MTTD/MTTR, device and rule coverage and response failures are measured from real triage (CG-058)', async t => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg058-')); let now = Date.now();
  const app = createApp({ dataDir, setupToken: 'quality-setup-token-0001', clock: () => now, remoteAccess: {} });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const { port } = await app.listen(0), base = `http://127.0.0.1:${port}`, password = 'Quality-Local-Test-2026!x';
  const req = async (p, { method = 'GET', data, user } = {}) => { const r = await fetch(base + p, { method, headers: { ...(data ? { 'Content-Type': 'application/json', Origin: base } : {}), ...(user ? { Cookie: user.cookie, 'X-CSRF-Token': user.csrf } : {}) }, body: data ? JSON.stringify(data) : undefined }); return { status: r.status, data: await r.json() }; };
  const login = async u => { const r = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ username: u, password }) }); assert.equal(r.status, 200); return { cookie: r.headers.get('set-cookie').split(';')[0], csrf: (await r.json()).csrf }; };
  await req('/api/auth/setup', { method: 'POST', data: { setup_token: 'quality-setup-token-0001', username: 'admin', password } });
  const adminId = app.store.get("SELECT id FROM users WHERE username='admin'").id;
  await app.auth.createUser(adminId, { username: 'analyst', password, role: 'analyst' }); await app.auth.createUser(adminId, { username: 'viewer', password, role: 'viewer' });
  const analyst = await login('analyst'), viewer = await login('viewer');
  // Real connector output: Security Hub findings raise CG-CLOUD-FINDING-046 alerts linked to their evidence.
  const out = path.join(dataDir, 'asff.json'); execFileSync(process.execPath, [path.join(ROOT, 'scripts', 'aws-connector.js'), 'findings-asff', '--input', path.join(ROOT, 'tests', 'fixtures', 'aws', 'securityhub-findings.json'), '--output', out]);
  const source = app.domain.createSource(adminId, { name: 'AWS read-only', stale_seconds: 86400 }), file = JSON.parse(fs.readFileSync(out, 'utf8'));
  const observed = Date.parse(file.events[0].observed_at); now = observed + 5 * 60000; app.domain.ingest(adminId, source.id, file);
  const alerts = app.store.all('SELECT id,rule_id,first_seen,evidence_ids FROM alerts ORDER BY id'); assert.ok(alerts.length >= 3, `alerts ${alerts.length}`);
  // Nothing measured before triage: no invented precision or MTTR.
  let m = (await req('/api/quality-metrics?days=30', { user: analyst })).data;
  assert.equal(m.detection_quality.precision, null); assert.equal(m.timing.mttr_minutes, null); assert.equal(m.detection_quality.not_triaged, alerts.length);
  assert.ok(m.timing.mttd_samples >= alerts.length && m.timing.mttd_minutes >= 4.9 && m.timing.mttd_minutes <= 5.1, 'MTTD is measured from evidence time to alert time');
  const firstEvidence = Math.min(...JSON.parse(alerts[0].evidence_ids).map(id => Date.parse(app.store.get('SELECT observed_at FROM events WHERE id=?', id).observed_at)));
  assert.ok(firstEvidence <= Date.parse(alerts[0].first_seen) && observed <= now);
  // Triage 30 and 90 minutes later: two true positives and one false positive.
  assert.equal((await req(`/api/alerts/${alerts[0].id}/disposition`, { method: 'POST', data: { disposition: 'true-positive' }, user: viewer })).status, 403, 'viewers cannot disposition');
  assert.equal((await req(`/api/alerts/${alerts[0].id}/disposition`, { method: 'POST', data: { disposition: 'maybe' }, user: analyst })).status, 400);
  now += 30 * 60000; Object.assign(analyst, await login('analyst')); const d1 = await req(`/api/alerts/${alerts[0].id}/disposition`, { method: 'POST', data: { disposition: 'true-positive', note: 'Confirmed exposed bucket' }, user: analyst });
  assert.equal(d1.status, 200); assert.equal(d1.data.status, 'resolved'); assert.equal(d1.data.disposition.disposition, 'true-positive');
  await req(`/api/alerts/${alerts[1].id}/disposition`, { method: 'POST', data: { disposition: 'false-positive', note: 'Expected public website bucket' }, user: analyst });
  now += 60 * 60000; Object.assign(analyst, await login('analyst')); await req(`/api/alerts/${alerts[2].id}/disposition`, { method: 'POST', data: { disposition: 'benign-true-positive' }, user: analyst });
  m = (await req('/api/quality-metrics?days=30', { user: analyst })).data;
  assert.deepEqual([m.detection_quality.true_positive, m.detection_quality.benign_true_positive, m.detection_quality.false_positive], [1, 1, 1]);
  assert.equal(m.detection_quality.precision, 0.667); assert.equal(m.detection_quality.false_positive_rate, 0.333);
  assert.deepEqual([m.timing.mttr_minutes, m.timing.mttr_samples], [60, 2], 'MTTR averages the true and benign positives (30 and 90 minutes)');
  const rule = m.by_rule.find(r => r.rule_id === alerts[0].rule_id); assert.equal(rule.precision, 0.667); assert.equal(rule.state, 'measured');
  assert.equal(app.store.all("SELECT * FROM audit WHERE action='alert.dispositioned'").length, 3);
  // Coverage: the AWS source is receiving; catalog rules without evidence of their kind are shown as blind, not as passing.
  assert.equal(m.device_coverage.coverage, 1); assert.ok(m.device_coverage.assets >= 1);
  assert.ok(m.rule_coverage.catalog_rules > 0 && m.rule_coverage.rules_with_evidence_received < m.rule_coverage.catalog_rules); assert.ok(m.rule_coverage.blind_rules.length > 0);
  // Response failures: one verified and one failed action through a connector.
  const asset = app.store.get('SELECT id FROM assets LIMIT 1').id, ts = new Date(now).toISOString();
  for (const status of ['verified', 'failed']) { const id = crypto.randomUUID(); app.store.run('INSERT INTO actions(id,type,asset_id,requested_by,approved_by,reason,requested_at,expires_at,preflight_hash,before_value,after_value,status,result,executed_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', id, 'network.block-ip', asset, adminId, adminId, 'quality metric fixture', ts, ts, 'x', '{}', '{}', status, status, null);
    app.store.run('INSERT INTO response_jobs(action_id,source_id,connector_id,request_json,phase,status,queued_at,completed_at,completion_json) VALUES (?,?,?,?,?,?,?,?,?)', id, source.id, 'SYNTHETIC-FW-058', '{}', 'execute', status === 'verified' ? 'succeeded' : 'failed', ts, ts, '{}'); }
  m = (await req('/api/quality-metrics', { user: analyst })).data;
  assert.equal(m.response_failures.action_failure_rate, 0.5); assert.equal(m.response_failures.job_failure_rate, 0.5); assert.deepEqual(m.response_failures.failed_by_type, { 'network.block-ip': 1 });
  assert.equal(m.response_failures.by_connector[0].connector_id, 'SYNTHETIC-FW-058');
  // Window: outside 1..365 days is refused; a 1-day window 3 days later excludes everything.
  assert.equal((await req('/api/quality-metrics?days=0', { user: analyst })).data.error, 'invalid_metric_days');
  now += 3 * 86400000; const later = await login('analyst'); m = (await req('/api/quality-metrics?days=1', { user: later })).data; assert.equal(m.detection_quality.alerts, 0); assert.equal(m.detection_quality.precision, null);
  assert.match(m.claim, /not measured instead of a guess/); assert.ok(m.claim_ar.includes('غير مُقاس'));
});
