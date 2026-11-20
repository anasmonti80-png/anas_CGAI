import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../server.js';
import { totpCode } from '../lib/auth.js';
import { triage, quarantine, parseYaraLite } from '../lib/file-triage.js';

test('detonation runs only in a registered isolated sandbox after independent approval and stops on any isolation breach (CG-093)', async t => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg093-')); let now = Date.now();
  const app = createApp({ dataDir, setupToken: 'sandbox-setup-token-0001', clock: () => now, remoteAccess: {} });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const { port } = await app.listen(0), base = `http://127.0.0.1:${port}`, password = 'Sandbox-Local-Test-2026!x', seeds = {};
  const req = async (p, { method = 'GET', data, user, bearer } = {}) => { const r = await fetch(base + p, { method, headers: { ...(data ? { 'Content-Type': 'application/json', Origin: base } : {}), ...(user ? { Cookie: user.cookie, 'X-CSRF-Token': user.csrf } : {}), ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}) }, body: data ? JSON.stringify(data) : undefined }); return { status: r.status, data: await r.json() }; };
  const login = async u => { const r = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ username: u, password, ...(seeds[u] ? { mfa_code: totpCode(seeds[u], now) } : {}) }) }); return { cookie: r.headers.get('set-cookie').split(';')[0], csrf: (await r.json()).csrf }; };
  await req('/api/auth/setup', { method: 'POST', data: { setup_token: 'sandbox-setup-token-0001', username: 'admin', password } });
  const adminId = app.store.get("SELECT id FROM users WHERE username='admin'").id; await app.auth.createUser(adminId, { username: 'admin2', password, role: 'admin' }); await app.auth.createUser(adminId, { username: 'analyst', password, role: 'analyst' });
  const mfa = async u => { const s = await login(u); seeds[u] = (await req('/api/auth/mfa/enroll', { method: 'POST', data: {}, user: s })).data.seed; await req('/api/auth/mfa/confirm', { method: 'POST', data: { code: totpCode(seeds[u], now) }, user: s }); return s; };
  let a = await mfa('admin'), b = await mfa('admin2'), analyst = await login('analyst');
  // A real quarantined file from triage (CG-092).
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'cg093-files-')); t.after(() => fs.rmSync(work, { recursive: true, force: true }));
  const file = path.join(work, 'loader.txt'); fs.writeFileSync(file, 'CG-SYNTHETIC-TRIAGE-MARKER-093 payload');
  const rules = parseYaraLite('rule M {\n  strings:\n    $a = "CG-SYNTHETIC-TRIAGE-MARKER-093"\n  condition:\n    any of them\n}'), r = await triage(file, { rules }), custody = quarantine(file, path.join(work, 'q'), { sha256: r.sha256, reason: 'Lab detonation candidate' });
  const logs = app.domain.createSource(adminId, { name: 'Endpoint triage', stale_seconds: 86400 });
  app.domain.ingest(adminId, logs.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'triage-1', kind: 'file.triage', observed_at: new Date(now).toISOString(), asset: { external_id: 'host:lab-ws', hostname: 'LAB-WS', os_family: 'windows', device_type: 'workstation', addresses: [] }, details: { ...r, rules_engine: 'built-in', quarantine: { state: 'quarantined', custody_id: custody.custody_id, record_hash: custody.record_hash, location: custody.location } } }] });
  // Not enabled until an administrator registers a sandbox fed by a dedicated sandbox-connector source.
  assert.equal((await req('/api/detonations', { user: analyst })).data.enabled, false);
  assert.equal((await req('/api/sandboxes', { method: 'POST', data: { name: 'CAPE lab', source_id: logs.id, isolation_ref: 'LAB-VLAN-999 no route', egress: 'none' }, user: a })).data.error, 'sandbox_requires_sandbox_connector_source');
  const conn = app.domain.createSource(adminId, { name: 'CAPE lab connector', stale_seconds: 86400, source_type: 'sandbox-connector' });
  assert.equal((await req('/api/sandboxes', { method: 'POST', data: { name: 'CAPE lab', source_id: conn.id, isolation_ref: 'LAB-VLAN-999 no route', egress: 'none' }, user: analyst })).status, 403);
  const sb = (await req('/api/sandboxes', { method: 'POST', data: { name: 'CAPE lab', source_id: conn.id, isolation_ref: 'LAB-VLAN-999 no route', egress: 'none' }, user: a })).data; assert.equal(sb.status, 'active');
  assert.equal((await req(`/api/sources/${conn.id}/events`, { method: 'POST', data: { schema_version: 'cg.telemetry/1', events: [{ event_id: 'x', kind: 'asset.observed', observed_at: new Date(now).toISOString(), asset: { external_id: 'x' }, details: {} }] }, bearer: conn.token })).data.error, 'sandbox_connector_cannot_ingest_telemetry');
  // Requests need a quarantined file; approval by a different administrator.
  assert.equal((await req('/api/detonations', { method: 'POST', data: { sandbox_id: sb.id, sha256: 'a'.repeat(64), reason: 'Unknown sample' }, user: analyst })).data.error, 'detonation_requires_quarantined_file');
  const job = (await req('/api/detonations', { method: 'POST', data: { sandbox_id: sb.id, sha256: r.sha256, reason: 'Confirm loader behaviour' }, user: analyst })).data; assert.equal(job.status, 'pending-approval');
  assert.equal((await req(`/api/detonations/${job.id}/approve`, { method: 'POST', data: {}, user: analyst })).status, 403);
  const own = (await req('/api/detonations', { method: 'POST', data: { sandbox_id: sb.id, sha256: r.sha256, reason: 'Own request' }, user: a })).data;
  assert.equal((await req(`/api/detonations/${own.id}/approve`, { method: 'POST', data: {}, user: a })).data.error, 'independent_detonation_approver_required');
  assert.equal((await req(`/api/detonations/${own.id}/reject`, { method: 'POST', data: {}, user: b })).data.status, 'rejected');
  assert.equal((await req(`/api/detonations/${job.id}/approve`, { method: 'POST', data: {}, user: a })).data.status, 'approved');
  // No passing isolation check: no jobs. A passing check within 24 hours releases the hash only.
  let jobs = await req(`/api/sources/${conn.id}/sandbox/jobs`, { bearer: conn.token }); assert.deepEqual([jobs.data.items.length, jobs.data.isolation_state], [0, 'no-isolation-check']);
  const check = { checked_at: new Date(now).toISOString(), internet_reachable: false, production_reachable: false, evidence_ref: 'cape-egress-test-1', probes: [{ target: '8.8.8.8:53', reachable: false }, { target: 'prod-gw:443', reachable: false }] };
  assert.equal((await req(`/api/sources/${conn.id}/sandbox/isolation`, { method: 'POST', data: check, bearer: conn.token })).data.state, 'isolated');
  jobs = await req(`/api/sources/${conn.id}/sandbox/jobs`, { bearer: conn.token }); assert.deepEqual(jobs.data.items, [{ job_id: job.id, sha256: r.sha256, file_name: 'loader.txt', custody_id: custody.custody_id }]);
  assert.equal((await req(`/api/sources/${conn.id}/sandbox/jobs`, { bearer: conn.token })).data.items.length, 0, 'a job is released once');
  const report = { sha256: r.sha256, verdict: 'malicious', duration_seconds: 240, processes: ['loader.exe', 'powershell.exe -enc ...'], network_attempts: [{ destination: 'c2.example.net', port: 443, blocked: true }], files_written: ['%APPDATA%\\x.dll'], registry_changes: ['HKCU\\...\\Run\\x'], signatures: ['persistence_autorun'], evidence_ref: 'cape-task-77' };
  assert.equal((await req(`/api/sources/${conn.id}/sandbox/jobs/${job.id}/report`, { method: 'POST', data: { ...report, sha256: 'b'.repeat(64) }, bearer: conn.token })).data.error, 'detonation_report_hash_mismatch');
  const done = (await req(`/api/sources/${conn.id}/sandbox/jobs/${job.id}/report`, { method: 'POST', data: report, bearer: conn.token })).data; assert.equal(done.status, 'completed'); assert.equal(done.report.verdict, 'malicious');
  assert.equal(app.store.get("SELECT severity FROM alerts WHERE rule_id='CG-SANDBOX-VERDICT-093'").severity, 'high');
  // A stale isolation check (over 24 hours) holds new jobs back.
  const job2 = (await req('/api/detonations', { method: 'POST', data: { sandbox_id: sb.id, sha256: r.sha256, reason: 'Second run with simulated internet' }, user: analyst })).data;
  await req(`/api/detonations/${job2.id}/approve`, { method: 'POST', data: {}, user: a }); now += 25 * 3600000;
  assert.equal((await req(`/api/sources/${conn.id}/sandbox/jobs`, { bearer: conn.token })).data.isolation_state, 'isolation-check-stale');
  await req(`/api/sources/${conn.id}/sandbox/isolation`, { method: 'POST', data: { ...check, checked_at: new Date(now).toISOString() }, bearer: conn.token });
  assert.equal((await req(`/api/sources/${conn.id}/sandbox/jobs`, { bearer: conn.token })).data.items.length, 1);
  // An unblocked network attempt during detonation suspends the sandbox and raises a critical alert.
  await req(`/api/sources/${conn.id}/sandbox/jobs/${job2.id}/report`, { method: 'POST', data: { ...report, network_attempts: [{ destination: '203.0.113.50', port: 443, blocked: false }] }, bearer: conn.token });
  assert.equal(app.store.get('SELECT status FROM sandboxes WHERE id=?', sb.id).status, 'suspended'); assert.equal(app.store.get("SELECT severity FROM alerts WHERE rule_id='CG-SANDBOX-ISOLATION-093'").severity, 'critical');
  a = await login('admin'); analyst = await login('analyst');
  assert.equal((await req('/api/detonations', { method: 'POST', data: { sandbox_id: sb.id, sha256: r.sha256, reason: 'Third run' }, user: analyst })).data.error, 'sandbox_not_active');
  assert.equal((await req(`/api/sources/${conn.id}/sandbox/jobs`, { bearer: conn.token })).data.isolation_state, 'suspended');
  const ov = (await req('/api/detonations', { user: analyst })).data; assert.ok(ov.claim_ar.includes('لا تلقائيًا')); assert.equal(ov.jobs.length, 3);
  assert.deepEqual(app.store.all("SELECT action FROM audit WHERE action LIKE 'detonation.%' OR action LIKE 'sandbox.%' ORDER BY seq").map(x => x.action).filter((v, i, all) => all.indexOf(v) === i).sort(), ['detonation.approved', 'detonation.rejected', 'detonation.reported', 'detonation.requested', 'sandbox.isolation_checked', 'sandbox.registered', 'sandbox.suspended']);
});
