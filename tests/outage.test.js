import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createApp } from '../server.js';
import { Forwarder } from '../lib/forwarder.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const asset = { external_id: 'branch-fw-01', hostname: 'BRANCH-FW-01', os_family: 'network', device_type: 'firewall', addresses: ['192.0.2.40'] };
const batch = (prefix, n, at) => ({ schema_version: 'cg.telemetry/1', events: Array.from({ length: n }, (_, i) => ({ event_id: `${prefix}-${i}`, kind: 'auth.failed', observed_at: new Date(at).toISOString(), asset, details: { account: `user-${prefix}-${i}`, source_ip: '198.51.100.20', protocol: 'ssh' } })) });

test('collectors queue locally through an outage, retry with backoff and resend without duplicates (CG-060)', async t => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg060-')), spool = fs.mkdtempSync(path.join(os.tmpdir(), 'cg060-spool-'));
  let now = Date.now(); const app = createApp({ dataDir, setupToken: 'outage-setup-token-00001', clock: () => now, remoteAccess: {} });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); fs.rmSync(spool, { recursive: true, force: true }); });
  const { port } = await app.listen(0), base = `http://127.0.0.1:${port}`;
  await fetch(`${base}/api/auth/setup`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ setup_token: 'outage-setup-token-00001', username: 'admin', password: 'Outage-Local-Test-2026!x' }) });
  const adminId = app.store.get("SELECT id FROM users WHERE username='admin'").id, source = app.domain.createSource(adminId, { name: 'Branch syslog forwarder', stale_seconds: 86400, source_type: 'log-forwarder' });
  assert.throws(() => new Forwarder({ spool, url: base, sourceId: source.id, token: '' }), /CG_SOURCE_TOKEN/);
  // The branch loses its link: the forwarder clock is two hours behind the server when the queue builds up.
  let mode = 'down', fclock = now - 2 * 3600000; const real = (u, o) => fetch(u, o);
  const fetchImpl = async (u, o) => { if (mode === 'down') { const e = new Error('connect ECONNREFUSED'); e.code = 'ECONNREFUSED'; throw e; } if (mode === 'lost') { await real(u, o); throw new Error('socket hang up'); } return real(u, o); };
  const fwd = new Forwarder({ spool, url: base, sourceId: source.id, token: source.token, fetchImpl, clock: () => fclock, random: () => 1, baseDelayMs: 1000 });
  assert.throws(() => fwd.enqueue({ schema_version: 'other/1', events: [] }), /unsupported schema_version/);
  const first = fwd.enqueue(batch('a', 3, fclock)); fclock += 1000; fwd.enqueue(batch('b', 2, fclock));
  let r = await fwd.drainOnce(); assert.equal(r.status, 'backoff'); assert.equal(r.last_error, 'ECONNREFUSED'); assert.equal(r.files, 2); assert.equal(r.attempts, 1);
  assert.equal((await fwd.drainOnce()).status, 'waiting', 'no hammering before the backoff delay');
  fclock += 1000; r = await fwd.drainOnce(); assert.equal(r.attempts, 2); assert.equal(Date.parse(r.next_attempt_at) - fclock, 2000, 'exponential backoff doubles the delay');
  assert.equal(app.store.get('SELECT COUNT(*) n FROM events').n, 0, 'nothing arrived during the outage');
  assert.equal(fs.readdirSync(path.join(spool, 'outbox'))[0], first, 'the queue survives on disk in order');
  // The link flaps: the server stores the first batch but the answer is lost, so the forwarder keeps the file.
  mode = 'lost'; fclock += 3000; r = await fwd.drainOnce(); assert.equal(r.status, 'backoff'); assert.equal(r.files, 2);
  assert.equal(app.store.get('SELECT COUNT(*) n FROM events').n, 3);
  // Link restored: the first batch is resent and recognised as duplicates; nothing is stored twice; order is kept.
  mode = 'up'; fclock += 10000; r = await fwd.drainOnce(); assert.deepEqual([r.status, r.delivered, r.duplicates, r.files], ['drained', 2, 3, 0]);
  assert.equal(app.store.get('SELECT COUNT(*) n FROM events').n, 5);
  const receipts = fs.readFileSync(path.join(spool, 'sent', 'receipts.jsonl'), 'utf8').trim().split('\n').map(JSON.parse); assert.deepEqual(receipts.map(x => [x.accepted, x.duplicates]), [[0, 3], [2, 0]]);
  // The server saw a two-hour-old backlog: flagged as a late delivery after an outage.
  const late = app.store.get("SELECT severity,title FROM alerts WHERE rule_id='CG-DELIVERY-BACKLOG-060'"); assert.equal(late.severity, 'medium'); assert.match(late.title, /Branch syslog forwarder/);
  const rec = app.domain.reconciliation(); assert.equal(rec.delivery[0].name, 'Branch syslog forwarder'); assert.ok(rec.delivery[0].max_delay_minutes >= 119); assert.equal(rec.delivery[0].state, 'drained');
  // A batch the server refuses for content (same event_id, different content) is set aside with the reason, not retried forever.
  const changed = batch('a', 1, fclock); changed.events[0].details.protocol = 'rdp'; fwd.enqueue(changed);
  r = await fwd.drainOnce(); assert.deepEqual([r.status, r.rejected, r.files], ['drained', 1, 0]);
  const reason = fs.readdirSync(path.join(spool, 'rejected')).find(f => f.endsWith('.reason.txt')); assert.match(fs.readFileSync(path.join(spool, 'rejected', reason), 'utf8'), /409 event_id_content_conflict/);
  // The command-line tool reports the queue without needing the token.
  const status = JSON.parse(execFileSync(process.execPath, [path.join(ROOT, 'scripts', 'forwarder.js'), 'status', '--spool', spool], { encoding: 'utf8' })); assert.equal(status.files, 0); assert.equal(status.rejected_files, 1);
});

test('response jobs stale after an outage expire for re-approval while rollbacks wait and are verified (CG-060)', async t => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg060r-')); let now = Date.now();
  const app = createApp({ dataDir, setupToken: 'outage-setup-token-00002', clock: () => now, remoteAccess: {} });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const { port } = await app.listen(0), base = `http://127.0.0.1:${port}`, password = 'Outage-Local-Test-2026!x';
  await fetch(`${base}/api/auth/setup`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ setup_token: 'outage-setup-token-00002', username: 'admin', password }) });
  const adminId = app.store.get("SELECT id FROM users WHERE username='admin'").id, logs = app.domain.createSource(adminId, { name: 'Logs', stale_seconds: 86400 }), connector = app.domain.createSource(adminId, { name: 'Firewall response connector', stale_seconds: 86400, source_type: 'response-connector' });
  app.domain.ingest(adminId, logs.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'asset', kind: 'asset.observed', observed_at: new Date(now).toISOString(), asset, details: {} }] });
  const assetId = app.store.get('SELECT id FROM assets').id, ago = m => new Date(now - m * 60000).toISOString();
  const job = (status, phase, queuedMinutesAgo) => { const id = crypto.randomUUID(); app.store.run('INSERT INTO actions(id,type,asset_id,requested_by,approved_by,reason,requested_at,expires_at,preflight_hash,before_value,after_value,status,result,executed_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', id, 'network.block-ip', assetId, adminId, adminId, 'outage fixture', ago(queuedMinutesAgo + 5), ago(queuedMinutesAgo - 5), 'x', '{}', '{}', status, null, null);
    app.store.run('INSERT INTO response_jobs(action_id,source_id,connector_id,request_json,phase,status,queued_at) VALUES (?,?,?,?,?,?,?)', id, connector.id, 'SYNTHETIC-FW-060', JSON.stringify({ action_type: 'network.block-ip', target: { ip: '198.51.100.20' } }), phase, 'queued', ago(queuedMinutesAgo)); return id; };
  const stale = job('dispatched', 'execute', 120), fresh = job('dispatched', 'execute', 10), rollback = job('rollback-pending', 'rollback', 180);
  // The connector comes back after two hours: the stale execute job is not handed out; the fresh one and the rollback are.
  const jobs = app.domain.responseJobs(connector.id).items.map(x => x.action_id).sort(); assert.deepEqual(jobs, [fresh, rollback].sort());
  assert.equal(app.store.get('SELECT status FROM actions WHERE id=?', stale).status, 'expired');
  assert.match(app.store.get('SELECT result FROM actions WHERE id=?', stale).result, /approve again against the current state/);
  assert.equal(app.store.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-RESPONSE-STALE-060'").n, 1);
  assert.equal(app.store.all("SELECT * FROM audit WHERE action='action.expired_before_execution'").length, 1);
  assert.throws(() => app.domain.completeResponseJob(connector.id, stale, { phase: 'execute', outcome: 'succeeded', observed_state: 'late', evidence_ref: 'late', rollback_supported: true }), /response_job_not_queued/, 'a late result for an expired job is refused');
  // Rollback counts only with the restored state reported as evidence.
  const done = app.domain.completeResponseJob(connector.id, rollback, { phase: 'rollback', outcome: 'succeeded', observed_state: 'Block rule removed; 198.51.100.20 reachable again', evidence_ref: 'SYNTHETIC-FW-ROLLBACK-060', rollback_supported: true }); assert.equal(done.status, 'rolled-back');
  // Reconciliation report over HTTP for an analyst; metrics count the expiry separately from failures.
  const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ username: 'admin', password }) }), cookie = login.headers.get('set-cookie').split(';')[0];
  const rec = await (await fetch(`${base}/api/reconciliation`, { headers: { Cookie: cookie } })).json();
  assert.deepEqual(rec.summary, { awaiting_connector: 1, rollbacks_pending: 0, expired_before_execution: 1, rollback_failed: 0, rollbacks_verified: 1, sources_with_backlog: 0 });
  assert.equal(rec.rollbacks_verified[0].evidence_ref, 'SYNTHETIC-FW-ROLLBACK-060'); assert.match(rec.rollbacks_verified[0].verified_state, /reachable again/); assert.equal(rec.job_max_age_minutes, 60);
  assert.ok(rec.claim_ar.includes('الانقطاع'));
  const m = app.domain.qualityMetrics(); const c = m.response_failures.by_connector[0]; assert.equal(c.failed, 0); assert.equal(c.expired, 1);
});
