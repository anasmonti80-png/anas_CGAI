import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { DataGovernance, bindTenant } from '../lib/data-governance.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg126-')), dbFile = path.join(dir, 'cyberguard.sqlite'), s = new Store(dbFile);
  t.after(() => { s.close(); fs.rmSync(dir, { recursive: true, force: true }); }); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  bindTenant(s, 'bank-a'); const g = new DataGovernance(s, { tenant: 'bank-a', dataDir: dir, dbFile });
  const src = d.createSource('admin-a', { name: 'Logs', stale_seconds: 86400 }), asset = { external_id: 'srv', hostname: 'SRV', os_family: 'windows', device_type: 'server', addresses: ['10.0.0.5'] };
  const put = (id, account) => d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: id, kind: 'auth.failed', observed_at: new Date().toISOString(), asset, details: { account, source_ip: '203.0.113.7', protocol: 'rdp' } }] });
  return { s, d, g, dir, dbFile, put };
}

test('a database is bound to its tenant and refuses to be opened for another one (CG-126)', t => {
  const { s, dbFile } = fixture(t);
  assert.throws(() => bindTenant(s, 'bank-b'), /tenant_data_mismatch: this database belongs to tenant bank-a/);
  assert.throws(() => s.run("UPDATE instance_identity SET tenant='bank-b'"), /tenant_binding_immutable/);
  assert.equal(bindTenant(s, 'bank-a'), 'bank-a'); assert.ok(fs.existsSync(dbFile));
});

test('the residency map shows where each data class lives and its declared region; export is complete and hashed (CG-126)', t => {
  const { g, put, s } = fixture(t); put('e1', 'ahmed.ali');
  let v = g.view(); assert.equal(v.tenant, 'bank-a'); assert.ok(v.locations.find(l => l.data_class === 'database').inside_tenant_directory); assert.ok(v.locations.find(l => l.data_class === 'database').bytes > 0);
  assert.equal(v.undeclared_regions.length, 6); g.declareRegion('admin-a', { data_class: 'database', region: 'saudi-arabia' }); assert.throws(() => g.declareRegion('admin-a', { data_class: 'database', region: 'mars' }), /invalid_region/);
  v = g.view(); assert.equal(v.locations.find(l => l.data_class === 'database').region, 'saudi-arabia');
  const x = g.exportAll('admin-a'), lines = x.body.trim().split('\n'), manifest = JSON.parse(lines.at(-1)).manifest;
  assert.equal(manifest.tenant, 'bank-a'); assert.equal(manifest.counts.events, 1); assert.equal(manifest.audit_chain.valid, true);
  assert.equal(createHash('sha256').update(lines.slice(0, -1).map(l => l + '\n').join('')).digest('hex'), manifest.sha256, 'the manifest hash covers every exported line');
  assert.ok(!x.body.includes('token_hash":"'), 'collector token hashes are not exported'); assert.ok(s.all("SELECT 1 FROM audit WHERE action='tenant.exported'").length === 1);
});

test('erasing a person needs a second administrator who re-enters the identifier; records in open cases stay under legal hold (CG-126)', t => {
  const { s, d, g, put } = fixture(t);
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-b', 'admin-b', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  for (let i = 0; i < 5; i++) put(`f${i}`, 'ahmed.ali'); put('other', 'bob');
  const alert = s.get("SELECT id,evidence_ids FROM alerts WHERE rule_id='CG-AUTH-FAILURES-5-IN-5M'"); d.createCase('admin-a', { title: 'Open investigation', alert_ids: [alert.id] });
  const r = g.requestErasure('admin-a', { identifier: 'Ahmed.Ali', reason: 'Data subject deletion request DSR-77' });
  assert.equal(r.matched + r.held, 5); assert.ok(r.held >= 1, 'evidence of the open case is held'); assert.ok(!JSON.stringify(s.all('SELECT * FROM erasure_requests')).toLowerCase().includes('ahmed.ali'), 'only the identifier hash is stored');
  assert.throws(() => g.approveErasure('admin-a', r.id, { identifier: 'ahmed.ali' }), /independent_approver_required/);
  assert.throws(() => g.approveErasure('admin-b', r.id, { identifier: 'someone.else' }), /erasure_identifier_does_not_match_request/);
  const done = g.approveErasure('admin-b', r.id, { identifier: 'ahmed.ali' }); assert.equal(done.status, 'completed'); assert.equal(done.erased, r.matched);
  assert.equal(s.get("SELECT COUNT(*) n FROM events WHERE payload LIKE '%ahmed.ali%'").n, r.held); assert.equal(s.get("SELECT COUNT(*) n FROM events WHERE payload LIKE '%bob%'").n, 1, 'other people are untouched');
  assert.ok(!JSON.stringify(s.all("SELECT details FROM audit WHERE action LIKE 'erasure.%'")).toLowerCase().includes('ahmed.ali')); assert.throws(() => g.approveErasure('admin-b', r.id, { identifier: 'ahmed.ali' }), /erasure_not_pending/);
});

test('the tenants script verifies isolation across customers (CG-126)', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cg126-tenants-')); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const run = (...a) => spawnSync(process.execPath, [path.join(ROOT, 'scripts/tenants.js'), ...a, '--root', root], { encoding: 'utf8' });
  assert.equal(run('add', 'bank-a', '--port', '19101').status, 0); assert.equal(run('add', 'bank-b', '--port', '19102').status, 0);
  for (const id of ['bank-a', 'bank-b']) { const s = new Store(path.join(root, id, 'cyberguard.sqlite')); bindTenant(s, id); s.close(); }
  let v = run('verify'); assert.equal(v.status, 0, v.stdout + v.stderr); assert.equal(JSON.parse(v.stdout).isolated, true);
  fs.copyFileSync(path.join(root, 'bank-a', 'cyberguard.sqlite'), path.join(root, 'bank-b', 'cyberguard.sqlite'));
  for (const f of ['-wal', '-shm']) fs.rmSync(path.join(root, 'bank-b', `cyberguard.sqlite${f}`), { force: true });
  v = run('verify'); assert.equal(v.status, 1); assert.deepEqual(JSON.parse(v.stdout).problems, ['bank-b: database is bound to tenant bank-a']);
});
