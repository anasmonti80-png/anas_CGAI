import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { parseVaults, parseRestoreJobs, assessVaults, vaultLockView } from '../lib/backup-vault-lock.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), B = n => path.join(ROOT, 'tests/fixtures/aws/backup', n), read = n => JSON.parse(fs.readFileSync(B(n), 'utf8'));
const NOW = Date.parse('2026-11-26T00:00:00Z');

test('vault lock mode, reversibility and cost risk are derived from the vault export and a vault is relied on only after a successful restore (CG-157)', () => {
  const vaults = assessVaults({ vaults: parseVaults(read('vaults.json')), restores: parseRestoreJobs(read('restore-jobs.json')) }, NOW), v = n => vaults.find(x => x.name === n), ids = n => v(n).findings.map(f => `${f.id}:${f.severity}`);
  assert.deepEqual([v('prod-immutable').mode, v('prod-immutable').restore, v('prod-immutable').reliable], ['compliance-immutable', 'restore-proven', true]);
  assert.deepEqual(ids('prod-immutable'), [], 'bounded retention and a proven restore within 90 days');
  assert.equal(v('finance-compliance-new').mode, 'compliance-grace');
  assert.deepEqual(ids('finance-compliance-new'), ['compliance-grace:high', 'cost-risk:medium', 'restore-untested:medium'], 'the lock becomes irreversible on 2026-12-01 without a proven restore, and no maximum retention is set');
  assert.deepEqual([v('logs-governance').mode, v('logs-governance').restore], ['governance', 'restore-failed']); assert.ok(ids('logs-governance').includes('restore-failed:high'));
  assert.deepEqual(ids('default'), ['not-immutable:medium', 'restore-untested:medium']);
  assert.equal(assessVaults({ vaults: parseVaults(read('vaults.json')), restores: [] }, Date.parse('2026-12-02T00:00:00Z')).find(x => x.name === 'finance-compliance-new').mode, 'compliance-immutable', 'after the lock date nothing can undo it');
  assert.equal(assessVaults({ vaults: parseVaults(read('vaults.json')), restores: parseRestoreJobs(read('restore-jobs.json')) }, Date.parse('2027-03-01T00:00:00Z')).find(x => x.name === 'prod-immutable').restore, 'restore-untested', 'a restore proof older than 90 days expires');
  assert.throws(() => parseVaults({ Vaults: [] }), /not_list_backup_vaults_export/);
});

test('vault lock findings raise alerts for irreversible locks without restore proof, failed restores and unlocked vaults (CG-157)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg157-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'Backup', stale_seconds: 86400 });
  const out = path.join(dir, 'v.json'), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/backup-vault-lock.js'), '--account-id', '111122223333', '--region', 'us-east-1', '--authorization-ref', 'SEC-157', '--vaults', B('vaults.json'), '--restore-jobs', B('restore-jobs.json'), '--output', out], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const ev = JSON.parse(fs.readFileSync(out, 'utf8')); ev.events[0].observed_at = new Date(NOW).toISOString(); d.ingest('a', src.id, ev);
  const rows = s.all("SELECT severity,title FROM alerts WHERE rule_id='CG-BACKUP-VAULT-157'").map(x => `${x.severity}:${x.title.split(':')[0]}`).sort();
  assert.equal(rows.filter(x => x.startsWith('high')).length, 2, 'compliance lock without restore proof and the failed restore');
  assert.equal(rows.length, 6, 'governance mode alone is a low note without an alert');
  assert.equal(vaultLockView(s, NOW).scopes[0].vaults.length, 4);
});
