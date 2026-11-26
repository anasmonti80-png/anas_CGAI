import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { PermissionReduction, fromAccessAnalyzer, decide } from '../lib/permission-reduction.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), AA = n => path.join(ROOT, 'tests/fixtures/aws/access-analyzer', n), read = n => JSON.parse(fs.readFileSync(AA(n), 'utf8'));
const NOW = Date.parse('2026-11-27T00:00:00Z');

test('a permission is recommended for removal only after a long enough window with an owner, never for a short window, break-glass or seasonal use (CG-152)', () => {
  const e = fromAccessAnalyzer(read('get-finding-v2-unused.json'), { windowDays: 120, owners: read('owners.json'), breakGlass: ['arn:aws:iam::111122223333:role/break-glass-admin'], seasonal: ['glacier'] });
  assert.equal(e.length, 5, 'archived findings are ignored');
  const by = p => decide(e.find(x => x.permission === p || x.principal.endsWith(p)), NOW).decision;
  assert.equal(by('s3:DeleteBucket,s3:PutBucketPolicy'), 'recommend');
  assert.equal(by('glacier:InitiateJob'), 'insufficient-window', 'a seasonal permission needs 400 days of data');
  assert.equal(by('role/legacy-deploy'), 'recommend');
  assert.equal(by('example-key-152'), 'needs-owner', 'no owner, no recommendation');
  assert.equal(by('role/break-glass-admin'), 'excluded');
  const short = fromAccessAnalyzer(read('get-finding-v2-unused.json'), { windowDays: 30, owners: read('owners.json') });
  assert.ok(short.every(x => decide(x, NOW).decision === 'insufficient-window'), 'thirty days of no use is never enough to recommend removal');
  assert.equal(decide({ window_days: 120, last_used: '2026-10-01T00:00:00Z', owner: 'x' }, NOW).decision, 'in-use');
});

test('recommendations need a change request and owner approval, the dry run changes nothing, and removal is verified by a later import (CG-152)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg152-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); let now = NOW; const d = new Domain(s, { clock: () => now }), pr = new PermissionReduction(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString()); const src = d.createSource('a', { name: 'IAM', stale_seconds: 86400 });
  const run = (file, extra = []) => { const out = path.join(dir, `o-${Math.random()}.json`), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/permission-usage.js'), '--source-ref', 'aws-111122223333', '--authorization-ref', 'SEC-152', '--window-days', '120', '--aws-findings', file, '--owners', AA('owners.json'), '--break-glass', 'arn:aws:iam::111122223333:role/break-glass-admin', '--seasonal', 'glacier', ...extra, '--output', out], { encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); d.ingest('a', src.id, JSON.parse(fs.readFileSync(out, 'utf8'))); };
  run(AA('get-finding-v2-unused.json'));
  const v = pr.view(); assert.deepEqual(v.summary, { recommend: 2, 'in-use': 0, 'insufficient-window': 1, 'needs-owner': 1, excluded: 1 });
  const role = v.items.find(x => x.kind === 'role' && x.decision === 'recommend');
  const dry = pr.dryRun(); assert.equal(dry.changes_made, 0); assert.equal(dry.changes.length, 2); assert.match(dry.changes.find(c => c.action === 'remove-unused-role').rollback, /Re-attach/);
  assert.throws(() => pr.transition('a', role.key, 'owner-approved', { approver: 'team-platform' }), /invalid_permission_workflow_transition/, 'approval needs a change request first');
  pr.transition('a', role.key, 'change-requested', { change_ref: 'CHG-152' });
  assert.throws(() => pr.transition('a', role.key, 'owner-approved', { approver: 'someone-else' }), /permission_approver_must_be_owner/);
  pr.transition('a', role.key, 'owner-approved', { approver: 'team-platform', note: 'remove in next window' });
  assert.equal(pr.view().items.find(x => x.key === role.key).workflow.state, 'owner-approved'); assert.equal(pr.view().verified_removed.length, 0, 'approval is not removal');
  const notRec = pr.view().items.find(x => x.decision === 'needs-owner'); assert.throws(() => pr.transition('a', notRec.key, 'change-requested', { change_ref: 'X' }), /permission_not_recommended/);
  const later = read('get-finding-v2-unused.json').filter(f => !f.resource.endsWith('role/legacy-deploy')), f2 = path.join(dir, 'later.json'); fs.writeFileSync(f2, JSON.stringify(later));
  now += 3600000; run(f2);
  assert.deepEqual(pr.view().verified_removed.map(x => [x.permission, x.change_ref, x.approver]), [['arn:aws:iam::111122223333:role/legacy-deploy', 'CHG-152', 'team-platform']]);
  assert.equal(s.all("SELECT 1 FROM audit WHERE action LIKE 'permission_reduction.%'").length, 2);
});
