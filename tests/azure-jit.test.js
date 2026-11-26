import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { planStatus, parseJitPolicies, assessJit, jitView, PERMISSIONS } from '../lib/azure-jit.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), J = n => path.join(ROOT, 'tests/fixtures/azure/jit', n), read = n => JSON.parse(fs.readFileSync(J(n), 'utf8'));
const S1 = '11111111-1111-4111-8111-111111111111', S2 = '22222222-2222-4222-8222-222222222222';

test('JIT coverage depends on Defender for Servers Plan 2 and policies are judged by port, source and duration (CG-156)', () => {
  assert.deepEqual([planStatus(read('pricing-p2.json')), planStatus(read('pricing-free.json')), planStatus({ value: [{ name: 'VirtualMachines', properties: { pricingTier: 'Standard' } }] })], [{ plan: 'plan-2', jit: true }, { plan: 'free', jit: false }, { plan: 'standard-unknown-subplan', jit: null }]);
  const vms = read('vms.json').map(x => ({ resource_id: x.id, name: x.name, account_id: '' }));
  const a = assessJit({ plans: [{ subscription: S1, status: planStatus(read('pricing-p2.json')) }, { subscription: S2, status: planStatus(read('pricing-free.json')) }], policies: parseJitPolicies(read('jit-policies.json')), vms }), v = n => a.vms.find(x => x.name === n);
  assert.deepEqual(v('jump-1').findings, [], 'restricted source, 1 to 3 hours, all management ports');
  assert.deepEqual(v('app-1').findings.map(f => f.id), ['any-source-3389', 'long-window-3389']); assert.deepEqual(v('app-1').ports_not_in_policy, [22, 5985, 5986]);
  assert.deepEqual([v('app-2').findings[0].id, v('app-2').findings[0].severity], ['no-jit-policy', 'medium'], 'Plan 2 is available but the VM has no policy');
  assert.deepEqual([v('dev-1').findings[0].severity, v('dev-1').jit_available], ['low', false], 'without Plan 2 JIT is not available, stated rather than alerted');
  assert.equal(PERMISSIONS.find(p => /Request/.test(p.task)).actions[0], 'Microsoft.Security/locations/jitNetworkAccessPolicies/initiate/action');
  assert.throws(() => parseJitPolicies({ items: [] }), /not_jit_policy_export/);
});

test('JIT requests are audited by requester, source, time and justification, and risky requests raise alerts (CG-156)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg156-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'Azure', stale_seconds: 86400 });
  const out = path.join(dir, 'j.json'), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/azure-jit.js'), '--authorization-ref', 'SEC-156', '--pricings', `${S1}=${J('pricing-p2.json')}`, '--pricings', `${S2}=${J('pricing-free.json')}`, '--jit-policies', J('jit-policies.json'), '--vms', J('vms.json'), '--output', out], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr); d.ingest('a', src.id, JSON.parse(fs.readFileSync(out, 'utf8')));
  const v = jitView(s); assert.deepEqual(v.requests.map(x => [x.requestor, x.findings]), [['dev@lab.example', ['no-justification', 'any-source']], ['ops-admin@lab.example', []]]);
  assert.deepEqual(s.all("SELECT rule_id,severity FROM alerts WHERE rule_id LIKE 'CG-AZURE-JIT%' ORDER BY rule_id,severity").map(x => `${x.rule_id}:${x.severity}`), ['CG-AZURE-JIT-156:medium', 'CG-AZURE-JIT-156:medium', 'CG-AZURE-JIT-REQUEST-156:high']);
});
