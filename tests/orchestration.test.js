import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { digest } from '../lib/common.js';
import { Orchestrator, PLAYBOOKS } from '../lib/orchestration.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), FX = n => path.join(ROOT, 'tests/fixtures/cisco', `acc-sw-01-${n}.txt`);
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg120-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.now(); const d = new Domain(s, { clock: () => now }), iso = (o = 0) => new Date(now + o).toISOString();
  for (const id of ['admin-a', 'admin-b']) { s.run('INSERT INTO users VALUES (?,?,?,?,?)', id, id, 'fixture-not-a-password-hash', 'admin', iso()); s.run('INSERT INTO mfa_assertions VALUES (?,?,?,?,?,?,?)', `${id}-mfa`, id, `fixture-session-${id}`, 'totp', iso(), iso(3600000), digest({ id })); }
  const sensors = d.createSource('admin-a', { name: 'Sensors', stale_seconds: 86400 }), conn = name => d.createSource('admin-a', { name, stale_seconds: 86400, source_type: 'response-connector' });
  const put = (src, ...e) => d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: e }), ev = (id, kind, details, asset) => ({ event_id: id, kind, observed_at: iso(), asset, details });
  const ws = { external_id: 'ws-win-01', hostname: 'WS-WIN-01', os_family: 'windows', device_type: 'workstation', addresses: ['10.0.0.20'] }, vm = { external_id: 'i-0abc1234def567890', hostname: 'web-prod-1', os_family: 'linux', device_type: 'virtual-machine', addresses: ['172.31.5.10'] };
  const alice = { external_id: 'ws-alice', hostname: 'WS-ALICE', os_family: 'windows', device_type: 'workstation', addresses: ['10.20.10.21'] }, sw = { external_id: 'acc-sw-01', hostname: 'ACC-SW-01', os_family: 'network', device_type: 'switch', addresses: ['10.20.10.2'] };
  const out = path.join(dir, 'pm.json'), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/port-map.js'), '--switch-ref', 'acc-sw-01', '--authorization-ref', 'NET-120', '--output', out, '--arp', FX('arp'), '--mac-table', FX('mac'), '--switchport', FX('switchport'), '--lldp', FX('lldp')], { encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr);
  d.ingest('admin-a', sensors.id, JSON.parse(fs.readFileSync(out, 'utf8')));
  put(sensors, ev('ws', 'asset.observed', {}, ws), ev('vm', 'asset.observed', {}, vm), ev('alice', 'asset.observed', {}, alice), ev('sw', 'asset.observed', {}, sw),
    ev('inv', 'cloud.resource_inventory', { inventory_id: 'INV-120', provider: 'aws', source: 'aws-resource-explorer', resources: [{ resource_id: 'i-0abc1234def567890', name: 'web-prod-1', account_id: '123456789012', region: 'me-south-1', type: 'ec2:instance', category: 'compute', tags: {}, public: true }] }, vm));
  const edr = conn('EDR connector'), cloud = conn('AWS connector'), ncc = conn('Network controller');
  const mgmt = (id, connector, type, target, asset) => ev(id, 'response.management_preflight', { connector_id: connector, action_type: type, target_hash: digest(target), protected_role: 'none', management_channel_impact: 'none', alternate_management: { status: 'not-applicable', evidence_ref: null }, captured_at: iso(-60000), evidence_ref: `M-${id}` }, asset);
  put(edr, ev('cap-edr', 'response.capability', { connector_id: 'EDR-120', owner_system: 'cyberguard-connector', capabilities: ['endpoint.isolate-device', 'network.block-ip'], target_asset_refs: ['ws-win-01'], tested_at: iso(-3600000), evidence_ref: 'EDR-120', status: 'active' }, ws),
    mgmt('m1', 'EDR-120', 'endpoint.isolate-device', { device_ref: 'ws-win-01' }, ws), mgmt('m2', 'EDR-120', 'network.block-ip', { ip: '198.51.100.66' }, ws));
  put(cloud, ev('cap-aws', 'response.capability', { connector_id: 'AWS-120', owner_system: 'cloud-connector', capabilities: ['cloud.isolate-instance', 'cloud.release-instance', 'cloud.disable-access-key'], target_asset_refs: ['i-0abc1234def567890'], tested_at: iso(-3600000), evidence_ref: 'AWS-120', status: 'active' }, vm));
  put(ncc, ev('cap-ncc', 'response.capability', { connector_id: 'NCC-120', owner_system: 'ncc-scoped-api', capabilities: ['network.switch-port-admin-down'], target_asset_refs: ['acc-sw-01'], tested_at: iso(-3600000), evidence_ref: 'NCC-120', status: 'active' }, sw),
    mgmt('m3', 'NCC-120', 'network.switch-port-admin-down', { device_ref: 'acc-sw-01', interface_ref: 'Gi1/0/5', port_role: 'edge', provenance_ref: 'port-map:acc-sw-01:Gi1/0/5' }, sw));
  const id = ext => s.get("SELECT a.id FROM assets a JOIN sources s ON s.id=a.source_id WHERE a.external_id=? AND s.name='Sensors'", ext).id;
  const sources = { edr, cloud, ncc };
  const finish = (action, src, outcome, phase = 'execute') => d.completeResponseJob(sources[src].id, action, { phase, outcome, observed_state: `${phase} ${outcome}`, evidence_ref: `EV-${action.slice(0, 6)}-${phase}-${outcome}`, rollback_supported: true });
  const approveRun = action => { d.approveAction('admin-b', action); d.executeAction('admin-a', action); };
  return { s, d, o: new Orchestrator(s, { domain: d, clock: () => now }), id, finish, approveRun, advance: ms => { now += ms; } };
}
const req = (o, extra) => ({ authorization_ref: 'IR-120', reason: 'Synthetic cross-provider containment', ...extra });

test('each step picks the provider by target and connector capability, not by command text (CG-120)', t => {
  const { o, id } = fixture(t);
  assert.equal(o.plan('contain-compromised-host', id('ws-win-01')).steps[0].provider, 'endpoint-agent');
  const cloudPlan = o.plan('contain-compromised-host', id('i-0abc1234def567890')); assert.equal(cloudPlan.steps[0].provider, 'cloud'); assert.deepEqual(cloudPlan.steps[0].target, { provider: 'aws', resource_id: 'i-0abc1234def567890' });
  const sw = o.plan('contain-compromised-host', id('ws-alice')).steps[0]; assert.equal(sw.provider, 'access-switch'); assert.deepEqual(sw.target, { device_ref: 'acc-sw-01', interface_ref: 'Gi1/0/5', port_role: 'edge', provenance_ref: 'port-map:acc-sw-01:Gi1/0/5' });
  assert.match(sw.considered.find(c => c.provider === 'endpoint-agent').reason, /no active connector can run endpoint.isolate-device on ws-alice/);
  assert.match(sw.considered.find(c => c.provider === 'cisco-ise').reason, /no active connector/);
  assert.equal(o.plan('contain-compromised-host', id('ws-win-01')).steps[1].status, 'skipped', 'no address given: the optional block step is skipped');
  assert.ok(PLAYBOOKS.every(p => p.steps.every(s => !('command' in s))), 'playbooks hold intents, never command text');
});

test('runs are idempotent, failed steps retry a bounded number of times and a failed required step rolls back completed steps in reverse order (CG-120)', t => {
  const { s, d, o, id, finish, approveRun, advance } = fixture(t), ws = id('ws-win-01');
  const run = o.start('admin-a', req(o, { playbook_id: 'contain-host-and-c2', asset_id: ws, params: { ip: '198.51.100.66' } }));
  assert.equal(run.steps[0].status, 'awaiting-approval'); assert.equal(run.steps[0].action_type, 'endpoint.isolate-device');
  const again = o.start('admin-a', req(o, { playbook_id: 'contain-host-and-c2', asset_id: ws, params: { ip: '198.51.100.66' } })); assert.equal(again.id, run.id); assert.equal(again.idempotent_replay, true); assert.equal(s.get('SELECT COUNT(*) n FROM actions').n, 1, 'no duplicate action');
  o.advance('admin-a', run.id); assert.equal(s.get('SELECT COUNT(*) n FROM actions').n, 1, 'advancing while waiting creates nothing');
  const a1 = run.steps[0].action_ids[0]; approveRun(a1); finish(a1, 'edr', 'succeeded');
  let r = o.advance('admin-a', run.id); assert.equal(r.steps[0].status, 'done'); assert.equal(r.steps[1].action_type, 'network.block-ip');
  for (let attempt = 1; attempt <= 3; attempt++) { const a = r.steps[1].action_ids.at(-1); approveRun(a); finish(a, 'edr', 'failed'); advance(1000); r = o.advance('admin-a', run.id); if (attempt < 3) { assert.equal(r.steps[1].status, 'retrying'); assert.equal(r.steps[1].attempts, attempt + 1); } }
  assert.equal(r.status, 'compensating'); assert.equal(r.steps[1].status, 'failed'); assert.equal(r.steps[0].status, 'rolling-back');
  assert.equal(s.get('SELECT status FROM actions WHERE id=?', a1).status, 'rollback-pending', 'the isolation is being undone');
  finish(a1, 'edr', 'succeeded', 'rollback'); r = o.advance('admin-a', run.id); assert.equal(r.status, 'rolled-back'); assert.equal(r.steps[0].status, 'rolled-back');
  const fresh = o.start('admin-a', req(o, { playbook_id: 'contain-host-and-c2', asset_id: ws, params: { ip: '198.51.100.66' } })); assert.notEqual(fresh.id, run.id, 'a finished run does not block a new one');
  assert.deepEqual(s.all("SELECT action FROM audit WHERE target=? AND action LIKE 'orchestration.%' ORDER BY seq", run.id).map(x => x.action), ['orchestration.started', 'orchestration.compensating', 'orchestration.rolled-back']);
});

test('a cloud credential playbook completes on AWS and an unavailable required step refuses to start (CG-120)', t => {
  const { o, id, finish, approveRun } = fixture(t), vm = id('i-0abc1234def567890');
  const run = o.start('admin-a', req(o, { playbook_id: 'cloud-credential-compromise', asset_id: vm, params: { principal_ref: 'arn:aws:iam::123456789012:user/ci-deployer', key_ref: 'AKIAEXAMPLEKEY00001' } }));
  assert.equal(run.steps[0].action_type, 'cloud.disable-access-key'); const a = run.steps[0].action_ids[0]; approveRun(a); finish(a, 'cloud', 'succeeded');
  let r = o.advance('admin-a', run.id); assert.equal(r.steps[1].action_type, 'cloud.isolate-instance'); const b = r.steps[1].action_ids[0]; approveRun(b); finish(b, 'cloud', 'succeeded');
  r = o.advance('admin-a', run.id); assert.equal(r.status, 'completed');
  assert.throws(() => o.start('admin-a', req(o, { playbook_id: 'cloud-credential-compromise', asset_id: id('ws-win-01'), params: {} })), /playbook_step_unavailable:disable-cloud-key/);
  assert.ok(o.view().claim_ar.includes('ثلاث محاولات'));
});
