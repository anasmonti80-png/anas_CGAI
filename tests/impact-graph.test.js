import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { ImpactGraph } from '../lib/impact-graph.js';
import { ResponsePreflight } from '../lib/response-preflight.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), FX = n => path.join(ROOT, 'tests/fixtures/cisco', `acc-sw-01-${n}.txt`);
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg133-')); process.once('exit', () => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const now = Date.now(), d = new Domain(s, { clock: () => now }), iso = () => new Date(now).toISOString();
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', iso());
  const src = d.createSource('admin-a', { name: 'Sensors', stale_seconds: 86400 });
  const out = path.join(dir, 'pm.json'), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/port-map.js'), '--switch-ref', 'acc-sw-01', '--authorization-ref', 'NET-133', '--output', out, '--arp', FX('arp'), '--mac-table', FX('mac'), '--switchport', FX('switchport'), '--lldp', FX('lldp')], { encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr);
  d.ingest('admin-a', src.id, JSON.parse(fs.readFileSync(out, 'utf8')));
  const A = (external_id, hostname, device_type, ip) => ({ external_id, hostname, os_family: device_type === 'switch' ? 'network' : 'windows', device_type, addresses: [ip] });
  const alice = A('ws-alice', 'WS-ALICE', 'workstation', '10.20.10.21'), dc = A('dc-01', 'DC-01', 'domain-controller', '10.20.10.40'), sw = A('acc-sw-01', 'ACC-SW-01', 'switch', '10.20.0.11'), jump = A('jump-01', 'JUMP-01', 'server', '10.20.5.5');
  const ev = (id, kind, details, asset) => ({ event_id: id, kind, observed_at: iso(), asset, details }), put = (...events) => d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events });
  put(ev('a', 'asset.observed', {}, alice), ev('dc', 'asset.observed', {}, dc), ev('sw', 'asset.observed', {}, sw), ev('j', 'asset.observed', {}, jump));
  put(ev('ctx', 'asset.context', { owner: { owner_id: 'fin-it', display_name: 'Finance IT', contact: null }, business_service: 'Payroll', service_name: null, site: 'HQ', data_sensitivity: 'confidential', maintenance_windows: [], service_criticality: 'high' }, alice));
  const flow = (from, port) => JSON.stringify({ TimeFlowStart: Math.floor(now / 1000) - 600, SrcAddr: from, DstAddr: '10.20.10.40', SrcPort: 50000, DstPort: port, Proto: 6, Bytes: 100, Packets: 1 });
  put(ev('flows', 'log.batch', { batch_id: 'F', source_name: 'flows', format: 'goflow-json', lines: [flow('10.20.10.21', 389), flow('10.20.10.15', 53)] }, dc));
  const ig = new ImpactGraph(s, { domain: d, clock: () => now }); d.impactGraph = ig;
  return { s, d, ig, alice, sw };
}

test('roles come from declarations, directory controllers, observed traffic, LLDP, voice VLANs and uplinks, each with its basis (CG-133)', t => {
  const { ig } = fixture(t), p = ig.providers(), has = (provider, role, basis) => p.find(x => x.provider === provider && x.role === role && x.basis === basis);
  assert.deepEqual(has('dc-01', 'ad', 'device-type').consumers, ['*']);
  assert.deepEqual(has('dc-01', 'ad', 'traffic').consumers, ['ws-alice']); assert.deepEqual(has('dc-01', 'dns', 'traffic').consumers, ['10.20.10.15'], 'an unknown client is kept by address');
  assert.equal(has('acc-sw-01:Gi1/0/12', 'hypervisor', 'lldp').neighbour, 'esx-host-07'); assert.equal(has('acc-sw-01:Gi1/0/12', 'hypervisor', 'lldp').consumers.length, 3);
  assert.equal(has('acc-sw-01:Gi1/0/48', 'shared-uplink', 'port-map').neighbour, 'CORE-SW-01'); assert.ok(has('acc-sw-01:Gi1/0/5', 'voip', 'voice-vlan'));
  assert.equal(ig.view().core_management_declared, false);
});

test('a port shutdown shows the phone, the PC and the business service behind it, and an uplink to an undeclared neighbour is refused (CG-133)', t => {
  const { ig } = fixture(t), down = port => ig.assess({ action_type: 'network.switch-port-admin-down', asset_ref: 'acc-sw-01', target: { interface_ref: port } });
  const edge = down('GigabitEthernet1/0/5'); assert.equal(edge.decision, 'ready-with-impact'); assert.equal(edge.core_management, 'none'); assert.deepEqual(edge.roles.map(r => r.role), ['voip']); assert.equal(edge.scope.devices.length, 2); assert.equal(edge.affected.devices, 2, 'the phone counted once although it is both on the port and a VoIP consumer');
  assert.deepEqual(edge.affected.services.map(x => [x.business_service, x.criticality]), [['Payroll', 'high']]);
  const up = down('Gi1/0/48'); assert.equal(up.decision, 'blocked'); assert.match(up.unknown[0].en, /uplink to CORE-SW-01 whose role is not declared/);
  assert.equal(down('Gi1/0/99').decision, 'blocked', 'a port missing from the port maps is unknown');
  ig.declare('admin-a', { asset_ref: 'CORE-SW-01', role: 'core' }); const known = down('Gi1/0/48'); assert.equal(known.decision, 'review-required'); assert.deepEqual(known.affected_core, [{ provider: 'CORE-SW-01', role: 'core', via: 'acc-sw-01:Gi1/0/48' }]);
  assert.equal(down('Gi1/0/12').roles[0].role, 'hypervisor');
});

test('network blocks are refused until the core and management path are declared, then show the roles and services they touch (CG-133)', t => {
  const { s, ig } = fixture(t), block = ip => ig.assess({ action_type: 'network.block-ip', asset_ref: 'acc-sw-01', target: { ip } });
  assert.equal(block('198.51.100.9').decision, 'blocked');
  assert.throws(() => ig.declare('admin-a', { asset_ref: 'x', role: 'everything' }), /impact_role/);
  ig.declare('admin-a', { asset_ref: 'jump-01', role: 'management', note: 'Administrators reach the switches from here' }); ig.declare('admin-a', { asset_ref: 'CORE-SW-01', role: 'core' });
  assert.equal(block('198.51.100.9').decision, 'ready'); const dcBlock = block('10.20.10.40'); assert.equal(dcBlock.decision, 'ready-with-impact'); assert.equal(dcBlock.affected.everyone, true); assert.ok(dcBlock.roles.some(r => r.role === 'ad' && r.basis === 'traffic'));
  const mg = block('10.20.5.5'); assert.equal(mg.decision, 'review-required'); assert.deepEqual(mg.affected_core.map(x => x.role), ['management']);
  assert.equal(ig.assess({ action_type: 'network.allow-ip', asset_ref: 'acc-sw-01', target: { ip: '10.20.5.5' } }).decision, 'not-disruptive');
  assert.equal(ig.assess({ action_type: 'endpoint.isolate-device', asset_ref: 'acc-sw-01', target: {} }).decision, 'blocked', 'a network device without a declared role is unknown');
  assert.equal(ig.assess({ action_type: 'endpoint.isolate-device', asset_ref: 'ws-alice', target: {} }).core_management, 'none');
  const id = ig.view().providers.find(p => p.role === 'management').id; ig.remove('admin-a', id); assert.equal(s.all("SELECT 1 FROM audit WHERE action LIKE 'impact_graph.role_%'").length, 3);
});

test('the governed preview refuses a change with unknown core or management impact and the preflight report shows the impact (CG-133)', t => {
  const { d, sw, ig } = fixture(t), asset = d.list('assets').items.find(a => a.external_id === sw.external_id);
  assert.throws(() => d.previewResponseAction('admin-a', { type: 'network.block-ip', asset_id: asset.id, target: { ip: '198.51.100.9' }, connector_id: 'FW', authorization_ref: 'IR-133', reason: 'Block attacker' }), /change_impact_unknown_on_core_or_management/);
  ig.declare('admin-a', { asset_ref: 'jump-01', role: 'management' });
  assert.throws(() => d.previewResponseAction('admin-a', { type: 'network.block-ip', asset_id: asset.id, target: { ip: '198.51.100.9' }, connector_id: 'FW', authorization_ref: 'IR-133', reason: 'Block attacker' }), /response_connector_capability_unavailable/, 'with the path declared the preview moves on to its other checks');
  const pf = new ResponsePreflight(d.s, { domain: d }), rep = pf.run({ identifiers: { asset_id: asset.id }, action_type: 'network.switch-port-admin-down', target: { interface_ref: 'Gi1/0/48' } });
  const c = rep.checks.find(x => x.id === 'impact-graph'); assert.equal(c.state, 'block'); assert.match(c.detail_ar, /غير معروف/);
});
