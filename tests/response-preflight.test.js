import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { ResponsePreflight } from '../lib/response-preflight.js';
import { digest } from '../lib/common.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), FX = n => path.join(ROOT, 'tests/fixtures/cisco', `acc-sw-01-${n}.txt`);
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg117-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.now(); const d = new Domain(s, { clock: () => now }), iso = (o = 0) => new Date(now + o).toISOString();
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', iso());
  const src = d.createSource('admin-a', { name: 'Sensors', stale_seconds: 86400 }), resp = d.createSource('admin-a', { name: 'EDR connector', stale_seconds: 86400, source_type: 'response-connector' });
  const out = path.join(dir, 'pm.json'), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/port-map.js'), '--switch-ref', 'acc-sw-01', '--authorization-ref', 'NET-117', '--output', out, '--arp', FX('arp'), '--mac-table', FX('mac'), '--switchport', FX('switchport'), '--lldp', FX('lldp')], { encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr);
  d.ingest('admin-a', src.id, JSON.parse(fs.readFileSync(out, 'utf8')));
  const alice = { external_id: 'ws-alice', hostname: 'WS-ALICE', os_family: 'windows', device_type: 'workstation', addresses: ['10.20.10.21'] }, dc = { external_id: 'dc-01', hostname: 'DC-01', os_family: 'windows', device_type: 'domain-controller', addresses: ['10.20.10.40'] }, twin = { external_id: 'ws-alice-old', hostname: 'WS-ALICE', os_family: 'windows', device_type: 'workstation', addresses: ['10.20.99.21'] };
  const ev = (id, kind, details, asset) => ({ event_id: id, kind, observed_at: iso(), asset, details }), put = (source, ...events) => d.ingest('admin-a', source.id, { schema_version: 'cg.telemetry/1', events });
  put(src, ev('a', 'asset.observed', {}, alice), ev('dc', 'asset.observed', {}, dc), ev('t', 'asset.observed', {}, twin));
  put(src, ev('ctx', 'asset.context', { owner: { owner_id: 'fin-it', display_name: 'Finance IT', contact: null }, business_service: 'Payroll', service_name: null, site: 'HQ', data_sensitivity: 'confidential', maintenance_windows: ['Fri 22:00-02:00'], service_criticality: 'high' }, alice));
  const flow = (s2, port) => JSON.stringify({ TimeFlowStart: Math.floor(now / 1000) - 600, SrcAddr: s2, DstAddr: '10.20.10.40', SrcPort: 50000, DstPort: port, Proto: 6, Bytes: 100, Packets: 1 });
  put(src, ev('flows', 'log.batch', { batch_id: 'F', source_name: 'flows', format: 'goflow-json', lines: [flow('10.20.10.21', 389), flow('10.20.10.15', 53)] }, dc));
  put(resp, ev('cap', 'response.capability', { connector_id: 'EDR-117', owner_system: 'cyberguard-connector', capabilities: ['endpoint.isolate-device'], target_asset_refs: ['ws-alice', 'dc-01'], tested_at: iso(-3600000), evidence_ref: 'EDR-TEST-117', status: 'active' }, alice));
  const mgmt = (id, asset, extra = {}) => ev(id, 'response.management_preflight', { connector_id: 'EDR-117', action_type: 'endpoint.isolate-device', target_hash: digest({ device_ref: asset.external_id }), protected_role: 'none', management_channel_impact: 'none', alternate_management: { status: 'not-applicable', evidence_ref: null }, captured_at: iso(-60000), evidence_ref: `MGMT-${id}`, ...extra }, asset);
  put(resp, mgmt('m-alice', alice), mgmt('m-dc', dc, { protected_role: 'domain-controller' }));
  return { s, d, pf: new ResponsePreflight(s, { domain: d, clock: () => now }), advance: ms => { now += ms; } };
}
const byId = r => Object.fromEntries(r.checks.map(c => [c.id, c.state]));

test('the target is identified from IP, MAC, hostname or asset id and refused when identifiers are ambiguous or disagree (CG-117)', t => {
  const { pf } = fixture(t);
  const ok = pf.run({ identifiers: { ip: '10.20.10.21', mac: 'a4bb.6d11.2021' } }); assert.equal(ok.asset.external_id, 'ws-alice'); assert.equal(byId(ok).target, 'pass'); assert.equal(ok.resolution_notes[0].location.interface, 'Gi1/0/5');
  const amb = pf.run({ identifiers: { hostname: 'ws-alice' } }); assert.equal(amb.decision, 'blocked'); assert.match(amb.checks[0].detail, /match 2 assets/);
  assert.equal(pf.run({ identifiers: { hostname: 'WS-ALICE', ip: '10.20.10.21' } }).asset.external_id, 'ws-alice', 'a second identifier settles it');
  const clash = pf.run({ identifiers: { ip: '10.20.10.21', mac: '0011.2233.4440' } }); assert.equal(clash.decision, 'blocked'); assert.equal(clash.checks[0].detail, 'The identifiers point to different assets');
  assert.equal(pf.run({ identifiers: { ip: '10.9.9.9' } }).checks[0].detail, 'No asset matches the identifiers');
  assert.throws(() => pf.run({ identifiers: {} }), /target_identifier_required/); assert.throws(() => pf.run({ identifiers: { ip: 'x' } }), /invalid_target_ip/); assert.throws(() => pf.run({ identifiers: { serial: '1' } }), /unknown_target_identifier_serial/);
});

test('impact, connector, licensed capability, management channel and dependencies are checked before isolation (CG-117)', t => {
  const { pf, d, s, advance } = fixture(t);
  const r = pf.run({ identifiers: { ip: '10.20.10.21' }, action_type: 'endpoint.isolate-device' }), c = byId(r);
  assert.equal(c.connector, 'pass'); assert.equal(c['management-channel'], 'pass'); assert.equal(c['impact-isolation-path'], 'pass'); assert.equal(c['impact-criticality'], 'pass'); assert.equal(c['capability-license'], 'warn', 'no probe: licence not verified');
  assert.equal(r.checks.find(x => x.id === 'impact-criticality').data.business_service, 'Payroll'); assert.equal(r.decision, 'ready-with-warnings');
  const dcr = pf.run({ identifiers: { hostname: 'DC-01' }, action_type: 'endpoint.isolate-device' }), dc = byId(dcr);
  assert.equal(dc['impact-protected-role'], 'block'); assert.equal(dc['impact-dependents'], 'warn'); assert.equal(dcr.checks.find(x => x.id === 'impact-dependents').data.hosts, 2); assert.equal(dcr.decision, 'blocked');
  const shut = pf.run({ identifiers: { ip: '10.20.10.21' }, action_type: 'endpoint.shutdown-host' }); assert.equal(byId(shut).connector, 'block'); assert.equal(byId(shut)['management-channel'], 'block');
  advance(20 * 60000); const stale = pf.run({ identifiers: { ip: '10.20.10.21' }, action_type: 'endpoint.isolate-device' }); assert.equal(byId(stale)['management-channel'], 'block'); assert.match(stale.checks.find(x => x.id === 'management-channel').detail, /stale/);
  // A device probe without the licensed feature blocks the capability.
  const resp = s.get("SELECT id FROM sources WHERE name='Sensors'").id;
  d.ingest('admin-a', resp, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'probe', kind: 'device.capability_probe', observed_at: new Date(Date.now() + 20 * 60000).toISOString(), asset: { external_id: 'ws-alice', hostname: 'WS-ALICE', os_family: 'windows', device_type: 'workstation', addresses: ['10.20.10.21'] }, details: { probe_id: 'p1', device_ref: 'ws-alice', vendor: 'synthetic-edr', model: 'agent', version: '7.2', license: { edition: 'basic', features: [] }, probed_at: new Date(Date.now() + 20 * 60000).toISOString(), probe_method: 'local-script', capabilities: [{ capability: 'isolation', status: 'supported', method: 'agent', evidence: 'probe', min_version: null, license_feature: 'network-containment' }] } }] });
  const lic = pf.run({ identifiers: { ip: '10.20.10.21' }, action_type: 'endpoint.isolate-device' }); assert.equal(byId(lic)['capability-license'], 'block'); assert.match(lic.checks.find(x => x.id === 'capability-license').detail, /license-missing/);
  assert.equal(s.get('SELECT COUNT(*) n FROM actions').n, 0, 'the preflight never creates an action'); assert.ok(lic.claim_ar.includes('لا يُنفذ شيء'));
});
