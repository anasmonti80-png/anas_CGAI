import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseArp, parseMacTable, parseSwitchport, parseLldp, verifyPath, verifyPort, verifyMac } from '../lib/port-map.js';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), FX = n => path.join(ROOT, 'tests/fixtures/cisco', `acc-sw-01-${n}.txt`), read = n => fs.readFileSync(FX(n), 'utf8');
const map = () => ({ switch_ref: 'acc-sw-01', arp: parseArp(read('arp')), mac_table: parseMacTable(read('mac')), switchports: parseSwitchport(read('switchport')), lldp: parseLldp(read('lldp')) });

test('Cisco ARP, MAC table, switchport and LLDP output are parsed (CG-101)', () => {
  const m = map();
  assert.equal(m.arp.length, 6); assert.deepEqual(m.arp[0], { ip: '10.20.10.15', mac: '00:50:56:aa:00:15', interface: 'Vlan10' });
  assert.equal(m.mac_table.length, 7, 'the CPU entry is not a port');
  assert.deepEqual(m.switchports.map(s => [s.interface, s.mode, s.access_vlan, s.voice_vlan]), [['Gi1/0/5', 'access', 10, 20], ['Gi1/0/12', 'access', 10, null], ['Gi1/0/48', 'trunk', 1, null]]);
  assert.deepEqual(m.lldp.map(n => [n.interface, n.system_name, n.hypervisor, n.capabilities.join(',')]), [['Gi1/0/12', 'esx-host-07', true, 'S'], ['Gi1/0/48', 'CORE-SW-01', false, 'B,R']]);
});

test('the IP-MAC-port-VLAN-user-asset path is proven before isolation and trunks, uplinks and shared hosts are refused (CG-101)', () => {
  const m = map(), nac = [{ category: 'nac', outcome: 'success', mac: 'a4:bb:6d:11:20:21', user: 'alice', time: new Date().toISOString() }];
  const ok = verifyPath({ ip: '10.20.10.21', maps: [m], nacRecords: nac, asset: { external_id: 'ws-alice', addresses: ['10.20.10.21'] } });
  assert.equal(ok.safe_to_isolate, true); assert.deepEqual([ok.interface, ok.vlan, ok.user], ['Gi1/0/5', 10, 'alice']);
  assert.deepEqual(ok.steps.map(s => [s.step, s.state]), [['ip-to-mac', 'verified'], ['mac-to-port', 'verified'], ['port-role', 'verified'], ['vlan', 'verified'], ['user', 'verified'], ['asset', 'verified']]);
  assert.match(ok.steps[2].detail, /likely an IP phone/);
  const vm = verifyPath({ ip: '10.20.10.15', maps: [m] }); assert.equal(vm.safe_to_isolate, false); assert.match(vm.steps.find(s => s.step === 'port-role').detail, /virtualization host/);
  const trunk = verifyPath({ ip: '10.20.10.40', maps: [m] }); assert.equal(trunk.steps.at(-1).state, 'blocking'); assert.match(trunk.steps.at(-1).detail, /trunk or uplink/);
  const spoof = verifyPath({ ip: '10.20.10.41', maps: [m] }); assert.match(spoof.steps[0].detail, /several MAC addresses/);
  assert.equal(verifyPath({ ip: '10.20.10.99', maps: [m] }).steps[0].state, 'unverified');
  assert.equal(verifyPath({ ip: '10.20.10.21', maps: [m], asset: { external_id: 'other', addresses: ['10.9.9.9'] } }).safe_to_isolate, false);
  assert.equal(verifyPort([m], 'acc-sw-01', 'GigabitEthernet1/0/5').safe_to_isolate, true);
  assert.deepEqual(['a4bb.6d11.2021', '00:50:56:aa:00:15', '00:11:22:33:44:40', 'de:ad:be:ef:00:01'].map(x => verifyMac([m], x).reason), [null, 'port-serves-virtualization-host', 'mac-only-on-trunks-or-uplinks', 'mac-not-in-port-maps']);
  assert.deepEqual(['GigabitEthernet1/0/48', 'Gi1/0/12', 'Gi1/0/7'].map(p => verifyPort([m], 'acc-sw-01', p).reason), ['port-is-not-an-access-port', 'port-serves-virtualization-host', 'port-not-in-port-map']);
});

test('the converter and API expose the verified path of an asset (CG-101)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg101-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true })); const out = path.join(dir, 'pm.json');
  const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/port-map.js'), '--switch-ref', 'acc-sw-01', '--authorization-ref', 'NET-101', '--output', out, '--arp', FX('arp'), '--mac-table', FX('mac'), '--switchport', FX('switchport'), '--lldp', FX('lldp')], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr); assert.equal(JSON.parse(r.stdout).ports, 3);
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, { clock: () => Date.now() });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = d.createSource('admin-a', { name: 'Switch exports', stale_seconds: 86400 }); d.ingest('admin-a', src.id, JSON.parse(fs.readFileSync(out, 'utf8')));
  d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'ws', kind: 'asset.observed', observed_at: new Date().toISOString(), asset: { external_id: 'ws-alice', hostname: 'WS-ALICE', os_family: 'windows', device_type: 'workstation', addresses: ['10.20.10.21'] }, details: {} }] });
  const p = d.networkPath(s.get("SELECT id FROM assets WHERE external_id='ws-alice'").id); assert.equal(p.safe_to_isolate, true); assert.equal(p.paths[0].interface, 'Gi1/0/5'); assert.ok(p.claim_ar.includes('منافذ trunk'));
});
