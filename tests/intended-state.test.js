import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { parseNetbox, IntendedState } from '../lib/intended-state.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), NB = n => path.join(ROOT, 'tests/fixtures/netbox', `${n}.json`), FX = n => path.join(ROOT, 'tests/fixtures/cisco', `acc-sw-01-${n}.txt`);
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg132-')); process.once('exit', () => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'analyst', new Date().toISOString()); const src = d.createSource('a', { name: 'Net', stale_seconds: 86400 });
  const run = (script, a) => { const out = path.join(dir, `${script}-${Math.random()}.json`), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts', script), ...a, '--output', out], { encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); d.ingest('a', src.id, JSON.parse(fs.readFileSync(out, 'utf8'))); return JSON.parse(r.stdout); };
  run('port-map.js', ['--switch-ref', 'acc-sw-01', '--authorization-ref', 'NET-132', '--arp', FX('arp'), '--mac-table', FX('mac'), '--switchport', FX('switchport'), '--lldp', FX('lldp')]);
  const alice = { external_id: 'ws-alice', hostname: 'WS-ALICE', os_family: 'windows', device_type: 'workstation', addresses: ['10.20.10.21'] };
  d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'alice', kind: 'asset.observed', observed_at: new Date().toISOString(), asset: alice, details: {} },
    { event_id: 'ctx', kind: 'asset.context', observed_at: new Date().toISOString(), asset: alice, details: { owner: { owner_id: 'hr', display_name: 'HR', contact: null }, business_service: 'Payroll', service_name: null, site: 'HQ', data_sensitivity: 'confidential', maintenance_windows: [], service_criticality: 'high' } }] });
  return { s, d, run, is: new IntendedState(s, {}) };
}

test('NetBox exports are converted read-only into intended devices with interfaces, VLANs and cabling (CG-132)', () => {
  const dev = parseNetbox({ devices: JSON.parse(fs.readFileSync(NB('devices'), 'utf8')), interfaces: JSON.parse(fs.readFileSync(NB('interfaces'), 'utf8')) });
  assert.deepEqual(dev.map(x => [x.name, x.ip, x.owner]), [['WS-ALICE', '10.20.10.21', 'Finance'], ['PRN-FLOOR2', '10.20.10.40', null], ['OLD-NAS', '10.20.10.77', 'IT']]);
  assert.deepEqual(dev[1].interfaces[0], { netbox_id: 202, name: 'eth0', mac: '00:11:22:33:44:40', vlan: 30, switch: 'acc-sw-01', port: 'Gi1/0/7', last_updated: '2025-02-10T08:00:00.000000Z' });
});

test('differences in presence, interface, VLAN and owner are listed with which side is newer (CG-132)', t => {
  const { run, is } = fixture(t); assert.equal(is.view().source, null);
  run('netbox-to-telemetry.js', ['--devices', NB('devices'), '--interfaces', NB('interfaces')]);
  const v = is.view(), by = k => v.conflicts.find(c => c.key === k);
  assert.equal(by('OLD-NAS:not-observed').type, 'not-observed');
  assert.match(by('PRN-FLOOR2:eth0:interface').detail, /learned on acc-sw-01 Gi1\/0\/48 \(trunk\)/); assert.equal(by('PRN-FLOOR2:eth0:vlan').observed, 10); assert.equal(by('PRN-FLOOR2:eth0:vlan').newer, 'observed', 'the source-of-truth record is older than the observation');
  assert.equal(by('PRN-FLOOR2:owner').type, 'owner-missing'); assert.equal(by('WS-ALICE:owner').type, 'owner-mismatch'); assert.equal(by('WS-ALICE:owner').observed, 'HR');
  assert.ok(!v.conflicts.some(c => c.key.startsWith('WS-ALICE:eth0')), 'matching interface, VLAN and MAC produce no conflict');
  assert.ok(v.conflicts.some(c => c.type === 'unregistered' && c.device === '10.20.10.15'), 'ARP addresses missing from the source of truth are listed');
  const dup = v.conflicts.filter(c => c.key === '10.20.10.41:unregistered'); assert.equal(dup.length, 1, 'one difference per address even when two MACs answer'); assert.match(dup[0].detail, /0011.2233.4441|00:11:22:33:44:41/); assert.equal(new Set(v.conflicts.map(c => c.key)).size, v.conflicts.length, 'review keys are unique'); assert.ok(v.claim_ar.includes('لا يكتب CyberGuard'));
});

test('each difference is reviewed by a person and only reviewed updates reach the NetBox patch (CG-132)', t => {
  const { s, run, is } = fixture(t); run('netbox-to-telemetry.js', ['--devices', NB('devices'), '--interfaces', NB('interfaces')]);
  assert.throws(() => is.review('a', { key: 'PRN-FLOOR2:eth0:vlan', decision: 'delete-everything' }), /invalid_review_decision/);
  assert.throws(() => is.review('a', { key: '10.20.10.15:unregistered', decision: 'update-source-of-truth' }), /nothing_to_update_in_source_of_truth/);
  is.review('a', { key: 'PRN-FLOOR2:eth0:vlan', decision: 'update-source-of-truth', note: 'Printer moved to VLAN 10 in change CHG-77' }); is.review('a', { key: 'OLD-NAS:not-observed', decision: 'fix-device' });
  const p = is.patch(); assert.equal(p.applied_by_cyberguard, false); assert.deepEqual(p.changes.map(c => [c.netbox.object, c.netbox.id, c.from, c.to]), [['dcim.interface', 202, 30, 10]]);
  assert.equal(is.view().conflicts.find(c => c.key === 'PRN-FLOOR2:eth0:vlan').review.decision, 'update-source-of-truth'); assert.equal(s.all("SELECT 1 FROM audit WHERE action='intended_state.reviewed'").length, 2);
});
