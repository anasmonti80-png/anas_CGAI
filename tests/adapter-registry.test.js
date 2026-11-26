import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { AdapterRegistry, loadRegistry, validateRegistry } from '../lib/adapter-registry.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const fixture = (t, now = Date.parse('2026-11-26T12:00:00Z')) => { const s = new Store(':memory:'); t.after(() => s.close()); let clock = now; return { s, reg: new AdapterRegistry(s, { root: ROOT, clock: () => clock }), advance: d => { clock += d * 86400000; } }; };

test('every adapter entry names a function, operations, firmware basis and existing tests, and invalid claims are rejected (CG-138)', () => {
  const reg = loadRegistry(ROOT); assert.deepEqual(validateRegistry(reg, ROOT), []);
  assert.ok(reg.entries.length >= 15); assert.ok(['cisco', 'huawei', 'juniper', 'fortinet'].every(v => reg.entries.some(e => e.vendor === v)));
  const bad = JSON.parse(JSON.stringify(reg)); Object.assign(bad.entries[0], { function: 'everything' }); Object.assign(bad.entries[1], { operations: { read: true, write: true, undo: false } }); bad.entries[2].evidence.tests = [{ file: 'tests/cisco-connector.test.js', name: 'a test that does not exist' }]; bad.entries[4].firmware = { min: '16.6', basis: null };
  const errors = validateRegistry(bad, ROOT).join('\n');
  assert.match(errors, /A-001: function must be a known function, not a vendor-wide claim/); assert.match(errors, /A-002: a write operation must have an undo/); assert.match(errors, /A-003: test not found/); assert.match(errors, /A-005: a minimum firmware needs its basis/);
});

test('support is answered per function, model and firmware with the evidence level, never from the vendor name (CG-138)', t => {
  const { reg } = fixture(t);
  const fw = reg.supports({ vendor: 'Fortinet', function: 'firewall-policy-read' }); assert.equal(fw.answer, 'fixture-verified'); assert.match(fw.reasons[0], /documented response shape only, not on a device/);
  const other = reg.supports({ vendor: 'fortinet', function: 'port-shutdown' }); assert.equal(other.answer, 'no-adapter'); assert.match(other.reasons[0], /other functions exist, which is not support for this one/);
  assert.equal(reg.supports({ vendor: 'cisco', function: 'config-read', firmware: '16.3.1' }).answer, 'unsupported-firmware', 'RESTCONF needs IOS XE 16.6');
  assert.equal(reg.supports({ vendor: 'cisco', function: 'config-read', firmware: '17.9.4' }).answer, 'fixture-verified');
  assert.equal(reg.supports({ vendor: 'acme', function: 'inventory-read' }).answer, 'no-adapter');
});

test('a recorded lab test makes one model and firmware lab-validated, write adapters need a verified undo, and old evidence goes stale (CG-138)', t => {
  const { s, reg, advance } = fixture(t);
  assert.throws(() => reg.recordLab('admin', 'A-006', { model: 'ISE 3.3', firmware: '3.3', result: 'pass', lab_ref: 'LAB-138-1' }), /write_adapter_lab_requires_verified_undo/);
  reg.recordLab('admin', 'A-006', { model: 'ISE 3.3', firmware: '3.3', result: 'pass', lab_ref: 'LAB-138-1', undo_verified: true, tested_at: '2026-11-25T09:00:00Z' });
  assert.equal(reg.supports({ vendor: 'cisco', function: 'endpoint-quarantine', model: 'ISE 3.3', firmware: '3.3' }).answer, 'lab-validated');
  const elsewhere = reg.supports({ vendor: 'cisco', function: 'endpoint-quarantine', model: 'ISE 3.1', firmware: '3.1' }); assert.equal(elsewhere.answer, 'fixture-verified'); assert.match(elsewhere.reasons[0], /not on this model or firmware/);
  reg.recordLab('admin', 'A-015', { model: 'FortiGate 100F', firmware: '7.4.3', result: 'fail', lab_ref: 'LAB-138-2' });
  const v = reg.view(), a6 = v.entries.find(e => e.id === 'A-006'); assert.equal(a6.status, 'lab-validated'); assert.equal(v.entries.find(e => e.id === 'A-015').failed_labs, 1); assert.equal(v.summary.lab_validated, 1);
  assert.equal(s.all("SELECT 1 FROM audit WHERE action='adapter.lab_recorded'").length, 2);
  advance(200); const later = reg.view(); assert.equal(later.entries.find(e => e.id === 'A-006').status, 'stale', 'lab and registry evidence older than 180 days is stale'); assert.equal(later.summary.stale, later.entries.length);
});
