import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { managedDevices, toTelemetry, platformCapabilities } from '../lib/mdm.js';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), SALT = 'test-salt-cg095-0000000';
const fixture = () => JSON.parse(fs.readFileSync(path.join(ROOT, 'tests/fixtures/mdm/managed-devices.json'), 'utf8').replaceAll('__RECENT__', new Date(Date.now() - 3600000).toISOString()));

test('Intune managed devices become platform coverage with personal devices pseudonymised (CG-095)', () => {
  assert.throws(() => managedDevices(fixture(), { salt: 'short' }), /private salt/);
  const devices = managedDevices(fixture(), { salt: SALT }), byName = Object.fromEntries(devices.map(d => [d.platform, d]));
  assert.deepEqual(devices.map(d => [d.platform, d.ownership, d.compliance]), [['macos', 'corporate', 'compliant'], ['ios', 'personal', 'noncompliant'], ['android', 'corporate', 'noncompliant'], ['windows', 'corporate', 'compliant']]);
  assert.equal(byName.ios.jailbroken, true); assert.equal(byName.ios.display_name, null); assert.equal(byName.android.encrypted, false); assert.equal(byName.windows.stale, true); assert.equal(byName.macos.display_name, 'MBP-DESIGN-07');
  const text = JSON.stringify(toTelemetry(devices));
  for (const pii of ['sam.personal@example.com', 'Sam', 'F2LSYNTH0002', '+15555550123', '350000000000002', 'dana@example.com', 'C02SYNTH0001']) assert.ok(!text.includes(pii), `${pii} is not kept`);
  assert.notEqual(managedDevices(fixture(), { salt: `${SALT}-other` })[1].device_ref, byName.ios.device_ref, 'references depend on the private salt');
  assert.ok(platformCapabilities.ios.not_visible.includes('processes') && platformCapabilities.android.not_visible.some(x => /BYOD/.test(x)));
});

test('mobile posture raises jailbreak, compliance, encryption and stale alerts and states what each platform cannot see (CG-095)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg095-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const input = path.join(dir, 'devices.json'), out = path.join(dir, 'out.json'); fs.writeFileSync(input, JSON.stringify(fixture()));
  assert.match(spawnSync(process.execPath, [path.join(ROOT, 'scripts/mdm-to-telemetry.js'), input, path.join(dir, 'x.json')], { encoding: 'utf8', env: { ...process.env, CG_MDM_SALT: '' } }).stderr, /Refused: a private salt/);
  const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/mdm-to-telemetry.js'), input, out], { encoding: 'utf8', env: { ...process.env, CG_MDM_SALT: SALT } }); assert.equal(r.status, 0, r.stderr); assert.equal(JSON.parse(r.stdout).devices, 4);
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, { clock: () => Date.now() });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = d.createSource('admin-a', { name: 'Intune export', stale_seconds: 86400 }); assert.equal(d.ingest('admin-a', src.id, JSON.parse(fs.readFileSync(out, 'utf8'))).accepted, 4);
  assert.deepEqual(s.all("SELECT rule_id,severity FROM alerts WHERE rule_id LIKE 'CG-MDM-%' ORDER BY rule_id").map(a => [a.rule_id, a.severity]), [['CG-MDM-JAILBREAK-095', 'high'], ['CG-MDM-NONCOMPLIANT-095', 'medium'], ['CG-MDM-NONCOMPLIANT-095', 'medium'], ['CG-MDM-STALE-095', 'low'], ['CG-MDM-UNENCRYPTED-095', 'medium']]);
  assert.match(s.get("SELECT title FROM alerts WHERE rule_id='CG-MDM-JAILBREAK-095'").title, /BYOD [a-f0-9]{8}/);
  const v = d.mobileCoverage(); assert.deepEqual(Object.keys(v.by_platform).sort(), ['android', 'ios', 'macos', 'windows']); assert.equal(v.by_platform.ios.personal, 1); assert.ok(v.privacy_ar.includes('IMEI'));
  const bad = JSON.parse(fs.readFileSync(out, 'utf8')); bad.events[1].event_id = 'leak'; bad.events[1].details.display_name = "Sam's iPhone";
  assert.throws(() => d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: [bad.events[1]] }), /personal_device_must_not_carry_a_name/);
});
