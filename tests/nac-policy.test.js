import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { assessNacPolicy } from '../lib/nac-policy.js';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), recent = new Date(Date.now() - 86400000).toISOString();
const strong = { policy_id: 'NAC-HQ', site: 'HQ', user_authentication: 'eap-tls', device_authentication: 'certificate', unknown_devices: 'quarantine', guest: { network: 'isolated-internet-only', sponsor_required: true, max_hours: 8 }, unmanaged_devices: 'restricted-segment', posture_check: 'required', reauth_hours: 12, segmentation: [{ from: 'users', to: ['apps'] }, { from: 'iot', to: ['iot-mgmt'] }], evidence_ref: 'ISE-POLICY-EXPORT-2026-11', reviewed_at: recent };
const weak = { ...strong, policy_id: 'NAC-BRANCH', site: 'Branch-7', user_authentication: 'peap-mschapv2', device_authentication: 'mab', unknown_devices: 'allow', guest: { network: 'shared', sponsor_required: false, max_hours: null }, unmanaged_devices: 'allow', posture_check: 'none', reauth_hours: null, segmentation: [{ from: 'users', to: ['*'] }], reviewed_at: '2024-01-01T00:00:00.000Z' };

test('NAC policy assessment checks device and user authenticity and the handling of new, guest and unmanaged devices (CG-098)', () => {
  const good = assessNacPolicy(strong); assert.deepEqual(good.findings, []); assert.equal(good.score, 100);
  const bad = assessNacPolicy(weak), ids = bad.findings.map(f => [f.id, f.severity]);
  assert.deepEqual(ids, [['mab-only', 'medium'], ['peap-mschapv2', 'medium'], ['unknown-devices-allowed', 'high'], ['guest-not-isolated', 'high'], ['guest-unbounded', 'low'], ['unmanaged-allowed', 'high'], ['no-posture-check', 'medium'], ['long-reauthentication', 'low'], ['flat-segmentation', 'medium'], ['policy-not-reviewed', 'low']]);
  assert.equal(bad.score, 0); assert.ok(bad.findings.every(f => /[؀-ۿ]/.test(f.title_ar)));
});

test('the declared policy is compared with NAC authentications actually observed in FreeRADIUS logs (CG-098)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg098-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const d0 = new Date(Date.now() - 3600000), mon = d0.toLocaleString('en-US', { month: 'short', timeZone: 'UTC' }), day = d0.toLocaleString('en-US', { weekday: 'short', timeZone: 'UTC' }), hh = String(d0.getUTCHours()).padStart(2, '0');
  const stamp = `${day} ${mon} ${String(d0.getUTCDate()).padStart(2, ' ')} ${hh}:10:00 ${d0.getUTCFullYear()}`;
  fs.writeFileSync(path.join(dir, 'radius.log'), [`${stamp} : Auth: (11) Login OK: [alice/<via Auth-Type = eap>] (from client sw-hq-01 port 10 cli 00-11-22-33-44-55)`, `${stamp} : Auth: (12) Login OK: [001122334466] (from client sw-hq-01 port 11 cli 00-11-22-33-44-66)`, `${stamp} : Auth: (13) Login incorrect: [bob/<via Auth-Type = eap>] (from client sw-hq-01 port 12 cli 00-11-22-33-44-77)`].join('\n') + '\n');
  execFileSync(process.execPath, [path.join(ROOT, 'scripts/logs-to-telemetry.js'), 'freeradius', path.join(dir, 'radius.log'), path.join(dir, 'radius.json'), 'HQ RADIUS'], { stdio: 'pipe' });
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, { clock: () => Date.now() });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = d.createSource('admin-a', { name: 'NAC', stale_seconds: 86400 }), asset = { external_id: 'ise-01', hostname: 'ISE-01', os_family: 'network', device_type: 'server', addresses: [] };
  // Without logs: enforcement cannot be confirmed.
  d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'p-hq', kind: 'nac.policy', observed_at: new Date().toISOString(), asset, details: strong }] });
  assert.deepEqual(d.nacPosture().items[0].findings.map(f => f.id), ['no-nac-evidence']);
  d.ingest('admin-a', src.id, JSON.parse(fs.readFileSync(path.join(dir, 'radius.json'), 'utf8')));
  const v = d.nacPosture(), hq = v.items.find(x => x.site === 'HQ');
  assert.deepEqual([v.observed.dot1x_success, v.observed.mab_success, v.observed.failure, v.observed.distinct_devices], [1, 1, 1, 3]);
  assert.deepEqual(hq.findings.map(f => f.id), ['policy-drift-mab'], 'certificates required on paper, but a MAC-based login succeeded');
  d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'p-branch', kind: 'nac.policy', observed_at: new Date().toISOString(), asset, details: weak }] });
  assert.equal(s.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-NAC-POLICY-098'").n, 3, 'one alert per high-severity gap');
  assert.equal(d.nacPosture().items[0].site, 'Branch-7', 'weakest site first'); assert.ok(v.claim_ar.includes('سجلات NAC'));
  assert.throws(() => d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'bad', kind: 'nac.policy', observed_at: new Date().toISOString(), asset, details: { ...strong, unknown_devices: 'maybe' } }] }), /invalid_nac_unknown_devices/);
});
