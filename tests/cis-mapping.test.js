import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { cisView } from '../lib/cis-mapping.js';

test('each system baseline maps to the assessed CIS benchmark with version, source, date and evidence, flags mismatched versions, stale assessments, failed controls and non-commercial licensing (CG-178)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); const now = Date.now(), d = new Domain(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin', 'admin', 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString());
  const src = d.createSource('admin', { name: 'Assessments', stale_seconds: 86400 }), day = n => new Date(now - n * 86400000).toISOString();
  const host = (n, os) => ({ external_id: n, hostname: n.toUpperCase(), os_family: os, device_type: 'server', addresses: [] });
  const res = (pass, fail) => [...Array.from({ length: pass }, (_, i) => ({ control_id: `1.${i + 1}`, status: 'pass', evidence_ref: `EV-${i}` })), ...Array.from({ length: fail }, (_, i) => ({ control_id: `2.${i + 1}`, title: 'Ensure setting', status: 'fail', evidence_ref: `EVF-${i}` })), { control_id: '9.9', status: 'manual' }];
  const ev = (id, asset, details) => ({ event_id: id, kind: 'compliance.cis_assessment', observed_at: new Date(now).toISOString(), asset, details: { assessment_id: id, profile: 'Level 1', tool: 'CIS-CAT Pro (owner licence)', source_ref: 'https://www.cisecurity.org/cis-benchmarks', ...details } });
  d.ingest('admin', src.id, { schema_version: 'cg.telemetry/1', events: [
    ev('win', host('win-01', 'windows'), { platform: 'windows-server', platform_version: 'Windows Server 2022', benchmark_title: 'Microsoft Windows Server 2022', benchmark_version: 'owner-declared', assessed_at: day(10), license_basis: 'securesuite-member', results: res(40, 0) }),
    ev('win-old', host('win-02', 'windows'), { platform: 'windows-server', platform_version: 'Windows Server 2022', benchmark_title: 'Microsoft Windows Server 2019', benchmark_version: 'owner-declared', assessed_at: day(120), license_basis: 'free-pdf-non-commercial', results: res(30, 2) }),
    ev('ios', host('rtr-01', 'network'), { platform: 'cisco-ios-xe', platform_version: '17.9.4', benchmark_title: 'Cisco IOS XE 17.x', benchmark_version: '2.2.2', assessed_at: day(5), license_basis: 'unknown', results: res(20, 1) }),
    ev('m365', host('tenant-lab', 'unknown'), { platform: 'm365', platform_version: 'tenant', benchmark_title: 'Microsoft 365 Foundations', benchmark_version: '7.0.0', assessed_at: day(3), license_basis: 'commercial-licence', results: res(50, 0) })] });
  const v = cisView(s, { clock: () => now }), by = a => v.systems.find(x => x.asset === a);
  assert.deepEqual(by('WIN-01').issues, [], 'matching benchmark, fresh, licensed, all scored controls pass');
  assert.equal(by('WIN-01').pass_rate, 100);
  assert.deepEqual(by('WIN-02').issues, ['benchmark-does-not-match-platform-version', 'assessment-stale', 'licence-may-restrict-commercial-use', 'failed-controls']);
  assert.deepEqual(by('RTR-01').issues, ['licence-may-restrict-commercial-use', 'failed-controls']); assert.equal(by('RTR-01').failed[0].control_id, '2.1');
  assert.deepEqual([by('TENANT-LAB').issues, by('TENANT-LAB').counts.manual], [[], 1]);
  assert.equal(v.licence.licence, 'CC BY-NC-SA 4.0 (CIS Benchmarks free PDF use)');
  assert.deepEqual(s.all("SELECT title FROM alerts WHERE rule_id='CG-CIS-BASELINE-178' ORDER BY title").map(a => /does not match/.test(a.title)), [false, true], 'the IOS XE failures and the mismatched Windows benchmark raise alerts');
  assert.throws(() => d.ingest('admin', src.id, { schema_version: 'cg.telemetry/1', events: [ev('bad', host('x', 'linux'), { platform: 'linux', platform_version: '1', benchmark_title: 'x', benchmark_version: '1', assessed_at: day(1), license_basis: 'unknown', results: res(1, 0) })] }), /cis_platform/);
});
