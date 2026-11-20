import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { evaluateSession } from '../lib/management-plane.js';
import { iosxeNative } from '../lib/connectors/cisco.js';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const policy = { policy_id: 'MGMT-CORE', scope: { asset_refs: ['core-sw-01'], networks: ['192.0.2.0/28'] }, approved_sources: ['10.99.0.0/29'], approved_protocols: ['ssh', 'https', 'snmpv3'], reference_required: true, admin_hours: { days: [0, 1, 2, 3, 4], start: '06:00', end: '18:00' }, evidence_ref: 'MGMT-STD-2026' };
const session = (over = {}) => ({ session_id: 's', protocol: 'ssh', source_a: { hostname: 'jump-01', ip: '10.99.0.4', account: 'netadmin' }, target_b: { hostname: 'CORE-SW-01', ip: '192.0.2.5', account: null }, relay: false, evidence_type: 'authentication_log', assessment: 'authorized', assessment_basis: 'source-report', authorization_ref: 'CHG-2026-118', rationale: null, ...over });

test('administrative sessions are checked for approved source, protocol, authorization and hours (CG-102)', () => {
  const monday10 = '2026-11-16T10:00:00.000Z', saturday = '2026-11-21T23:30:00.000Z';
  assert.deepEqual(evaluateSession(policy, session(), monday10), []);
  assert.deepEqual(evaluateSession(policy, session({ source_a: { hostname: 'laptop', ip: '10.20.10.21', account: 'netadmin' } }), monday10).map(v => v.id), ['unapproved-source']);
  assert.deepEqual(evaluateSession(policy, session({ protocol: 'rdp' }), monday10).map(v => v.id), ['unapproved-protocol']);
  assert.deepEqual(evaluateSession(policy, session({ authorization_ref: null }), saturday).map(v => v.id), ['no-authorization', 'outside-hours']);
  assert.deepEqual(evaluateSession(policy, session(), saturday), [], 'an emergency change reference allows access outside hours');
});

test('violations raise alerts and insecure management protocols in device configurations are listed (CG-102)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); const now = Date.parse('2026-11-16T10:00:00.000Z'), d = new Domain(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString());
  const src = d.createSource('admin-a', { name: 'Network', stale_seconds: 86400 }), at = new Date(now).toISOString(), core = { external_id: 'core-sw-01', hostname: 'CORE-SW-01', os_family: 'network', device_type: 'switch', addresses: ['192.0.2.5'] };
  const ingest = events => d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events });
  ingest([{ event_id: 'pol', kind: 'management.policy', observed_at: at, asset: core, details: policy }]);
  ingest([{ event_id: 'ok', kind: 'remote.authenticated', observed_at: at, asset: core, details: session({ session_id: 'ok' }) }, { event_id: 'bad', kind: 'remote.authenticated', observed_at: at, asset: core, details: session({ session_id: 'bad', protocol: 'rdp', source_a: { hostname: 'laptop', ip: '10.20.10.21', account: 'netadmin' }, authorization_ref: null, assessment: 'unknown' }) }]);
  const alerts = s.all("SELECT severity,title FROM alerts WHERE rule_id='CG-MGMT-ACCESS-102' ORDER BY severity,title"); assert.equal(alerts.length, 3); assert.ok(alerts.some(a => /10\.20\.10\.21/.test(a.title)));
  const c = iosxeNative(fs.readFileSync(new URL('./fixtures/cisco/iosxe-native.json', import.meta.url), 'utf8')), ref = 'isr-edge-01';
  ingest([{ event_id: 'cfg', kind: 'network.device_config', observed_at: at, asset: { external_id: ref, hostname: 'ISR-EDGE-01', os_family: 'network', device_type: 'router', addresses: ['198.51.100.1'] }, details: { snapshot_id: `${ref}:1`, device_ref: ref, device_type: 'router', vendor: 'cisco', model: 'ISR4451-X/K9', firmware_version: c.firmware_version, dns_servers: c.dns_servers, ntp_servers: c.ntp_servers, vpn_profiles: [], management: c.management, config_sha256: null } }]);
  const v = d.managementPlane(); assert.equal(v.violations, 1); assert.equal(v.sessions.find(x => x.violations.length).violations.length, 3);
  assert.ok(v.insecure_management.some(x => x.device_ref === ref), 'Telnet enabled on the router is listed'); assert.ok(v.claim_ar.includes('الإجراء المعتمد'));
  assert.throws(() => ingest([{ event_id: 'pol2', kind: 'management.policy', observed_at: at, asset: core, details: { ...policy, approved_protocols: ['telnet'] } }]), /invalid_mgmt_protocol_0/);
});
