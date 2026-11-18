import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { digest } from '../lib/common.js';
import { negotiate } from '../lib/capability-negotiation.js';

const probe = (over = {}) => ({ probe_id: 'p1', device_ref: 'edge-01', vendor: 'cisco-iosxe', model: 'ISR4451', version: '17.3.8', license: { edition: 'network-advantage', features: [{ name: 'dna-advantage', expires_at: '2027-01-01T00:00:00.000Z' }, { name: 'old-feature', expires_at: '2026-01-01T00:00:00.000Z' }] }, probed_at: '2026-11-17T00:00:00.000Z', probe_method: 'connector', capabilities: [
  { capability: 'read', status: 'supported', method: 'RESTCONF GET', evidence: 'HTTP 200', min_version: null, license_feature: null },
  { capability: 'config', status: 'supported', method: 'RESTCONF native', evidence: 'HTTP 200', min_version: null, license_feature: null },
  { capability: 'policy', status: 'supported', method: 'RESTCONF ACL', evidence: 'HTTP 200', min_version: null, license_feature: 'dna-advantage' },
  { capability: 'isolation', status: 'supported', method: 'ISE ANC', evidence: 'ERS 200', min_version: null, license_feature: 'old-feature' },
  { capability: 'port-shutdown', status: 'supported', method: 'RESTCONF interface', evidence: 'HTTP 200', min_version: '18.1', license_feature: null },
  { capability: 'undo', status: 'unsupported', method: null, evidence: 'no rollback API', min_version: null, license_feature: null }], ...over });

test('capability negotiation requires a confirming probe, the minimum version, a current licence feature and a fresh probe', () => {
  const now = Date.parse('2026-11-18T00:00:00.000Z'), by = r => Object.fromEntries(r.map(c => [c.capability, c]));
  let r = by(negotiate(probe(), now));
  assert.equal(r.read.available, true); assert.equal(r.config.available, true, 'IOS XE 17.3.8 meets the documented RESTCONF minimum 16.6'); assert.equal(r.config.min_version, '16.6');
  assert.equal(r.policy.available, true); assert.deepEqual(r.isolation.reasons, ['license-expired']); assert.deepEqual(r['port-shutdown'].reasons, ['version-too-old']);
  assert.deepEqual(r.undo.reasons, ['probe-unsupported']); assert.deepEqual(r.logs.reasons, ['not-probed']);
  r = by(negotiate(probe({ version: '16.3.1', license: null }), now));
  assert.deepEqual(r.config.reasons, ['version-too-old']); assert.deepEqual(r.policy.reasons, ['license-missing']);
  r = by(negotiate(probe(), Date.parse('2027-01-20T00:00:00.000Z')));
  assert.ok(r.read.reasons.includes('probe-stale'));
});

test('a response action is refused when the target probe shows the needed capability is unavailable', t => {
  const s = new Store(':memory:'); t.after(() => s.close());
  let now = Date.parse('2026-11-18T05:00:00.000Z'); const d = new Domain(s, { clock: () => now }), at = new Date(now).toISOString();
  for (const id of ['admin-a', 'admin-b']) { s.run('INSERT INTO users VALUES (?,?,?,?,?)', id, id, 'fixture-not-a-password-hash', 'admin', at); s.run('INSERT INTO mfa_assertions VALUES (?,?,?,?,?,?,?)', `${id}-mfa`, id, `s-${id}`, 'totp', at, new Date(now + 5 * 60000).toISOString(), digest({ id, now })); }
  const source = d.createSource('admin-a', { name: 'Probe test', stale_seconds: 3600 }), asset = { external_id: 'host-01', hostname: 'HOST-01', os_family: 'windows', device_type: 'workstation', addresses: [] };
  const ingest = events => d.ingest('admin-a', source.id, { schema_version: 'cg.telemetry/1', events });
  const responder = d.createSource('admin-a', { name: 'EDR response connector', stale_seconds: 3600, source_type: 'response-connector' }), respond = events => d.ingest('admin-a', responder.id, { schema_version: 'cg.telemetry/1', events });
  respond([{ event_id: 'cap', kind: 'response.capability', observed_at: at, asset, details: { connector_id: 'EDR-1', owner_system: 'cyberguard-connector', capabilities: ['endpoint.isolate-device'], target_asset_refs: ['host-01'], tested_at: at, evidence_ref: 'EDR-TEST', status: 'active' } },
    { event_id: 'mgmt', kind: 'response.management_preflight', observed_at: at, asset, details: { connector_id: 'EDR-1', action_type: 'endpoint.isolate-device', target_hash: digest({ device_ref: 'host-01' }), protected_role: 'none', management_channel_impact: 'none', alternate_management: { status: 'not-applicable', evidence_ref: null }, captured_at: at, evidence_ref: 'MGMT' } }]);
  const assetId = d.list('assets').items.find(a => a.external_id === 'host-01').id, request = () => d.previewAction('admin-a', { type: 'endpoint.isolate-device', asset_id: assetId, target: { device_ref: 'host-01' }, connector_id: 'EDR-1', authorization_ref: 'IR-044', reason: 'Contain', ttl_seconds: 600 });
  const probeEvent = (id, status) => ({ event_id: id, kind: 'device.capability_probe', observed_at: new Date(now).toISOString(), asset, details: { probe_id: 'local-host-01', device_ref: 'host-01', vendor: 'microsoft-windows', model: 'Windows 11 Pro', version: '10.0.26200', license: { edition: 'Pro', features: [] }, probed_at: new Date(now).toISOString(), probe_method: 'local-script', capabilities: [{ capability: 'isolation', status, method: 'Windows Firewall', evidence: status === 'supported' ? 'administrator' : 'not administrator', min_version: null, license_feature: null }] } });
  ingest([probeEvent('probe-1', 'unsupported')]);
  assert.throws(request, /device_capability_unavailable/);
  const caps = d.deviceCapabilities().items[0].capabilities.find(c => c.capability === 'isolation'); assert.deepEqual(caps.reasons, ['probe-unsupported']);
  now += 60000; ingest([probeEvent('probe-2', 'supported')]);
  assert.equal(request().status, 'pending-approval', 'a newer probe confirming isolation lets the governed request proceed');
  assert.throws(() => ingest([{ ...probeEvent('bad', 'supported'), details: { ...probeEvent('bad', 'supported').details, capabilities: [{ capability: 'teleport', status: 'supported', method: null, evidence: null, min_version: null, license_feature: null }] } }]), /invalid_probe_capability_0_name/);
});

test('read collectors and response connectors are separate privilege classes with explicit asset authorization (CG-045)', t => {
  const s = new Store(':memory:'); t.after(() => s.close());
  const now = Date.parse('2026-11-18T06:00:00.000Z'), at = new Date(now).toISOString(), d = new Domain(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', at);
  const reader = d.createSource('admin-a', { name: 'Read collector', stale_seconds: 3600, source_type: 'network-collector' }), writer = d.createSource('admin-a', { name: 'Response connector', stale_seconds: 3600, source_type: 'response-connector' });
  const asset = { external_id: 'host-45', hostname: 'HOST-45', os_family: 'windows', device_type: 'workstation', addresses: [] };
  const send = (src, id, kind, details) => d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: id, kind, observed_at: at, asset, details }] });
  const cap = refs => ({ connector_id: 'EDR-45', owner_system: 'cyberguard-connector', capabilities: ['endpoint.isolate-device'], target_asset_refs: refs, tested_at: at, evidence_ref: 'EDR-TEST-45', status: 'active' });
  assert.throws(() => send(reader, 'c1', 'response.capability', cap(['host-45'])), /response_registration_requires_response_connector_source/);
  assert.throws(() => send(writer, 't1', 'auth.failed', { account: 'x', source_ip: '198.51.100.9', protocol: 'rdp' }), /response_connector_cannot_ingest_telemetry/);
  for (const bad of [['*'], ['any'], ['host-*']]) assert.throws(() => send(writer, `w-${bad}`, 'response.capability', cap(bad)), /response_capability_requires_explicit_assets/);
  assert.doesNotThrow(() => send(writer, 'c2', 'response.capability', cap(['host-45'])));
  assert.doesNotThrow(() => send(reader, 't2', 'auth.failed', { account: 'x', source_ip: '198.51.100.9', protocol: 'rdp' }));
  assert.throws(() => d.responseJobs(reader.id), /source_not_authorized_for_response_jobs/);
  assert.equal(d.responseJobs(writer.id).items.length, 0);
  const listed = Object.fromEntries(d.sources().map(x => [x.name, [x.source_type, x.privilege]]));
  assert.deepEqual(listed['Response connector'], ['response-connector', 'write']); assert.deepEqual(listed['Read collector'], ['network-collector', 'read']);
});
