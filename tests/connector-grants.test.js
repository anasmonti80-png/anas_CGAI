import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { digest } from '../lib/common.js';
import { ConnectorGrants } from '../lib/connector-grants.js';

test('sources are read-only by default; a connector writes only under a second-approved, expiring, revocable grant naming the target ID, and tokens are inventoried (CG-177)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.now(); const d = new Domain(s, { clock: () => now }), cg = new ConnectorGrants(s, { clock: () => now });
  for (const id of ['admin-a', 'admin-b']) { s.run('INSERT INTO users VALUES (?,?,?,?,?)', id, id, 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString()); s.run('INSERT INTO mfa_assertions VALUES (?,?,?,?,?,?,?)', `${id}-mfa`, id, `fixture-session-${id}`, 'totp', new Date(now).toISOString(), new Date(now + 400 * 86400000).toISOString(), digest({ id, now })); }
  const sensors = d.createSource('admin-a', { name: 'Sensors', stale_seconds: 86400 }), edr = d.createSource('admin-a', { name: 'EDR connector', stale_seconds: 86400, source_type: 'response-connector' });
  const host = n => ({ external_id: n, hostname: n.toUpperCase(), os_family: 'windows', device_type: 'workstation', addresses: [] });
  const put = (src, ...e) => d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: e }), ev = (id, kind, details, a) => ({ event_id: id, kind, observed_at: new Date(now).toISOString(), asset: a, details });
  const capability = () => put(edr, ev(`cap-${now}`, 'response.capability', { connector_id: 'EDR-177', owner_system: 'cyberguard-connector', capabilities: ['endpoint.isolate-device'], target_asset_refs: ['ws-1', 'ws-2'], tested_at: new Date(now - 3600000).toISOString(), evidence_ref: 'EDR-TEST', status: 'active' }, host('ws-1')),
    ...['ws-1', 'ws-2'].map(n => ev(`pf-${n}-${now}`, 'response.management_preflight', { connector_id: 'EDR-177', action_type: 'endpoint.isolate-device', target_hash: digest({ device_ref: n }), protected_role: 'none', management_channel_impact: 'none', alternate_management: { status: 'not-applicable', evidence_ref: null }, captured_at: new Date(now - 60000).toISOString(), evidence_ref: 'PF' }, host(n))));
  put(sensors, ev('a1', 'asset.observed', {}, host('ws-1')), ev('a2', 'asset.observed', {}, host('ws-2'))); capability();
  const id = n => s.get("SELECT a.id FROM assets a JOIN sources s ON s.id=a.source_id WHERE a.external_id=? AND s.name='Sensors'", n).id;
  const isolate = n => d.previewAction('admin-a', { type: 'endpoint.isolate-device', asset_id: id(n), target: { device_ref: n }, connector_id: 'EDR-177', authorization_ref: 'IR-177', reason: 'Contain', ttl_seconds: 600 });
  // The connector declared ws-1 and ws-2, but without a grant it is read-only.
  assert.throws(() => isolate('ws-1'), /connector_write_grant_required_for_target/);
  assert.throws(() => cg.request('admin-a', { source_id: sensors.id, scope_type: 'site', scope_ref: 'HQ', target_ids: ['ws-1'], reason: 'x' }), /write_grants_are_for_response_connectors/);
  assert.throws(() => cg.request('admin-a', { source_id: edr.id, scope_type: 'site', scope_ref: 'HQ', target_ids: ['ws-*'], reason: 'x' }), /grant_target_ids_must_be_explicit/);
  const g = cg.request('admin-a', { source_id: edr.id, scope_type: 'site', scope_ref: 'HQ', target_ids: ['ws-1'], days: 30, reason: 'EDR containment for HQ workstations' });
  assert.throws(() => cg.approve('admin-a', g.id), /grant_needs_second_approver/);
  assert.throws(() => isolate('ws-1'), /connector_write_grant_required_for_target/, 'a pending grant does not allow writes');
  assert.equal(cg.approve('admin-b', g.id).state, 'active');
  assert.ok(isolate('ws-1').id, 'the granted target ID is allowed');
  assert.throws(() => isolate('ws-2'), /connector_write_grant_required_for_target/, 'a target the grant does not name is refused');
  // Expiry and revocation.
  now += 31 * 86400000; s.run('UPDATE mfa_assertions SET verified_at=?', new Date(now).toISOString()); capability();
  assert.equal(cg.get(g.id).state, 'expired'); assert.throws(() => isolate('ws-1'), /connector_write_grant_required_for_target/);
  const g2 = cg.approve('admin-b', cg.request('admin-a', { source_id: edr.id, scope_type: 'site', scope_ref: 'HQ', target_ids: ['ws-1'], days: 7, reason: 'Renewed' }).id);
  cg.revoke('admin-b', g2.id, 'Contract ended'); assert.throws(() => isolate('ws-1'), /connector_write_grant_required_for_target/);
  // Token inventory: privilege and rotation state per source.
  now += 60 * 86400000; const inv = cg.view().sources, by = n => inv.find(x => x.name === n);
  assert.deepEqual([by('Sensors').privilege, by('Sensors').token, by('EDR connector').grants.map(x => x.state)], ['read-only', 'rotation-due', ['revoked', 'expired']]);
  assert.deepEqual(s.all("SELECT action FROM audit WHERE action LIKE 'connector_grant.%' ORDER BY seq").map(r => r.action), ['connector_grant.requested', 'connector_grant.approved', 'connector_grant.requested', 'connector_grant.approved', 'connector_grant.revoked']);
});
