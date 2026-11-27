import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { digest } from '../lib/common.js';
import { IsolationSurvival } from '../lib/isolation-survival.js';

test('a host behind a full-tunnel VPN, proxy or hypervisor host is isolated only with a survived management channel or out-of-band recovery, and isolation is not shown as success before it is proven (CG-170)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.now(); const d = new Domain(s, { clock: () => now }), iso = new IsolationSurvival(s, { clock: () => now, domain: d });
  for (const id of ['admin-a', 'admin-b']) { s.run('INSERT INTO users VALUES (?,?,?,?,?)', id, id, 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString()); s.run('INSERT INTO mfa_assertions VALUES (?,?,?,?,?,?,?)', `${id}-mfa`, id, `fixture-session-${id}`, 'totp', new Date(now).toISOString(), new Date(now + 5 * 60000).toISOString(), digest({ id, now })); }
  const sensors = d.createSource('admin-a', { name: 'Network sensors', stale_seconds: 86400 }), responder = d.createSource('admin-a', { name: 'EDR connector', stale_seconds: 86400, source_type: 'response-connector' });
  const host = { external_id: 'vpn-laptop-01', hostname: 'VPN-LAPTOP-01', os_family: 'windows', device_type: 'workstation', addresses: ['10.8.0.21'] }, target = { device_ref: 'vpn-laptop-01' };
  const ev = (id, kind, details) => ({ event_id: id, kind, observed_at: new Date(now).toISOString(), asset: host, details }), put = (src, ...e) => d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: e });
  put(sensors, ev('seen', 'asset.observed', {}));
  put(responder, ev('cap', 'response.capability', { connector_id: 'EDR-170', owner_system: 'cyberguard-connector', capabilities: ['endpoint.isolate-device'], target_asset_refs: ['vpn-laptop-01'], tested_at: new Date(now - 3600000).toISOString(), evidence_ref: 'EDR-TEST-170', status: 'active' }),
    ev('mgmt', 'response.management_preflight', { connector_id: 'EDR-170', action_type: 'endpoint.isolate-device', target_hash: digest(target), protected_role: 'none', management_channel_impact: 'none', alternate_management: { status: 'not-applicable', evidence_ref: null }, captured_at: new Date(now - 60000).toISOString(), evidence_ref: 'MGMT-170' }));
  const assetId = s.get("SELECT a.id FROM assets a JOIN sources s ON s.id=a.source_id WHERE a.external_id='vpn-laptop-01' AND s.name='Network sensors'").id;
  const request = () => d.previewAction('admin-a', { type: 'endpoint.isolate-device', asset_id: assetId, target, connector_id: 'EDR-170', authorization_ref: 'IR-170', reason: 'Contain synthetic laptop', ttl_seconds: 600 });
  // Full-tunnel VPN, untested and no recovery: refused.
  iso.record('admin-a', assetId, { path_type: 'full-tunnel-vpn', management_channel: 'EDR cloud over the corporate VPN', survival: 'untested' });
  assert.throws(request, /isolation_survival_not_proven:untested-no-recovery/);
  assert.throws(() => iso.record('admin-a', assetId, { path_type: 'full-tunnel-vpn', management_channel: 'x', survival: 'tested-survives' }), /survival_test_requires_time_and_evidence/);
  // Tested and lost: still refused; an out-of-band method with owner and evidence makes it ready.
  iso.record('admin-a', assetId, { path_type: 'full-tunnel-vpn', management_channel: 'EDR cloud over the corporate VPN', survival: 'tested-lost', tested_at: new Date(now - 86400000).toISOString(), test_evidence_ref: 'TEST-170-lost' });
  assert.throws(request, /isolation_survival_not_proven:channel-lost-no-recovery/);
  assert.throws(() => iso.record('admin-a', assetId, { path_type: 'full-tunnel-vpn', management_channel: 'x', survival: 'untested', oob_method: 'mdm' }), /oob_recovery_requires_owner_and_evidence/);
  iso.record('admin-a', assetId, { path_type: 'full-tunnel-vpn', management_channel: 'EDR cloud over the corporate VPN', survival: 'tested-lost', tested_at: new Date(now - 86400000).toISOString(), test_evidence_ref: 'TEST-170-lost', oob_method: 'mdm', oob_owner: 'endpoint-team', oob_evidence_ref: 'MDM-RELEASE-RUNBOOK-7' });
  assert.equal(iso.state(assetId).gate, 'out-of-band-recovery');
  const a = request(); d.approveAction('admin-b', a.id); d.executeAction('admin-a', a.id);
  d.completeResponseJob(responder.id, a.id, { phase: 'execute', outcome: 'succeeded', observed_state: 'EDR reports containment', evidence_ref: 'EDR-exec', rollback_supported: true });
  let shown = iso.view().actions.find(x => x.action_id === a.id); assert.equal(shown.shown_as, 'executed-not-proven', 'the connector saying done is not success');
  now += 30000; put(sensors, ev('probe', 'response.outcome_check', { action_id: a.id, check_type: 'connectivity-probe', expected_state: 'isolated', observed_state: 'isolated', checked_at: new Date(now).toISOString(), method: 'probe from monitoring host', evidence_ref: 'PROBE-170' }));
  shown = iso.view().actions.find(x => x.action_id === a.id); assert.equal(shown.shown_as, 'isolation-proven');
  // A survival test older than 30 days no longer counts on its own.
  iso.record('admin-a', assetId, { path_type: 'hypervisor-host', management_channel: 'vCenter console', survival: 'tested-survives', tested_at: new Date(now - 40 * 86400000).toISOString(), test_evidence_ref: 'TEST-old' });
  assert.equal(iso.state(assetId).gate, 'survival-test-expired');
  iso.record('admin-a', assetId, { path_type: 'direct', management_channel: 'Local EDR agent', survival: 'untested' }); assert.equal(iso.state(assetId).ready, true);
  assert.equal(s.get("SELECT COUNT(*) n FROM audit WHERE action='isolation.path_recorded'").n, 5);
});
