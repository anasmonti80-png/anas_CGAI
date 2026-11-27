import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { digest } from '../lib/common.js';
import { CriticalShutdown } from '../lib/critical-shutdown.js';

test('critical infrastructure is never disrupted by a single command: only the next step of a two-approver composite plan with a window or out-of-band recovery (CG-174)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.now(); const d = new Domain(s, { clock: () => now }), cs = new CriticalShutdown(s, { clock: () => now });
  for (const id of ['admin-a', 'admin-b', 'admin-c']) { s.run('INSERT INTO users VALUES (?,?,?,?,?)', id, id, 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString()); s.run('INSERT INTO mfa_assertions VALUES (?,?,?,?,?,?,?)', `${id}-mfa`, id, `fixture-session-${id}`, 'totp', new Date(now).toISOString(), new Date(now + 60 * 60000).toISOString(), digest({ id, now })); }
  const sensors = d.createSource('admin-a', { name: 'Sensors', stale_seconds: 86400 }), responder = d.createSource('admin-a', { name: 'Mgmt', stale_seconds: 86400, source_type: 'response-connector' });
  const hv = { external_id: 'esxi-01', hostname: 'ESXI-01', os_family: 'linux', device_type: 'server', addresses: ['10.1.0.10'] }, target = { device_ref: 'esxi-01' };
  const ev = (id, kind, details) => ({ event_id: id, kind, observed_at: new Date(now).toISOString(), asset: hv, details }), put = (src, ...e) => d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: e });
  put(sensors, ev('seen', 'asset.observed', {}));
  put(responder, ev('cap', 'response.capability', { connector_id: 'MGMT-174', owner_system: 'cyberguard-connector', capabilities: ['endpoint.isolate-device', 'endpoint.shutdown-host'], target_asset_refs: ['esxi-01'], tested_at: new Date(now - 3600000).toISOString(), evidence_ref: 'MGMT-TEST-174', status: 'active' }),
    ...['endpoint.isolate-device', 'endpoint.shutdown-host'].map((type, i) => ev(`pf${i}`, 'response.management_preflight', { connector_id: 'MGMT-174', action_type: type, target_hash: digest(target), protected_role: 'none', management_channel_impact: 'none', alternate_management: { status: 'not-applicable', evidence_ref: null }, captured_at: new Date(now - 60000).toISOString(), evidence_ref: `PF-${i}` })));
  const assetId = s.get("SELECT a.id FROM assets a JOIN sources s ON s.id=a.source_id WHERE a.external_id='esxi-01' AND s.name='Sensors'").id;
  const preview = (type, plan_id) => d.previewAction('admin-a', { type, asset_id: assetId, target, connector_id: 'MGMT-174', authorization_ref: 'CHG-174', reason: 'Planned host maintenance', ttl_seconds: 600, ...(plan_id ? { plan_id } : {}) });
  // Before it is declared critical, a single isolation is accepted by this gate.
  assert.ok(preview('endpoint.isolate-device').id); now += 601000; s.run('UPDATE mfa_assertions SET verified_at=?,expires_at=?', new Date(now).toISOString(), new Date(now + 3600000).toISOString()); // that request expires unapproved, so it no longer counts as in flight (CG-175)
  cs.declare('admin-a', { asset_ref: 'esxi-01', role: 'hypervisor-host', evidence_ref: 'CMDB-ESXI-01' });
  assert.throws(() => preview('endpoint.isolate-device'), /critical_asset_requires_composite_plan:hypervisor-host/);
  assert.throws(() => cs.plan('admin-a', { asset_ref: 'esxi-01', steps: ['endpoint.shutdown-host'], change_ref: 'CHG-174', reason: 'x', oob: { method: 'ilo-idrac-ipmi', owner: 'dc-ops', evidence_ref: 'ILO-1' } }), /composite_plan_requires_2_to_10_steps/);
  assert.throws(() => cs.plan('admin-a', { asset_ref: 'esxi-01', steps: ['endpoint.isolate-device', 'endpoint.shutdown-host'], change_ref: 'CHG-174', reason: 'x' }), /composite_plan_requires_window_or_out_of_band_recovery/);
  const p = cs.plan('admin-a', { asset_ref: 'esxi-01', steps: ['endpoint.isolate-device', 'endpoint.shutdown-host'], change_ref: 'CHG-174', reason: 'Firmware upgrade: isolate, then power off', oob: { method: 'ilo-idrac-ipmi', owner: 'dc-ops', evidence_ref: 'ILO-ESXI-01' } });
  assert.throws(() => cs.approve('admin-a', p.id), /plan_needs_two_distinct_approvers/, 'the requester cannot approve');
  cs.approve('admin-b', p.id); assert.throws(() => cs.approve('admin-b', p.id), /plan_needs_two_distinct_approvers/);
  assert.throws(() => preview('endpoint.isolate-device', p.id), /composite_plan_not_approved/, 'one approval is not enough');
  assert.equal(cs.approve('admin-c', p.id).status, 'approved');
  assert.throws(() => preview('endpoint.shutdown-host', p.id), /composite_plan_next_step_is_endpoint.isolate-device/, 'steps run in order');
  assert.ok(preview('endpoint.isolate-device', p.id).id); assert.ok(preview('endpoint.shutdown-host', p.id).id);
  assert.equal(cs.get(p.id).status, 'completed'); assert.throws(() => preview('endpoint.isolate-device', p.id), /composite_plan_not_approved/, 'a used plan cannot be replayed');
  // A domain controller keeps the protected-role refusal unless an approved plan covers the step.
  const dc = { external_id: 'dc-174', hostname: 'DC-174', os_family: 'windows', device_type: 'domain-controller', addresses: ['10.1.0.20'] }, dcTarget = { device_ref: 'dc-174' };
  put(sensors, { ...ev('seen-dc', 'asset.observed', {}), asset: dc });
  put(responder, { ...ev('cap-dc', 'response.capability', { connector_id: 'MGMT-DC', owner_system: 'cyberguard-connector', capabilities: ['endpoint.isolate-device'], target_asset_refs: ['dc-174'], tested_at: new Date(now - 3600000).toISOString(), evidence_ref: 'MGMT-DC', status: 'active' }), asset: dc },
    { ...ev('pf-dc', 'response.management_preflight', { connector_id: 'MGMT-DC', action_type: 'endpoint.isolate-device', target_hash: digest(dcTarget), protected_role: 'domain-controller', management_channel_impact: 'none', alternate_management: { status: 'not-applicable', evidence_ref: null }, captured_at: new Date(now - 60000).toISOString(), evidence_ref: 'PF-DC' }), asset: dc });
  const dcId = s.get("SELECT a.id FROM assets a JOIN sources s ON s.id=a.source_id WHERE a.external_id='dc-174' AND s.name='Sensors'").id;
  const dcPreview = plan_id => d.previewAction('admin-a', { type: 'endpoint.isolate-device', asset_id: dcId, target: dcTarget, connector_id: 'MGMT-DC', authorization_ref: 'IR-174', reason: 'Contain', ttl_seconds: 600, ...(plan_id ? { plan_id } : {}) });
  assert.throws(() => dcPreview(), /protected_infrastructure_disruption_prohibited/);
  s.run("INSERT INTO change_windows(id,asset_ref,starts_at,ends_at,change_ref,created_by,created_at) VALUES ('w174','dc-174',?,?,'CHG-DC','admin-a',?)", new Date(now - 60000).toISOString(), new Date(now + 3600000).toISOString(), new Date(now).toISOString());
  const dp = cs.plan('admin-a', { asset_ref: 'dc-174', steps: ['endpoint.isolate-device', 'endpoint.shutdown-host'], change_ref: 'CHG-DC', reason: 'Demote and rebuild', window_id: 'w174' }); cs.approve('admin-b', dp.id); cs.approve('admin-c', dp.id);
  assert.ok(dcPreview(dp.id).id, 'with an approved plan inside its maintenance window the step is accepted');
  assert.equal(cs.view().assets.length, 2);
});
