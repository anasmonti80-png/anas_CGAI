import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { digest } from '../lib/common.js';
import { SafetyGate, tierOf, REQUIREMENTS } from '../lib/safety-tiers.js';
import { grantDeclaredCapabilities } from './helpers/write-grant.js';

function fixture(t) {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.parse('2026-11-22T10:00:00.000Z'); const d = new Domain(s, { clock: () => now }), gate = new SafetyGate(s, { clock: () => now }); d.safetyGate = gate;
  for (const id of ['admin-a', 'admin-b', 'admin-c']) { s.run('INSERT INTO users VALUES (?,?,?,?,?)', id, id, 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString()); s.run('INSERT INTO mfa_assertions VALUES (?,?,?,?,?,?,?)', `${id}-mfa`, id, `fixture-session-${id}`, 'totp', new Date(now).toISOString(), new Date(now + 3600000).toISOString(), digest({ id })); }
  const sensors = d.createSource('admin-a', { name: 'Sensors', stale_seconds: 86400 }), responder = d.createSource('admin-a', { name: 'EDR', stale_seconds: 86400, source_type: 'response-connector' });
  const host = { external_id: 'srv-app-01', hostname: 'SRV-APP-01', os_family: 'windows', device_type: 'server', addresses: ['10.0.3.10'] }, iso = (o = 0) => new Date(now + o).toISOString();
  const ev = (id, kind, details) => ({ event_id: id, kind, observed_at: iso(), asset: host, details }), put = (src, ...e) => { const r = d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: e }); grantDeclaredCapabilities(s, { clock: () => now }); return r; };
  put(sensors, ev('a', 'asset.observed', {}));
  put(responder, ev('cap', 'response.capability', { connector_id: 'EDR-119', owner_system: 'cyberguard-connector', capabilities: ['endpoint.shutdown-host', 'network.block-ip'], target_asset_refs: ['srv-app-01'], tested_at: iso(-3600000), evidence_ref: 'EDR-119', status: 'active' }),
    ...[['endpoint.shutdown-host', { device_ref: 'srv-app-01' }], ['network.block-ip', { ip: '198.51.100.9' }]].map(([type, target], i) => ev(`m${i}`, 'response.management_preflight', { connector_id: 'EDR-119', action_type: type, target_hash: digest(target), protected_role: 'none', management_channel_impact: 'none', alternate_management: { status: 'not-applicable', evidence_ref: null }, captured_at: iso(-60000), evidence_ref: `M-${i}` })));
  const assetId = s.get("SELECT a.id FROM assets a JOIN sources s ON s.id=a.source_id WHERE s.name='Sensors'").id;
  const preview = (type, target) => d.previewAction('admin-a', { type, asset_id: assetId, target, connector_id: 'EDR-119', authorization_ref: 'CHG-119', reason: 'Synthetic tier test', ttl_seconds: 3600 });
  const refresh = () => put(responder, ev(`m-fresh-${now}`, 'response.management_preflight', { connector_id: 'EDR-119', action_type: 'endpoint.shutdown-host', target_hash: digest({ device_ref: 'srv-app-01' }), protected_role: 'none', management_channel_impact: 'none', alternate_management: { status: 'not-applicable', evidence_ref: null }, captured_at: iso(), evidence_ref: 'M-fresh' }));
  return { s, d, gate, preview, iso, refresh, advance: ms => { now += ms; s.run('UPDATE mfa_assertions SET verified_at=?,expires_at=?', iso(), iso(3600000)); } };
}

test('every action type has one tier with graduated approvals, confirmation and change-window rules (CG-119)', () => {
  assert.equal(tierOf('network.block-ip'), 'low-impact'); assert.equal(tierOf('endpoint.isolate-device'), 'sensitive'); assert.equal(tierOf('endpoint.shutdown-host'), 'destructive'); assert.equal(tierOf('endpoint.remove-service'), 'destructive');
  assert.deepEqual(Object.values(REQUIREMENTS).map(r => r.approvers), [0, 1, 1, 2]);
  assert.deepEqual([REQUIREMENTS.sensitive.emergency_override, REQUIREMENTS.destructive.emergency_override], [true, false]);
});

test('low-impact runs after one approval; destructive shutdown needs a safety approver, typed confirmation and a change window (CG-119)', t => {
  const { s, d, gate, preview, iso, refresh, advance } = fixture(t);
  const low = preview('network.block-ip', { ip: '198.51.100.9' }); d.approveAction('admin-b', low.id); assert.equal(d.executeAction('admin-a', low.id).status, 'dispatched', 'low impact: no confirmation or window');
  const down = preview('endpoint.shutdown-host', { device_ref: 'srv-app-01' }); d.approveAction('admin-b', down.id);
  assert.throws(() => d.executeAction('admin-a', down.id), /safety_tier_destructive_requires_safety_approval/);
  assert.throws(() => d.safetyApproveAction('admin-b', down.id), /separate_safety_approver_required/); d.safetyApproveAction('admin-c', down.id);
  assert.throws(() => d.executeAction('admin-a', down.id), /safety_tier_destructive_requires_typed_confirmation/);
  assert.throws(() => gate.confirm('admin-a', down.id, { typed_target: 'SRV-APP-02' }), /typed_target_does_not_match/);
  gate.confirm('admin-a', down.id, { typed_target: 'srv-app-01' }); assert.throws(() => d.executeAction('admin-a', down.id), /safety_tier_destructive_requires_change_window/);
  assert.throws(() => gate.addWindow('admin-a', { asset_ref: 'srv-app-01', starts_at: iso(), ends_at: iso(3 * 86400000), change_ref: 'CHG-1' }), /change_window_must_be/);
  gate.addWindow('admin-a', { asset_ref: 'srv-app-01', starts_at: iso(1200000), ends_at: iso(4800000), change_ref: 'CHG-119' });
  assert.throws(() => d.executeAction('admin-a', down.id), /requires_change_window/, 'a future window does not count yet');
  // Inside the window: fresh management check, new preview, both approvals, confirmation by the executor.
  advance(1200000 + 1000); refresh(); d.cancelAction('admin-a', down.id, 'Replaced by a request inside the change window'); const run = preview('endpoint.shutdown-host', { device_ref: 'srv-app-01' }); d.approveAction('admin-b', run.id); d.safetyApproveAction('admin-c', run.id);
  gate.confirm('admin-a', run.id, { typed_target: 'SRV-APP-01' }); advance(11 * 60000); assert.throws(() => d.executeAction('admin-a', run.id), /requires_confirmation_expired/, 'the confirmation is valid for 10 minutes');
  gate.confirm('admin-a', run.id, { typed_target: 'SRV-APP-01' }); assert.throws(() => d.executeAction('admin-b', run.id), /the_confirming_user_must_execute/);
  assert.equal(d.executeAction('admin-a', run.id).status, 'dispatched'); const down2 = run;
  assert.deepEqual(s.all("SELECT action FROM audit WHERE target=? AND action IN ('action.approved','action.safety_approved','action.confirmed','action.safety_tier_checked','action.dispatched') ORDER BY seq", down2.id).map(x => x.action), ['action.approved', 'action.safety_approved', 'action.confirmed', 'action.confirmed', 'action.safety_tier_checked', 'action.dispatched']);
  const v = gate.view(); assert.deepEqual(v.tiers.find(x => x.tier === 'destructive').action_types, ['endpoint.shutdown-host', 'endpoint.remove-service', 'endpoint.change-service-permanent']); assert.equal(v.windows.length, 1); assert.ok(v.claim_ar.includes('نافذة تغيير'));
});
