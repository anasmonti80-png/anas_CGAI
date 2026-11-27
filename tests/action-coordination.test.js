import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { digest } from '../lib/common.js';
import { RuleLeases } from '../lib/rule-lease.js';
import { ActionCoordination } from '../lib/action-coordination.js';

test('a change runs once, opposing changes and active leases need an explicit supersede, provider request IDs are unique and shared resources state a restore method (CG-175)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.now(); const d = new Domain(s, { clock: () => now });
  for (const id of ['admin-a', 'admin-b']) { s.run('INSERT INTO users VALUES (?,?,?,?,?)', id, id, 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString()); s.run('INSERT INTO mfa_assertions VALUES (?,?,?,?,?,?,?)', `${id}-mfa`, id, `fixture-session-${id}`, 'totp', new Date(now).toISOString(), new Date(now + 3600000).toISOString(), digest({ id, now })); }
  const sensors = d.createSource('admin-a', { name: 'Sensors', stale_seconds: 86400 }), responder = d.createSource('admin-a', { name: 'Firewall connector', stale_seconds: 86400, source_type: 'response-connector' });
  const fw = { external_id: 'fw-175', hostname: 'FW-175', os_family: 'network', device_type: 'firewall', addresses: ['192.0.2.1'] };
  const ev = (id, kind, details) => ({ event_id: id, kind, observed_at: new Date(now).toISOString(), asset: fw, details }), put = (src, ...e) => d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: e });
  const ips = ['198.51.100.9', '198.51.100.50'], targets = [...ips.flatMap(ip => [['network.block-ip', { ip }], ['network.allow-ip', { ip }]]), ['endpoint.shutdown-host', { device_ref: 'fw-175' }]];
  put(sensors, ev('seen', 'asset.observed', {}));
  put(responder, ev('cap', 'response.capability', { connector_id: 'FW-175', owner_system: 'cyberguard-connector', capabilities: ['network.block-ip', 'network.allow-ip', 'endpoint.shutdown-host'], target_asset_refs: ['fw-175'], tested_at: new Date(now - 3600000).toISOString(), evidence_ref: 'FW-TEST', status: 'active' }),
    ...targets.map(([type, target], i) => ev(`pf${i}`, 'response.management_preflight', { connector_id: 'FW-175', action_type: type, target_hash: digest(target), protected_role: 'none', management_channel_impact: 'none', alternate_management: { status: 'not-applicable', evidence_ref: null }, captured_at: new Date(now - 60000).toISOString(), evidence_ref: `PF-${i}` })));
  const assetId = s.get("SELECT a.id FROM assets a JOIN sources s ON s.id=a.source_id WHERE a.external_id='fw-175' AND s.name='Sensors'").id;
  const preview = (type, target, extra = {}) => d.previewAction('admin-a', { type, asset_id: assetId, target, connector_id: 'FW-175', authorization_ref: 'IR-175', reason: 'Synthetic coordination test', ttl_seconds: 600, ...extra });

  // Idempotency: the same change twice is refused while the first is in flight; withdrawing it frees the change ID.
  const b1 = preview('network.block-ip', { ip: ips[0] });
  assert.throws(() => preview('network.block-ip', { ip: ips[0] }), new RegExp(`duplicate_action_in_flight:${b1.id}`));
  assert.equal(d.cancelAction('admin-b', b1.id, 'Duplicate of a colleague request').status, 'cancelled');
  const b2 = preview('network.block-ip', { ip: ips[0] });
  const row = s.get('SELECT change_id,restore_method FROM actions WHERE id=?', b2.id);
  assert.match(row.change_id, /^chg-[0-9a-f]{24}$/); assert.equal(row.restore_method, 'inverse:network.allow-ip');
  assert.equal(row.change_id, s.get('SELECT change_id FROM actions WHERE id=?', b1.id).change_id, 'the same change has the same ID');

  // Conflict: allowing the address another party is blocking needs an explicit supersede.
  assert.throws(() => preview('network.allow-ip', { ip: ips[0] }), new RegExp(`conflicting_action_in_flight:network.block-ip:${b2.id}`));
  const allow = preview('network.allow-ip', { ip: ips[0] }, { supersedes: b2.id });
  assert.equal(s.get('SELECT supersedes FROM actions WHERE id=?', allow.id).supersedes, b2.id);

  // Conflict with an active rule lease (CG-172) on the same address.
  const rl = new RuleLeases(s, { clock: () => now, domain: d });
  const lease = rl.approve('admin-b', rl.request('admin-a', { asset_ref: 'fw-175', source: '192.0.2.40', destination: ips[1], protocol: 'tcp', port: 443, ttl_minutes: 60, owner_ref: 'ops', ticket_ref: 'CHG-175', reason: 'Vendor access', connector_id: 'FW-175' }).id);
  assert.throws(() => preview('network.block-ip', { ip: ips[1] }), new RegExp(`conflicting_action_in_flight:rule-lease:${lease.id}`));

  // Shared resource: shutting down the firewall has no inverse, so the restore method must be stated.
  assert.throws(() => preview('endpoint.shutdown-host', { device_ref: 'fw-175' }), /shared_resource_requires_restore_method/);
  const down = preview('endpoint.shutdown-host', { device_ref: 'fw-175' }, { restore_method: 'Power on from iLO, restore config backup CFG-2026-11-27' });
  assert.match(s.get('SELECT restore_method FROM actions WHERE id=?', down.id).restore_method, /iLO/);

  // Provider request IDs: unique per action.
  d.approveAction('admin-b', b2.id); d.executeAction('admin-a', b2.id);
  d.completeResponseJob(responder.id, b2.id, { phase: 'execute', outcome: 'succeeded', observed_state: 'blocked', evidence_ref: 'FW-exec', rollback_supported: true, provider_request_id: 'fw-api-req-7781' });
  assert.equal(s.get('SELECT provider_request_id FROM response_jobs WHERE action_id=?', b2.id).provider_request_id, 'fw-api-req-7781');
  assert.throws(() => new ActionCoordination(s, { clock: () => now }).checkProviderRequest(allow.id, 'fw-api-req-7781'), /provider_request_id_reused/);
  const v = new ActionCoordination(s, { clock: () => now }).view();
  assert.ok(v.recent.some(a => a.provider_request_id === 'fw-api-req-7781')); assert.ok(v.active.length >= 3);
  assert.equal(s.get("SELECT COUNT(*) n FROM audit WHERE action='action.cancelled'").n, 1);
});
