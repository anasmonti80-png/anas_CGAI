import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { digest } from '../lib/common.js';
import { qualify, COVERAGE } from '../lib/simulation-coverage.js';
import { grantDeclaredCapabilities } from './helpers/write-grant.js';

const rule = (id, extra = {}) => ({ rule_id: id, name: id, position: 1, enabled: true, direction: 'in', action: 'allow', protocol: 'tcp', src: ['any'], dst: ['192.0.2.10/32'], src_ports: ['any'], dst_ports: ['443'], application: null, profile: 'any', last_hit_at: null, hit_count: null, expires_at: null, owner: null, created_at: null, filters_readable: true, scope_constraints: [], ...extra });

test('every simulation states its coverage and qualification, and an unqualified or stale result is never applied to a sensitive production firewall (CG-176)', t => {
  assert.deepEqual(qualify({ vendor: 'palo-alto', rules: [rule('web')] }, null), { qualified: true, reasons: [] });
  assert.deepEqual(qualify({ vendor: 'other', rules: [rule('web', { application: 'ssl', filters_readable: false, protocol: 'gre' })] }, null).reasons, ['vendor-not-modelled:other', 'unresolved-named-objects:1', 'protocol-not-modelled:gre', 'application-rules-as-labels-only']);
  assert.ok(COVERAGE.not_modelled.includes('nat') && COVERAGE.not_modelled.includes('routing-and-path'));
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.now(); const d = new Domain(s, { clock: () => now });
  for (const id of ['admin-a', 'admin-b']) { s.run('INSERT INTO users VALUES (?,?,?,?,?)', id, id, 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString()); s.run('INSERT INTO mfa_assertions VALUES (?,?,?,?,?,?,?)', `${id}-mfa`, id, `fixture-session-${id}`, 'totp', new Date(now).toISOString(), new Date(now + 48 * 3600000).toISOString(), digest({ id, now })); }
  const sensors = d.createSource('admin-a', { name: 'Sensors', stale_seconds: 86400 }), responder = d.createSource('admin-a', { name: 'FW connector', stale_seconds: 86400, source_type: 'response-connector' });
  const fw = { external_id: 'fw-176', hostname: 'FW-176', os_family: 'network', device_type: 'firewall', addresses: ['192.0.2.1'] }, target = { ip: '198.51.100.76' };
  const ev = (id, kind, details) => ({ event_id: id, kind, observed_at: new Date(now).toISOString(), asset: fw, details }), put = (src, ...e) => { const r = d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: e }); grantDeclaredCapabilities(s, { clock: () => now }); return r; };
  const ruleset = (id, rules) => ev(id, 'firewall.ruleset', { ruleset_id: id, device_ref: 'fw-176', vendor: 'palo-alto', evaluation: 'first-match', rules });
  for (const [ref, role] of [['core-1', 'core'], ['mgmt-1', 'management']]) s.run('INSERT INTO impact_roles(id,asset_ref,role,consumers_json,note,declared_by,declared_at) VALUES (?,?,?,?,?,?,?)', ref, ref, role, '["*"]', 'test', 'admin-a', new Date(now).toISOString());
  put(sensors, ev('seen', 'asset.observed', {}), ev('ctx', 'asset.context', { owner: { owner_id: 'net', display_name: 'Network', contact: null }, business_service: 'Internet edge', service_name: null, site: 'HQ', data_sensitivity: 'internal', maintenance_windows: [], service_criticality: 'critical' }), ruleset('rs-1', [rule('web')]));
  const preflight = () => put(responder, ev(`cap-${now}`, 'response.capability', { connector_id: 'FW-176', owner_system: 'cyberguard-connector', capabilities: ['network.block-ip'], target_asset_refs: ['fw-176'], tested_at: new Date(now - 3600000).toISOString(), evidence_ref: 'FW-TEST', status: 'active' }),
    ev(`pf-${now}`, 'response.management_preflight', { connector_id: 'FW-176', action_type: 'network.block-ip', target_hash: digest(target), protected_role: 'none', management_channel_impact: 'none', alternate_management: { status: 'not-applicable', evidence_ref: null }, captured_at: new Date(now - 60000).toISOString(), evidence_ref: 'PF-176' }));
  preflight();
  const assetId = s.get("SELECT a.id FROM assets a JOIN sources s ON s.id=a.source_id WHERE a.external_id='fw-176' AND s.name='Sensors'").id;
  const preview = simulation_id => d.previewAction('admin-a', { type: 'network.block-ip', asset_id: assetId, target, connector_id: 'FW-176', authorization_ref: 'IR-176', reason: 'Block a scanner', ttl_seconds: 600, ...(simulation_id ? { simulation_id } : {}) });
  const change = { op: 'add', rule: { rule_id: 'block-76', position: 0, direction: 'in', action: 'deny', protocol: 'any', src: ['198.51.100.76/32'], dst: ['any'], dst_ports: ['any'] } };
  const good = d.firewallChangeImpact({ device_ref: 'fw-176', change }, 'admin-a');
  assert.deepEqual([good.qualified, good.reasons, good.coverage.scope], [true, [], 'single-device-l3-l4-filters']); assert.match(good.simulation_id, /^[0-9a-f-]{36}$/);
  assert.throws(() => preview(), /qualified_simulation_required_for_sensitive_production/);
  // A ruleset with an application rule makes the simulation unqualified: it is not applied.
  now += 1000; put(sensors, ruleset('rs-2', [rule('web'), rule('app', { position: 2, application: 'ssl' })]));
  const weak = d.firewallChangeImpact({ device_ref: 'fw-176', change }, 'admin-a'); assert.equal(weak.qualified, false);
  assert.throws(() => preview(weak.simulation_id), /simulation_not_qualified:application-rules-as-labels-only/);
  // A qualified simulation older than 24 hours no longer counts.
  now += 25 * 3600000; s.run('UPDATE mfa_assertions SET verified_at=?', new Date(now).toISOString()); preflight(); assert.throws(() => preview(good.simulation_id), /simulation_older_than_24_hours/);
  put(sensors, ruleset('rs-3', [rule('web')])); const fresh = d.firewallChangeImpact({ device_ref: 'fw-176', change }, 'admin-a');
  assert.ok(preview(fresh.simulation_id).id, 'a fresh qualified simulation of this device lets the action proceed');
  assert.equal(s.get('SELECT COUNT(*) n FROM simulations').n, 3);
});
