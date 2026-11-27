import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { digest } from '../lib/common.js';
import { catalystInventory, catalystTopology, catalystHealth, fmcAccessRules, iosxeNative, iseAncRequest } from '../lib/connectors/cisco.js';
import { validateResponseTarget } from '../lib/response-actions.js';
import { grantDeclaredCapabilities } from './helpers/write-grant.js';

const fx = name => JSON.parse(fs.readFileSync(new URL(`./fixtures/cisco/${name}`, import.meta.url), 'utf8'));

test('Cisco Catalyst Center inventory, physical topology and device health convert from the Intent API responses', () => {
  const inv = catalystInventory(fx('catalyst-network-device.json'));
  assert.deepEqual(inv.map(d => d.asset.device_type), ['switch', 'switch', 'router', 'access-point']);
  assert.equal(inv[0].asset.external_id, 'cisco-catalyst:a1b2c3d4-0001-4000-8000-000000000001'); assert.deepEqual(inv[0].asset.addresses, ['192.0.2.11']); assert.equal(inv[2].facts.reachability, 'Unreachable');
  const topo = catalystTopology(fx('catalyst-physical-topology.json'));
  assert.equal(topo.nodes.length, 4); assert.equal(topo.links.length, 3); assert.equal(topo.dropped_links, 1, 'links to nodes absent from the response are dropped, not invented');
  assert.deepEqual(topo.links.map(l => l.status), ['up', 'down', 'up']);
  const health = catalystHealth(fx('catalyst-device-health.json'));
  assert.equal(health[1].cpu_percent, 96, 'documented cpuUlitilization spelling is read'); assert.equal(health[2].reachability, 'unreachable'); assert.equal(health[2].overall_health, 0);
  assert.throws(() => catalystInventory({}), /network-device/); assert.throws(() => catalystTopology({ response: {} }), /physical-topology/);
});

test('Secure Firewall FMC access rules and IOS XE RESTCONF configuration convert without guessing unresolved objects', () => {
  const fmc = fmcAccessRules(fx('fmc-accessrules.json'), { policyName: 'SYN-ACP' });
  assert.equal(fmc.rules.length, 5); assert.deepEqual(fmc.rules.map(r => r.action), ['allow', 'allow', 'allow', 'deny', 'deny']);
  assert.deepEqual(fmc.rules[0].src, ['0.0.0.0/0']); assert.deepEqual(fmc.rules[0].dst_ports, ['443']); assert.equal(fmc.rules[0].protocol, 'tcp'); assert.deepEqual(fmc.rules[0].scope_constraints, ['src-zone:OUTSIDE']);
  assert.deepEqual(fmc.rules[1].src, ['any']); assert.deepEqual(fmc.rules[1].dst_ports, ['3389']);
  assert.equal(fmc.rules[2].filters_readable, false, 'a named network group without values is not evaluated'); assert.equal(fmc.unreadable, 1); assert.equal(fmc.monitor_only, 1);
  const c = iosxeNative(fx('iosxe-native.json'));
  assert.equal(c.hostname, 'isr-edge-01'); assert.equal(c.firmware_version, '17.3'); assert.deepEqual(c.dns_servers, ['192.0.2.53', '198.51.100.53']); assert.deepEqual(c.ntp_servers, ['192.0.2.123']);
  assert.deepEqual(c.management.map(m => [m.protocol, m.restricted_sources]), [['telnet', false], ['ssh', false], ['http', false], ['https', false], ['snmpv2c', false]], 'vty 0-4 has no access-class, so no protocol counts as restricted');
  assert.ok(!JSON.stringify(c).includes('synthetic-ro'), 'SNMP community names are never copied out');
});

test('Cisco telemetry feeds topology, health alerts, the firewall analyzer and device configuration checks; ISE ANC isolation runs only as an approved governed job', t => {
  const s = new Store(':memory:'); t.after(() => s.close());
  let now = Date.parse('2026-11-17T09:00:00.000Z'); const d = new Domain(s, { clock: () => now });
  for (const id of ['admin-a', 'admin-b']) { s.run('INSERT INTO users VALUES (?,?,?,?,?)', id, id, 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString()); s.run('INSERT INTO mfa_assertions VALUES (?,?,?,?,?,?,?)', `${id}-mfa`, id, `fixture-session-${id}`, 'totp', new Date(now).toISOString(), new Date(now + 5 * 60000).toISOString(), digest({ id, now })); }
  const source = d.createSource('admin-a', { name: 'Cisco connector', stale_seconds: 3600 }), at = new Date(now).toISOString();
  const collector = { external_id: 'cisco-connector', hostname: 'collector', os_family: 'linux', device_type: 'server', addresses: [] };
  const ev = (id, kind, details, asset = collector) => ({ event_id: id, kind, observed_at: at, asset, details });
  const ingest = events => d.ingest('admin-a', source.id, { schema_version: 'cg.telemetry/1', events });
  // CG-045: ISE registration and jobs use a separate response-connector source.
  const responder = d.createSource('admin-a', { name: 'ISE response connector', stale_seconds: 3600, source_type: 'response-connector' }), respond = events => { const r = d.ingest('admin-a', responder.id, { schema_version: 'cg.telemetry/1', events }); grantDeclaredCapabilities(s, { clock: () => now }); return r; };
  ingest(catalystInventory(fx('catalyst-network-device.json')).map((x, i) => ev(`inv-${i}`, 'asset.observed', {}, x.asset)));
  const topo = catalystTopology(fx('catalyst-physical-topology.json'));
  ingest([ev('topo', 'network.topology', { topology_id: 'cisco-catalyst-physical', source: 'cisco-catalyst-center', nodes: topo.nodes, links: topo.links }), ev('health', 'network.device_health', { snapshot_id: 'cisco-catalyst-health', source: 'cisco-catalyst-center', devices: catalystHealth(fx('catalyst-device-health.json')) })]);
  const map = d.networkTopology();
  assert.equal(map.items[0].counts.nodes, 4); assert.equal(map.items[0].counts.down_links, 1); assert.equal(map.items[0].nodes.find(n => n.label === 'isr-edge-01').health.reachability, 'unreachable');
  assert.deepEqual(map.degraded.map(x => x.name).sort(), ['cat9k-access-01', 'isr-edge-01']);
  assert.deepEqual(s.all("SELECT severity FROM alerts WHERE rule_id='CG-NET-HEALTH-041' ORDER BY severity").map(r => r.severity), ['high', 'medium']);
  ingest([ev('fmc', 'firewall.ruleset', { ruleset_id: 'cisco-fmc:SYN-ACP', device_ref: 'cisco-fmc', vendor: 'cisco-fmc', evaluation: 'first-match', rules: fmcAccessRules(fx('fmc-accessrules.json')).rules })]);
  const fw = d.firewallRuleAnalysis().items.find(x => x.vendor === 'cisco-fmc');
  assert.ok(fw.findings.some(f => /3389|rdp|admin/i.test(JSON.stringify(f))), 'RDP open to any is reported by the CG-020 analyzer');
  const c = iosxeNative(fx('iosxe-native.json')), ref = 'cisco-catalyst:a1b2c3d4-0003-4000-8000-000000000003';
  ingest([ev('iosxe', 'network.device_config', { snapshot_id: `${ref}:1`, device_ref: ref, device_type: 'router', vendor: 'cisco', model: 'ISR4451-X/K9', firmware_version: c.firmware_version, dns_servers: c.dns_servers, ntp_servers: c.ntp_servers, vpn_profiles: [], management: c.management, config_sha256: null }, { external_id: ref, hostname: 'isr-edge-01', os_family: 'network', device_type: 'router', addresses: ['192.0.2.1'] })]);
  const cfg = d.deviceConfigMonitoring().items.find(x => x.device_ref === ref);
  assert.ok(cfg.findings.some(f => f.type === 'insecure-management-protocol'), 'Telnet over RESTCONF configuration is flagged by the CG-021 checks');
  // ISE ANC isolation through the normal governed path.
  const target = { mac: '00:00:5E:00:53:AA', policy_name: 'ANC_Quarantine' };
  // CG-101: the endpoint MAC must be learned on exactly one edge access port before ISE may quarantine it.
  ingest([ev('portmap-041', 'network.port_map', { switch_ref: 'acc-sw-041', authorization_ref: 'NET-041', arp: [], mac_table: [{ vlan: 10, mac: '00:00:5e:00:53:aa', type: 'dynamic', interface: 'Gi1/0/7' }], switchports: [{ interface: 'Gi1/0/7', mode: 'access', access_vlan: 10, voice_vlan: null }], lldp: [] }, { external_id: 'acc-sw-041', hostname: 'ACC-SW-041', os_family: 'network', device_type: 'switch', addresses: [] })]);
  assert.deepEqual(validateResponseTarget('network.nac-quarantine-endpoint', target), target);
  assert.throws(() => validateResponseTarget('network.nac-quarantine-endpoint', { ...target, mac: '00:00:5E:00:53' }), /invalid_response_mac/);
  assert.throws(() => validateResponseTarget('network.nac-quarantine-endpoint', { ...target, policy_name: 'x; rm -rf' }), /invalid_response_anc_policy/);
  respond([ev('ise-cap', 'response.capability', { connector_id: 'SYN-ISE-041', owner_system: 'cisco-ise', capabilities: ['network.nac-quarantine-endpoint', 'network.nac-release-endpoint'], target_asset_refs: [ref], tested_at: at, evidence_ref: 'SYN-ISE-TEST-041', status: 'active' }),
    ev('ise-mgmt', 'response.management_preflight', { connector_id: 'SYN-ISE-041', action_type: 'network.nac-quarantine-endpoint', target_hash: digest(target), protected_role: 'none', management_channel_impact: 'none', alternate_management: { status: 'not-applicable', evidence_ref: null }, captured_at: at, evidence_ref: 'SYN-ISE-MGMT-041' }, { external_id: ref, hostname: 'isr-edge-01', os_family: 'network', device_type: 'router', addresses: ['192.0.2.1'] })]);
  const asset = d.list('assets').items.find(a => a.external_id === ref);
  const action = d.previewAction('admin-a', { type: 'network.nac-quarantine-endpoint', asset_id: asset.id, target, connector_id: 'SYN-ISE-041', authorization_ref: 'IR-041', reason: 'Quarantine synthetic endpoint via ISE ANC', ttl_seconds: 600 });
  assert.equal(action.status, 'pending-approval'); assert.throws(() => d.approveAction('admin-a', action.id), /independent_approver_required/);
  d.approveAction('admin-b', action.id); d.executeAction('admin-a', action.id);
  let jobs = d.responseJobs(responder.id); assert.equal(jobs.items[0].request.action_type, 'network.nac-quarantine-endpoint');
  assert.deepEqual(iseAncRequest('execute', jobs.items[0].request.target), { method: 'PUT', path: '/ers/config/ancendpoint/apply', body: { OperationAdditionalData: { additionalData: [{ name: 'macAddress', value: '00:00:5E:00:53:AA' }, { name: 'policyName', value: 'ANC_Quarantine' }] } } });
  assert.equal(d.completeResponseJob(responder.id, action.id, { phase: 'execute', outcome: 'succeeded', observed_state: 'ISE ANC applied', evidence_ref: 'ise-ers:synthetic', rollback_supported: true }).status, 'verified');
  d.rollbackAction('admin-b', action.id); jobs = d.responseJobs(responder.id);
  assert.equal(jobs.items[0].request.action_type, 'network.nac-release-endpoint'); assert.equal(iseAncRequest('rollback', jobs.items[0].request.target).path, '/ers/config/ancendpoint/clear');
  assert.equal(d.completeResponseJob(responder.id, action.id, { phase: 'rollback', outcome: 'succeeded', observed_state: 'ISE ANC cleared', evidence_ref: 'ise-ers:synthetic', rollback_supported: true }).status, 'rolled-back');
});
