import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { nceDevices, parseHuaweiVrp, vrpLldp } from '../lib/connectors/huawei.js';

const fx = name => fs.readFileSync(new URL(`./fixtures/huawei/${name}`, import.meta.url), 'utf8');

test('Huawei NCE-Campus devices, VRP configuration and LLDP neighbours convert without copying secrets', () => {
  const devices = nceDevices(fx('nce-devices.json'));
  assert.deepEqual(devices.map(d => d.asset.device_type), ['router', 'switch', 'access-point', 'firewall']);
  assert.deepEqual(devices.map(d => d.facts.status), ['normal', 'alarm', 'offline', 'unregistered']);
  assert.deepEqual(devices.map(d => d.health.reachability), ['reachable', 'reachable', 'unreachable', 'unknown']);
  assert.throws(() => nceDevices({ errcode: '1001', errmsg: 'token expired', data: [] }), /errcode 1001/);
  const c = parseHuaweiVrp(fx('vrp-display-version.txt'), fx('vrp-current-config.txt'));
  assert.equal(c.hostname, 'S5735-Access-01'); assert.equal(c.model, 'S5735-L24P4S-A'); assert.equal(c.firmware_version, 'V200R021C00SPC100');
  assert.deepEqual(c.dns_servers, ['192.0.2.53', '198.51.100.53']); assert.deepEqual(c.ntp_servers, ['192.0.2.123']); assert.deepEqual(c.vpn_profiles, [{ name: 'ike-peer-HQ', peer: '203.0.113.9', protocol: 'ipsec' }]);
  const m = Object.fromEntries(c.management.map(x => [x.protocol, x]));
  assert.equal(m.telnet.enabled, true); assert.equal(m.telnet.restricted_sources, false, 'vty 0 4 has no inbound ACL'); assert.equal(m.ssh.enabled, true); assert.equal(m.https.enabled, true); assert.equal(m.http.enabled, false); assert.equal(m.snmpv2c.enabled, true); assert.equal(m.snmpv3.enabled, true);
  assert.ok(!/cipher|SYNTHETIC|irreversible/i.test(JSON.stringify(c)), 'cipher passwords, keys and SNMP communities are never copied');
  const a = vrpLldp(fx('vrp-lldp-brief-v200.txt'), 'S5735-Access-01'), b = vrpLldp(fx('vrp-lldp-brief-v8.txt'), 'CE6850-Core');
  assert.deepEqual(a.links.map(l => [l.source_port, l.target, l.target_port]), [['GE0/0/1', 'vrp:ar651-branch-01', 'GE0/0/2'], ['GE0/0/24', 'vrp:airengine-ap-01', 'GE0/0/0']]);
  assert.deepEqual(b.links.map(l => [l.source_port, l.target, l.target_port]), [['10GE1/0/1', 'vrp:s5735-access-01', 'GE0/0/1']]);
  assert.throws(() => vrpLldp('nothing here', 'x'), /lldp neighbor brief/);
});

test('Huawei telemetry drives device health alerts, configuration checks and LLDP topology', t => {
  const s = new Store(':memory:'); t.after(() => s.close());
  const d = new Domain(s, { clock: () => Date.parse('2026-11-18T05:00:00.000Z') });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', '2026-11-18T05:00:00.000Z');
  const source = d.createSource('admin-a', { name: 'Huawei connector', stale_seconds: 3600 }), at = '2026-11-18T05:00:00.000Z';
  const collector = { external_id: 'huawei-connector', hostname: 'collector', os_family: 'linux', device_type: 'server', addresses: [] };
  const ingest = events => d.ingest('admin-a', source.id, { schema_version: 'cg.telemetry/1', events });
  const devices = nceDevices(fx('nce-devices.json'));
  ingest([...devices.map((x, i) => ({ event_id: `nce-${i}`, kind: 'asset.observed', observed_at: at, asset: x.asset, details: {} })), { event_id: 'nce-health', kind: 'network.device_health', observed_at: at, asset: collector, details: { snapshot_id: 'huawei-nce-device-status', source: 'huawei-imaster-nce', devices: devices.map(x => x.health) } }]);
  assert.deepEqual(s.all("SELECT title FROM alerts WHERE rule_id='CG-NET-HEALTH-041'").map(r => r.title.match(/: (\S+)/)[1]), ['AirEngine-AP-01']);
  const c = parseHuaweiVrp(fx('vrp-display-version.txt'), fx('vrp-current-config.txt')), ref = 'huawei-nce:5e1c0002-syn';
  ingest([{ event_id: 'vrp-cfg', kind: 'network.device_config', observed_at: at, asset: { external_id: ref, hostname: c.hostname, os_family: 'network', device_type: 'switch', addresses: [] }, details: { snapshot_id: `${ref}:1`, device_ref: ref, device_type: 'switch', vendor: 'huawei', model: c.model, firmware_version: c.firmware_version, dns_servers: c.dns_servers, ntp_servers: c.ntp_servers, vpn_profiles: c.vpn_profiles, management: c.management, config_sha256: null } }]);
  assert.ok(d.deviceConfigMonitoring().items.find(x => x.device_ref === ref).findings.some(f => f.type === 'insecure-management-protocol'), 'Telnet on VRP is flagged by the CG-021 checks');
  const topo = vrpLldp(fx('vrp-lldp-brief-v200.txt'), 'S5735-Access-01');
  ingest([{ event_id: 'vrp-lldp', kind: 'network.topology', observed_at: at, asset: collector, details: { topology_id: 'huawei-lldp:s5735-access-01', source: 'device-lldp', nodes: topo.nodes, links: topo.links } }]);
  const map = d.networkTopology().items.find(x => x.topology_id === 'huawei-lldp:s5735-access-01');
  assert.equal(map.counts.nodes, 3); assert.equal(map.counts.links, 2);
  assert.equal(map.nodes.find(n => n.label === 'AirEngine-AP-01').health.reachability, 'unreachable', 'LLDP neighbours pick up controller health by device name');
});
