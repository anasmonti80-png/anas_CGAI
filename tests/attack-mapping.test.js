import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MAPPINGS, TECHNIQUES, TACTICS, D3FEND, mappingFor, navigatorLayer } from '../lib/attack-mapping.js';
import { tacticOf } from '../lib/incident-graph.js';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
function fixture(t) {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.parse('2026-11-20T10:00:00.000Z'); const d = new Domain(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString());
  const src = d.createSource('admin-a', { name: 'Synthetic lab', stale_seconds: 86400 });
  const event = (id, kind, details, asset = {}) => ({ event_id: id, kind, observed_at: new Date(now).toISOString(), asset: { external_id: 'synthetic-01', hostname: 'LAB-01', os_family: 'windows', device_type: 'workstation', addresses: ['192.0.2.10'], ...asset }, details });
  const ingest = events => d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events });
  const rules = like => s.all('SELECT rule_id,severity,status FROM alerts WHERE rule_id LIKE ? ORDER BY rule_id', like);
  return { s, d, event, ingest, rules, advance: ms => { now += ms; } };
}

test('every rule raised in lib/ is mapped to ATT&CK, a sensor, D3FEND and an existing success test (CG-110)', () => {
  const raised = new Set();
  for (const f of fs.readdirSync(path.join(ROOT, 'lib')).filter(f => f.endsWith('.js') && f !== 'attack-mapping.js')) {
    const src = fs.readFileSync(path.join(ROOT, 'lib', f), 'utf8');
    for (const m of src.matchAll(/(?:rule|id)\s*:\s*'(CG-[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)'/g)) raised.add(m[1]);
    for (const m of src.matchAll(/'(CG-[A-Z]+(?:-[A-Z]+)*-\d{3})'/g)) raised.add(m[1]);
    for (const m of src.matchAll(/rule:\s*`(CG-[A-Z]+-)\$\{/g)) raised.add(`${m[1]}X`);
  }
  assert.ok(raised.size >= 75, `found ${raised.size} rules`);
  const unmapped = [...raised].filter(r => !mappingFor(r)); assert.deepEqual(unmapped, [], 'every raised rule has a mapping');
  const tests = new Map();
  for (const m of MAPPINGS) {
    assert.ok(m.use_case && m.use_case_ar && m.sensor && m.indicator && m.analytic && m.response && m.test, `${m.rule} has every field`);
    for (const t of m.techniques) { assert.match(t, /^T\d{4}(\.\d{3})?$/); assert.ok(TECHNIQUES[t], `${m.rule}: technique ${t} named`); }
    for (const t of m.tactics) assert.ok(TACTICS[t], `${m.rule}: tactic ${t}`);
    for (const d of [...m.d3fend_detect, ...m.d3fend_respond]) { assert.match(d, /^D3-[A-Z]+$/); assert.ok(D3FEND[d], `${m.rule}: D3FEND ${d} named`); }
    if (m.category === 'detection' && m.rule !== 'CG-HYP-*' && m.rule !== 'CG-REPORTED-FINDING') { assert.ok(m.techniques.length, `${m.rule} detection names a technique`); assert.ok(m.d3fend_detect.length, `${m.rule} names a D3FEND detect technique`); }
    const [file, name] = [m.test.slice(0, m.test.indexOf(': ')), m.test.slice(m.test.indexOf(': ') + 2)];
    if (!tests.has(file)) tests.set(file, fs.readFileSync(path.join(ROOT, file), 'utf8'));
    assert.ok(tests.get(file).includes(`test('${name}'`), `${m.rule}: success test exists: ${m.test}`);
  }
  assert.equal(new Set(MAPPINGS.map(m => m.rule)).size, MAPPINGS.length, 'one mapping per rule');
  for (const m of MAPPINGS.filter(m => !m.rule.endsWith('*'))) { const t = tacticOf(m.rule); if (t.id) assert.ok(m.tactics.includes(t.id), `${m.rule}: incident graph tactic ${t.id} is in the mapping`); }
});

test('CG-NET-DNS-017 is raised by random-looking DNS queries in resolver logs (CG-110)', t => {
  const { ingest, event, rules } = fixture(t);
  const q = (name, type = 'A') => `20-Nov-2026 09:59:00.000 client @0x1 10.0.0.7#53000 (${name}): query: ${name} IN ${type} + (10.0.0.53)`;
  ingest([event('dns', 'log.batch', { batch_id: 'DNS-110', source_name: 'bind', format: 'bind-query', lines: [q('www.example.org'), q('k3v8q1z7w2m9p4r6t0y5xbn.cdn.example.net'), q('x9q7z2kd8w4m1p0r6t3y5vbn.tunnel.example.net', 'TXT'), ...Array.from({ length: 30 }, (_, i) => q(`h${i}.exfil.example.com`))] })]);
  const r = rules('CG-NET-DNS%'); assert.equal(r.length, 2, 'random label with TXT and 30 unique subdomains alert; a normal name or one weak reason alone does not'); assert.ok(r.every(x => x.rule_id === 'CG-NET-DNS-017'));
});

test('CG-NETDEV-VPN-024 is raised when a device VPN peer changes between snapshots (CG-110)', t => {
  const { ingest, event, rules, advance } = fixture(t), snap = (id, vpn) => ({ snapshot_id: id, device_ref: 'cisco:edge-rtr-01', device_type: 'router', vendor: 'cisco', model: 'ISR4331/K9', firmware_version: '17.3.4a', dns_servers: ['10.0.0.53'], ntp_servers: [], vpn_profiles: vpn, management: [{ protocol: 'ssh', enabled: true, exposed_to: 'internal', restricted_sources: true }], config_sha256: id === 'S1' ? 'a'.repeat(64) : 'b'.repeat(64) });
  ingest([event('cfg-1', 'network.device_config', snap('S1', [{ name: 'branch', peer: '198.51.100.1', protocol: 'ipsec' }]))]);
  advance(60000); ingest([event('cfg-2', 'network.device_config', snap('S2', [{ name: 'branch', peer: '203.0.113.200', protocol: 'ipsec' }]))]);
  assert.deepEqual(rules('CG-NETDEV-%').map(x => x.rule_id), ['CG-NETDEV-VPN-024']);
});

test('CG-ASSET-CHANGED and CG-ASSET-RESTORED are raised by discovery changes and recovery (CG-110)', t => {
  const { ingest, event, rules, advance } = fixture(t), base = { authorization_ref: 'AUTH-LAB-110', acquisition: 'passive-import', availability: 'up', networks: ['192.0.2.0/24'], routes: [], vlans: [{ id: 10, name: 'Lab' }], interfaces: [], services: [] }, sw = { device_type: 'switch', os_family: 'network' };
  ingest([event('d1', 'discovery.observed', base, sw)]); advance(1000);
  ingest([event('d2', 'discovery.observed', { ...base, vlans: [{ id: 10, name: 'Lab' }, { id: 20, name: 'Guest' }] }, sw)]); advance(1000);
  ingest([event('d3', 'discovery.observed', { ...base, availability: 'down' }, sw)]); advance(1000);
  ingest([event('d4', 'discovery.observed', { ...base, availability: 'up' }, sw)]);
  const ids = rules('CG-ASSET-%').map(x => x.rule_id); for (const r of ['CG-ASSET-ADDED', 'CG-ASSET-CHANGED', 'CG-ASSET-UNREACHABLE', 'CG-ASSET-RESTORED']) assert.ok(ids.includes(r), r);
});

test('CG-FILE-SUSPICIOUS-092 is raised for a file judged suspicious by YARA (CG-110)', t => {
  const { ingest, event, rules } = fixture(t);
  ingest([event('ft', 'file.triage', { name: 'report.docm', directory_ref: 'a'.repeat(16), size: 2048, type: 'ole-document', sha256: 'b'.repeat(64), sha1: 'c'.repeat(40), md5: 'd'.repeat(32), signature: { status: 'not-applicable', signer: null, issuer: null, reason: null }, yara: [{ rule: 'office_macro_autoopen', tags: ['macro'], severity: 'medium', engine: 'built-in' }], reputation: 'unknown', verdict: 'suspicious', rules_engine: 'built-in', quarantine: { state: 'not-quarantined', custody_id: null, record_hash: null, location: null } })]);
  assert.deepEqual(rules('CG-FILE-%').map(x => [x.rule_id, x.severity]), [['CG-FILE-SUSPICIOUS-092', 'medium']]);
});

test('CG-REMOTE-EXPOSURE is raised for an open remote access port without a proven session (CG-110)', t => {
  const { ingest, event, rules } = fixture(t);
  ingest([event('port', 'remote.port_open', { session_id: 'p1', protocol: 'rdp', source_a: { ip: '192.0.2.20', account: null }, target_b: { ip: '192.0.2.10', account: null }, evidence_type: 'port_observation' })]);
  assert.deepEqual(rules('CG-REMOTE-%').map(x => [x.rule_id, x.severity]), [['CG-REMOTE-EXPOSURE', 'medium']]);
});

test('CG-VISIBILITY-GAP is raised for an open gap and resolved when the gap closes (CG-110)', t => {
  const { ingest, event, rules, advance } = fixture(t), gap = (id, status) => event(id, 'visibility.gap', { entity_type: 'system', entity_ref: 'LAB-02', reason: 'no-agent', last_seen: '2026-11-20T09:00:00.000Z', recommendation: 'Install the agent', status });
  ingest([gap('g1', 'open')]); assert.deepEqual(rules('CG-VISIBILITY-GAP').map(x => [x.severity, x.status]), [['medium', 'open']]);
  advance(1000); ingest([gap('g2', 'resolved')]); assert.equal(rules('CG-VISIBILITY-GAP')[0].status, 'resolved');
});

test('the mapping shows live sensor and alert status and exports an ATT&CK Navigator layer (CG-110)', t => {
  const { d, ingest, event } = fixture(t);
  ingest([event('port', 'remote.port_open', { session_id: 'p1', protocol: 'rdp', source_a: { ip: '192.0.2.20', account: null }, target_b: { ip: '192.0.2.10', account: null }, evidence_type: 'port_observation' })]);
  const v = d.attackMapping(), row = r => v.rows.find(x => x.rule === r);
  assert.equal(v.summary.rules, MAPPINGS.length); assert.ok(v.summary.techniques >= 60); assert.ok(v.summary.d3fend_techniques >= 40);
  assert.equal(row('CG-REMOTE-EXPOSURE').status, 'sensor-active'); assert.equal(row('CG-REMOTE-EXPOSURE').alerts_total, 1); assert.equal(row('CG-NET-DNS-017').status, 'no-sensor-data');
  assert.ok(v.by_tactic.find(x => x.id === 'TA0001').techniques > 5);
  const layer = d.attackNavigatorLayer(); assert.equal(layer.domain, 'enterprise-attack'); assert.equal(layer.versions.layer, '4.5');
  const t1133 = layer.techniques.find(x => x.techniqueID === 'T1133'); assert.equal(t1133.score, 1); assert.match(t1133.comment, /CG-REMOTE-EXPOSURE/);
  assert.ok(!layer.techniques.some(x => /^T0\d{3}$/.test(x.techniqueID) || x.techniqueID === 'T1404'), 'ICS and mobile techniques stay out of the enterprise layer');
  assert.deepEqual(navigatorLayer([]).techniques, []); assert.ok(v.claim_ar.includes('D3FEND'));
});
