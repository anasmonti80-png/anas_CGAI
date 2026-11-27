import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { digest } from '../lib/common.js';
import { ControlOutcomes } from '../lib/control-outcome.js';
import { grantDeclaredCapabilities } from './helpers/write-grant.js';

function fixture(t) {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.parse('2026-11-22T10:00:00.000Z'); const d = new Domain(s, { clock: () => now });
  for (const id of ['admin-a', 'admin-b']) { s.run('INSERT INTO users VALUES (?,?,?,?,?)', id, id, 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString()); s.run('INSERT INTO mfa_assertions VALUES (?,?,?,?,?,?,?)', `${id}-mfa`, id, `fixture-session-${id}`, 'totp', new Date(now).toISOString(), new Date(now + 5 * 60000).toISOString(), digest({ id, now })); }
  const sensors = d.createSource('admin-a', { name: 'Network sensors', stale_seconds: 86400 }), responder = d.createSource('admin-a', { name: 'EDR connector', stale_seconds: 86400, source_type: 'response-connector' });
  const host = { external_id: 'lab-ws-01', hostname: 'LAB-WS-01', os_family: 'windows', device_type: 'workstation', addresses: ['10.0.0.20'] };
  const ev = (id, kind, details, asset = host) => ({ event_id: id, kind, observed_at: new Date(now).toISOString(), asset, details }), put = (src, ...e) => { const r = d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: e }); grantDeclaredCapabilities(s, { clock: () => now }); return r; };
  const advance = ms => { now += ms; s.run('UPDATE mfa_assertions SET verified_at=?,expires_at=?', new Date(now).toISOString(), new Date(now + 5 * 60000).toISOString()); };
  put(sensors, ev('seen', 'asset.observed', {}));
  put(responder, ev('cap', 'response.capability', { connector_id: 'EDR-118', owner_system: 'cyberguard-connector', capabilities: ['endpoint.isolate-device', 'network.block-ip'], target_asset_refs: ['lab-ws-01'], tested_at: new Date(now - 3600000).toISOString(), evidence_ref: 'EDR-TEST-118', status: 'active' }),
    ...[['endpoint.isolate-device', { device_ref: 'lab-ws-01' }], ['network.block-ip', { ip: '198.51.100.66' }]].map(([type, target], i) => ev(`mgmt${i}`, 'response.management_preflight', { connector_id: 'EDR-118', action_type: type, target_hash: digest(target), protected_role: 'none', management_channel_impact: 'none', alternate_management: { status: 'not-applicable', evidence_ref: null }, captured_at: new Date(now - 60000).toISOString(), evidence_ref: `MGMT-${i}` })));
  const assetId = s.get("SELECT a.id FROM assets a JOIN sources s ON s.id=a.source_id WHERE a.external_id='lab-ws-01' AND s.name='Network sensors'").id;
  const run = (type, target) => { const a = d.previewAction('admin-a', { type, asset_id: assetId, target, connector_id: 'EDR-118', authorization_ref: 'IR-118', reason: 'Contain synthetic lab host', ttl_seconds: 600 }); d.approveAction('admin-b', a.id); d.executeAction('admin-a', a.id); return a.id; };
  const done = (id, phase, outcome, observed_state) => d.completeResponseJob(responder.id, id, { phase, outcome, observed_state, evidence_ref: `EDR-${phase}-${outcome}`, rollback_supported: true });
  const check = (id, action_id, expected_state, observed_state, src = sensors) => put(src, ev(id, 'response.outcome_check', { action_id, check_type: 'connectivity-probe', expected_state, observed_state, checked_at: new Date(now).toISOString(), method: 'probe from monitoring host', evidence_ref: `PROBE-${id}` }));
  return { s, d, sensors, responder, run, done, check, advance, put, ev, co: new ControlOutcomes(s, { domain: d, clock: () => now }) };
}

test('controls are verified independently of the connector and contradictions or leaking traffic mark them ineffective (CG-118)', t => {
  const { s, co, run, done, check, advance, responder, put, ev, sensors } = fixture(t);
  const iso = run('endpoint.isolate-device', { device_ref: 'lab-ws-01' }); advance(30000); done(iso, 'execute', 'succeeded', 'EDR reports network containment');
  assert.equal(co.outcome(iso).state, 'connector-reported-only', 'a connector report alone is not proof');
  assert.throws(() => check('self', iso, 'isolated', 'isolated', responder), /response_connector_cannot_ingest_telemetry/, 'the executing connector cannot vouch for itself');
  advance(30000);
  advance(30000); check('probe1', iso, 'isolated', 'isolated'); let o = co.outcome(iso); assert.equal(o.state, 'verified-effective'); assert.equal(o.in_force, true); assert.equal(o.duration_seconds, 60); assert.equal(o.checks.filter(c => c.independent).length, 1);
  const blk = run('network.block-ip', { ip: '198.51.100.66' }); advance(10000); done(blk, 'execute', 'succeeded', 'Firewall rule pushed');
  advance(60000); check('probe2', blk, 'blocked', 'reachable');
  o = co.outcome(blk); assert.equal(o.state, 'ineffective'); assert.equal(s.all("SELECT severity FROM alerts WHERE rule_id='CG-CONTROL-INEFFECTIVE-118'").length, 1);
  // Isolation contradicted by traffic the host still sends after enforcement.
  const line = JSON.stringify({ TimeFlowStart: Math.floor(Date.parse('2026-11-22T10:04:00.000Z') / 1000), SrcAddr: '10.0.0.20', DstAddr: '203.0.113.80', SrcPort: 50000, DstPort: 443, Proto: 6, Bytes: 900, Packets: 3 });
  advance(120000); put(sensors, ev('leak', 'log.batch', { batch_id: 'L1', source_name: 'flows', format: 'goflow-json', lines: [line] }));
  o = co.outcome(iso); assert.equal(o.state, 'ineffective'); assert.equal(o.traffic_after_enforcement[0].dst_ip, '203.0.113.80');
  const view = co.list(); assert.equal(view.summary.ineffective, 2); assert.equal(s.all("SELECT 1 FROM alerts WHERE rule_id='CG-CONTROL-INEFFECTIVE-118'").length, 2); assert.ok(view.claim_ar.includes('دون تجميل'));
});

test('execution errors and failed rollbacks are shown as such with the duration the control stayed in force (CG-118)', t => {
  const { s, d, co, run, done, check, advance } = fixture(t);
  const bad = run('network.block-ip', { ip: '198.51.100.66' }); advance(5000); done(bad, 'execute', 'failed', 'Firewall API returned 403 Forbidden');
  let o = co.outcome(bad); assert.equal(o.state, 'execution-failed'); assert.match(o.error, /403 Forbidden/); assert.equal(o.in_force, false);
  const iso = run('endpoint.isolate-device', { device_ref: 'lab-ws-01' }); advance(10000); done(iso, 'execute', 'succeeded', 'contained'); advance(10000); check('p', iso, 'isolated', 'isolated');
  advance(600000); d.rollbackAction('admin-b', iso); done(iso, 'rollback', 'failed', 'Agent offline, reconnect not applied');
  o = co.outcome(iso); assert.equal(o.rollback.state, 'rollback-failed'); assert.equal(o.in_force, true, 'the host is still isolated'); assert.match(o.rollback.error, /Agent offline/);
  assert.equal(s.get('SELECT status FROM actions WHERE id=?', iso).status, 'rollback-failed', 'not a generic failure');
  assert.equal(s.all("SELECT severity FROM alerts WHERE rule_id='CG-ROLLBACK-FAILED-118'")[0].severity, 'critical');
  advance(60000); d.rollbackAction('admin-b', iso); done(iso, 'rollback', 'succeeded', 'Endpoint reconnected');
  o = co.outcome(iso); assert.equal(o.rollback.state, 'rolled-back'); assert.equal(o.in_force, false); assert.equal(o.duration_seconds, 670, 'from enforcement to the verified rollback (10 s + 600 s + 60 s)');
  assert.equal(co.list().summary.execution_failed, 1);
});
