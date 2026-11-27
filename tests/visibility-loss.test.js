import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { lossView, INTERNAL_SOURCE_ID } from '../lib/visibility-loss.js';

const asset = (n) => ({ external_id: n, hostname: n, os_family: 'windows', device_type: 'workstation', addresses: ['192.0.2.30'] });
const setup = (t, now) => { const s = new Store(':memory:'); t.after(() => s.close()); const clock = { t: now }, d = new Domain(s, { clock: () => clock.t });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString()); return { s, d, clock }; };
const iso = t => new Date(t).toISOString();
const tamper = (id, host, type, action, at, context = {}) => ({ event_id: id, kind: 'endpoint.defense_tamper', observed_at: at, asset: asset(host), details: { tamper_id: id, control: { type, name: `${type} service` }, change: { action, occurred_at: at, actor_ref: 'lab-user', process_ref: 'synthetic', method: 'user-command', previous_value: 'on', new_value: 'off', time_skew_seconds: action === 'time-changed' ? -7200 : null }, context: { authorization_ref: null, change_ticket_ref: null, maintenance_window: false, preceding_errors: 0, recovered_at: null, recovery_evidence_ref: null, ...context }, evidence_ref: id } });

test('a visibility loss is an independent stored event with cause, affected rules and an assessment that is never compromise, and it closes when the source reports again (CG-163)', t => {
  const now = Date.now() - 7200000, { s, d, clock } = setup(t, now);
  const agent = d.createSource('a', { name: 'Agent WS1', stale_seconds: 300, source_type: 'managed-agent' });
  d.ingest('a', agent.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'p1', kind: 'auth.failed', observed_at: iso(now), asset: asset('WS1'), details: { account: 'u', source_ip: '198.51.100.9', protocol: 'rdp' } }] });
  clock.t = now + 900000; d.checkHealth();
  let v = lossView(s); assert.equal(v.items.length, 1); const loss = v.items[0];
  assert.deepEqual([loss.cause, loss.assessment, loss.compromise_confirmed, loss.ended_at, loss.source_name, loss.asset], ['agent-disconnected', 'unexplained', false, null, 'Agent WS1', 'WS1']);
  assert.ok(loss.rules_affected.includes('CG-CORR-BRUTE-SUCCESS-161'), 'rules fed by auth.failed lose their input');
  assert.equal(s.get('SELECT source_id FROM events WHERE kind=?', 'visibility.loss').source_id, INTERNAL_SOURCE_ID, 'stored from the internal source');
  assert.equal(s.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-VISIBILITY-LOSS-163'").n, 0, 'an unexplained disconnection is not alerted as an incident');
  d.checkHealth(); assert.equal(lossView(s).items.length, 1, 'no duplicate while it lasts');
  assert.throws(() => d.ingest('a', agent.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'x', kind: 'visibility.loss', observed_at: iso(clock.t), asset: asset('WS1'), details: {} }] }), /invalid_kind|unknown_kind|kind/, 'only CyberGuard creates visibility.loss');
  clock.t = now + 1800000; d.ingest('a', agent.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'p2', kind: 'asset.observed', observed_at: iso(clock.t), asset: asset('WS1'), details: {} }] });
  v = lossView(s); assert.deepEqual([v.items[0].ended_at, v.items[0].duration_minutes, v.open], [iso(clock.t), 30, 0]);
  assert.equal(d.sources().some(x => x.id === INTERNAL_SOURCE_ID), false, 'the internal source is not listed as a monitored source');
  // A second silence while another high alert is open on the asset is suspicious-concurrent: alerted, still not compromise.
  d.alert({ key: 'x1', assetId: s.get("SELECT id FROM assets WHERE external_id='WS1'").id, sourceId: agent.id, rule: 'CG-MAL-LOLBIN-001', severity: 'high', title: 'synthetic' });
  clock.t = now + 3000000; d.checkHealth();
  const open = lossView(s).items.find(i => !i.ended_at); assert.deepEqual([open.assessment, open.concurrent_rules, open.compromise_confirmed], ['suspicious-concurrent', ['CG-MAL-LOLBIN-001'], false]);
  assert.match(s.get("SELECT title FROM alerts WHERE rule_id='CG-VISIBILITY-LOSS-163'").title, /not a confirmed compromise/);
});

test('tampering, cleared logs and clock changes create visibility losses that correlation rules use, and authorised changes are not alerted (CG-163)', t => {
  const now = Date.now() - 600000, { s, d } = setup(t, now);
  const edr = d.createSource('a', { name: 'EDR', stale_seconds: 86400 });
  d.ingest('a', edr.id, { schema_version: 'cg.telemetry/1', events: [tamper('t1', 'WS2', 'logging', 'cleared', iso(now)), tamper('t2', 'WS3', 'time', 'time-changed', iso(now)), tamper('t3', 'WS4', 'agent', 'stopped', iso(now), { change_ticket_ref: 'CHG-163', maintenance_window: true }), tamper('t4', 'WS5', 'firewall', 'disabled', iso(now))] });
  const v = lossView(s), by = h => v.items.find(i => i.asset === h);
  assert.deepEqual([by('WS2').cause, by('WS3').cause, by('WS4').cause, by('WS5')], ['log-deletion', 'clock-change', 'agent-disabled', undefined], 'a firewall change is not a loss of visibility');
  assert.equal(by('WS4').assessment, 'authorized-change');
  const corr = s.all("SELECT title FROM alerts WHERE rule_id='CG-CORR-TAMPER-THEN-LOSS-163'").map(r => r.title).join('|');
  assert.match(corr, /tampered, then visibility lost/); assert.equal(s.all("SELECT 1 FROM alerts WHERE rule_id='CG-CORR-TAMPER-THEN-LOSS-163'").length, 3, 'the correlation rule joins each tamper and its loss on the same asset');
  assert.equal(s.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-VISIBILITY-LOSS-163'").n, 0);
  // Delivery backlog: telemetry delivered more than an hour late is a closed transport-failure loss.
  d.recordDelivery(edr.id, { depth: 400, oldest: iso(now - 7200000), attempt: 3 });
  const tf = lossView(s).items.find(i => i.cause === 'transport-failure'); assert.ok(tf.ended_at); assert.match(tf.detail, /400 queued/);
});
