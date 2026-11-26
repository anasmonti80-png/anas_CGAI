import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { correlateRemote, remoteCorrelationView } from '../lib/remote-correlation.js';

function fixture(t) {
  const s = new Store(':memory:'); t.after(() => s.close()); const now = Date.now(), d = new Domain(s, { clock: () => now }), at = m => new Date(now - m * 60000).toISOString();
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', at(0)); const src = d.createSource('a', { name: 'Sensors', stale_seconds: 86400 });
  const host = (ref, ip) => ({ external_id: ref, hostname: ref.toUpperCase(), os_family: 'windows', device_type: 'workstation', addresses: [ip] });
  const put = (id, kind, details, asset, m) => d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: id, kind, observed_at: at(m), asset, details }] });
  const remote = (id, phase, asset, m, extra) => put(id, `remote.${phase}`, { session_id: extra.session_id, protocol: extra.protocol, source_a: extra.source_a || null, target_b: extra.target_b || null, relay: extra.relay || false, evidence_type: { attempt: 'connection_attempt', authenticated: 'authentication_log', active: 'session_log' }[phase], assessment: extra.authorization_ref ? 'authorized' : 'unknown', assessment_basis: 'source-report', authorization_ref: extra.authorization_ref || null, rationale: null }, asset, m);
  const proc = (id, asset, m, processes, extra = {}) => put(id, 'endpoint.process_causality', { causality_id: id, collector: { type: 'edr', name: 'Synthetic EDR', trust: 'high', evidence_ref: 'SYN' }, window: { starts_at: at(m + 5), ends_at: at(Math.max(m - 5, 0)) }, processes: processes.map((p, i) => ({ process_id: p.id || `p${i}`, parent_process_id: p.parent || null, image_path: p.image, command_line: p.cmd || p.image.split('\\').pop(), user_ref: 'user', started_at: at(p.m ?? m), signer: { status: 'signed', publisher: 'Synthetic' }, integrity: 'medium', evidence_ref: `edr:${i}` })), service_changes: extra.services || [], scheduled_task_changes: extra.tasks || [], connections: extra.connections || [] }, asset, m);
  return { s, d, now, at, host, put, remote, proc };
}
const find = (list, ref, tool) => list.find(x => x.asset_ref === ref && x.tool === tool);

test('installed, started, connected and authenticated are separate stages and a relay hides the peer (CG-141)', t => {
  const { d, now, at, host, put, remote, proc } = fixture(t), ws = host('ws-01', '10.40.0.11');
  put('inv', 'software.inventory', { inventory_id: 'INV-WS', os: { name: 'Windows 11', version: '10.0.26100', build: '26100' }, software: [{ name: 'AnyDesk', vendor: 'AnyDesk Software GmbH', version: '9.0.4', install_date: null, source: 'uninstall-registry' }], updates: [], evidence_ref: 'SYN' }, ws, 120);
  let g = find(correlateRemote(d, { now }), 'ws-01', 'anydesk'); assert.deepEqual(g.reached, ['installed']); assert.equal(g.classification, 'installed-only'); assert.match(g.note, /no authenticated session is proven/);
  proc('p1', ws, 60, [{ id: 'a', image: 'C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe' }], { connections: [{ connection_id: 'c1', process_id: 'a', direction: 'outbound', protocol: 'tcp', remote_address: '198.51.100.20', remote_port: 443, occurred_at: at(59), evidence_ref: 'edr:c' }] });
  g = find(correlateRemote(d, { now }), 'ws-01', 'anydesk'); assert.deepEqual(g.reached, ['installed', 'started', 'connected']); assert.equal(g.classification, 'connected-only', 'a connection to the vendor is not a session');
  remote('r1', 'authenticated', ws, 30, { session_id: 'AD-77', protocol: 'anydesk', relay: true, target_b: { hostname: 'WS-01', ip: null, account: 'user1' } });
  g = find(correlateRemote(d, { now }), 'ws-01', 'anydesk'); assert.deepEqual(g.reached, ['installed', 'started', 'connected', 'authenticated']); assert.deepEqual(g.peers, [{ peer: 'relay', ip: null }]);
  assert.equal(g.classification, 'external-session-needs-review'); assert.equal(g.compromise_confirmed, false); assert.match(g.note, /not proof of compromise/);
});

test('misuse needs both an identity and a behaviour signal and is never called a compromise automatically (CG-141)', t => {
  const { s, d, now, host, put, remote, proc } = fixture(t), srv = host('srv-01', '10.40.0.20'), attacker = '203.0.113.50';
  for (let i = 0; i < 6; i++) put(`f${i}`, 'auth.failed', { account: 'administrator', source_ip: attacker, protocol: 'rdp' }, srv, 50 - i);
  remote('r2', 'authenticated', srv, 40, { session_id: 'RDP-1', protocol: 'rdp', source_a: { hostname: null, ip: attacker, account: null }, target_b: { hostname: 'SRV-01', ip: null, account: 'administrator' } });
  let g = find(correlateRemote(d, { now }), 'srv-01', 'rdp'); assert.equal(g.identity.length, 1); assert.match(g.identity[0].detail, /6 failed logons from 203\.0\.113\.50/); assert.equal(g.classification, 'external-session-needs-review', 'identity alone is not misuse');
  proc('p2', srv, 30, [{ id: 'x', image: 'C:\\Windows\\System32\\cmd.exe' }, { id: 'y', parent: 'x', image: 'C:\\Windows\\System32\\whoami.exe' }], { services: [{ change_id: 's1', process_id: 'x', service_name: 'SyntheticSvc', action: 'created', binary_path: 'C:\\ProgramData\\s.exe', occurred_at: new Date(now - 29 * 60000).toISOString(), evidence_ref: 'edr:s' }] });
  g = find(correlateRemote(d, { now }), 'srv-01', 'rdp'); assert.equal(g.classification, 'suspected-misuse'); assert.equal(g.behaviour.length, 3); assert.equal(g.compromise_confirmed, false); assert.match(g.note, /analyst must confirm/);
  const alerts = s.all("SELECT dedup_key,severity,title FROM alerts WHERE rule_id='CG-REMOTE-CORRELATION-141' ORDER BY dedup_key");
  assert.deepEqual(alerts.map(a => [a.dedup_key, a.severity]), [['CG-REMOTE-CORRELATION-141:srv-01:rdp:external-session-needs-review', 'medium'], ['CG-REMOTE-CORRELATION-141:srv-01:rdp:suspected-misuse', 'high']]);
  assert.ok(alerts.every(a => /not proof of compromise/.test(a.title)));
});

test('an authorized internal session is not flagged and behaviour long after a session is not tied to it (CG-141)', t => {
  const { s, d, now, host, remote, proc } = fixture(t), jump = host('jump-01', '10.40.0.30');
  remote('r3', 'authenticated', jump, 300, { session_id: 'SSH-9', protocol: 'ssh', source_a: { hostname: 'ADMIN-PC', ip: '10.40.1.5', account: 'ops' }, authorization_ref: 'CHG-141' });
  proc('p3', jump, 10, [{ id: 'z', image: 'C:\\Windows\\System32\\cmd.exe' }]);
  const g = find(correlateRemote(d, { now }), 'jump-01', 'ssh'); assert.equal(g.classification, 'authorized'); assert.deepEqual(g.peers, [{ peer: 'internal', ip: '10.40.1.5' }]); assert.equal(g.behaviour.length, 0, 'a shell five hours later is outside the two-hour window');
  assert.equal(s.all("SELECT 1 FROM alerts WHERE rule_id='CG-REMOTE-CORRELATION-141'").length, 0);
  assert.equal(remoteCorrelationView(d).stages.length, 4);
});
