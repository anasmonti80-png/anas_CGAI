import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { identityChains, identityChainView, localPart } from '../lib/identity-chain.js';

function fixture(t) {
  const s = new Store(':memory:'); t.after(() => s.close()); const now = Date.now(), d = new Domain(s, { clock: () => now }), at = m => new Date(now - m * 60000).toISOString();
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', at(0)); const src = d.createSource('a', { name: 'Sensors', stale_seconds: 86400 });
  const idp = { external_id: 'entra', hostname: 'ENTRA', os_family: 'unknown', device_type: 'server', addresses: [] }, ws = { external_id: 'ws-07', hostname: 'WS-07', os_family: 'windows', device_type: 'workstation', addresses: ['10.50.0.7'] };
  const put = (id, kind, details, asset, m) => d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: id, kind, observed_at: at(m), asset, details }] });
  const signin = (id, m, ip, country, result = 'success') => put(id, 'identity.signin_activity', { batch_id: id, directory_ref: 'entra:corp', window: { starts_at: at(m + 1), ends_at: at(m) }, signins: [{ signin_id: id, principal_ref: 'alice@corp.example', at: at(m), result, failure_reason: null, source_ip: ip, country, client_app: 'browser', mfa: 'satisfied' }] }, idp, m);
  const proc = (id, m, user, extra = {}) => put(id, 'endpoint.process_causality', { causality_id: id, collector: { type: 'edr', name: 'Synthetic EDR', trust: 'high', evidence_ref: 'SYN' }, window: { starts_at: at(m + 5), ends_at: at(Math.max(m - 5, 0)) }, processes: [{ process_id: 'p', parent_process_id: null, image_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', command_line: 'powershell.exe', user_ref: user, started_at: at(m), signer: { status: 'signed', publisher: 'Microsoft' }, integrity: 'medium', evidence_ref: 'edr:1' }], service_changes: [], scheduled_task_changes: [], connections: extra.connections || [] }, ws, m);
  return { s, d, now, at, put, signin, proc, idp };
}

test('account names are matched by their user part across directory, UPN and cloud ARN forms (CG-142)', () => {
  assert.deepEqual(['CORP\\Alice', 'alice@corp.example', 'arn:aws:iam::111122223333:user/alice', ' ALICE '].map(localPart), ['alice', 'alice', 'alice', 'alice']);
});

test('an unusual sign-in is joined with tokens, policy changes, processes and connections, and only shared records prove a link (CG-142)', t => {
  const { s, d, now, at, put, signin, proc, idp } = fixture(t), bad = '198.51.100.200';
  signin('s-old', 60 * 24 * 10, '10.50.0.7', 'SA'); signin('s-usual', 60 * 24 * 2, '10.50.0.7', 'SA');
  proc('p-before', 300, 'CORP\\alice');
  signin('s-new', 120, bad, 'RO');
  put('consent', 'identity.oauth_consent', { consent_id: 'C1', directory_ref: 'entra:corp', app_ref: 'Synthetic Mail Reader', publisher: 'Unknown', publisher_verified: false, consent_type: 'user', scopes: ['Mail.Read', 'offline_access'], granted_by_ref: 'alice@corp.example', granted_at: at(110) }, idp, 110);
  const trail = JSON.stringify({ eventTime: at(100), eventSource: 'iam.amazonaws.com', eventName: 'CreateAccessKey', sourceIPAddress: bad, userIdentity: { type: 'IAMUser', arn: 'arn:aws:iam::111122223333:user/alice' } });
  put('trail', 'log.batch', { batch_id: 'CT', source_name: 'cloudtrail', format: 'aws-cloudtrail-json', lines: [trail] }, idp, 100);
  proc('p-after', 60, 'CORP\\alice', { connections: [{ connection_id: 'c', process_id: 'p', direction: 'outbound', protocol: 'tcp', remote_address: '203.0.113.99', remote_port: 443, occurred_at: at(59), evidence_ref: 'edr:c' }] });
  const [c] = identityChains(d, { now });
  assert.equal(c.principal, 'alice@corp.example'); assert.deepEqual(c.steps.map(x => x.step), ['unusual-signin', 'oauth-consent', 'token-or-key', 'endpoint-process', 'network-connection']);
  assert.match(c.steps[0].detail, /new country RO, new address 198\.51\.100\.200/);
  assert.deepEqual(c.links.map(l => l.basis), ['same-account', 'proven', 'same-account', 'proven'], 'the key reuses the sign-in address; the connection is made by the same process; the rest share only the account');
  assert.deepEqual(c.links[1].shared, ['ip:198.51.100.200']); assert.equal(c.preceding.length, 1); assert.match(c.preceding[0].note, /not its consequence/);
  assert.equal(c.severity, 'high'); assert.equal(s.all("SELECT 1 FROM alerts WHERE rule_id='CG-IDENTITY-CHAIN-142' AND severity='high'").length, 1);
  assert.match(identityChainView(d).claim, /never presented as its result/);
});

test('a usual sign-in, a first sign-in and activity of another account start no chain (CG-142)', t => {
  const { s, d, now, signin, proc } = fixture(t);
  signin('first', 120, '198.51.100.1', 'RO'); assert.equal(identityChains(d, { now }).length, 0, 'without one day of history a sign-in is not called unusual');
  signin('later', 60, '198.51.100.1', 'RO'); assert.equal(identityChains(d, { now }).length, 0);
  proc('other', 30, 'CORP\\bob'); assert.equal(s.all("SELECT 1 FROM alerts WHERE rule_id='CG-IDENTITY-CHAIN-142'").length, 0);
});
