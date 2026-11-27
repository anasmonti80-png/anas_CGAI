import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { Deception } from '../lib/deception.js';

const asset = { external_id: 'ws9', hostname: 'ws9', os_family: 'windows', device_type: 'workstation', addresses: ['192.0.2.9'] };
const ACC = { type: 'decoy-account', ref: 'svc-backup-legacy', placement: 'LAB domain, Service Accounts OU', owner: 'soc-team', authorization_ref: 'SEC-164', isolation: ['no-privileges', 'logon-denied-or-disabled', 'monitored-sign-in'] };

test('a decoy runs only after a second administrator approves it, stores no real credential and raises a high-confidence alert when touched (CG-164)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {}), dc = new Deception(s);
  for (const u of ['analyst1', 'admin2']) s.run('INSERT INTO users VALUES (?,?,?,?,?)', u, u, 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  assert.throws(() => dc.propose('analyst1', { ...ACC, isolation: ['no-privileges'] }), /decoy_isolation_attestation_required/);
  assert.throws(() => dc.propose('analyst1', { ...ACC, ref: 'admin' }), /decoy_ref_too_generic/);
  assert.throws(() => dc.propose('analyst1', { ...ACC, note: 'password=Summer2026!' }), /decoy_must_not_contain_credentials/);
  assert.throws(() => dc.propose('analyst1', { type: 'honeytoken', ref: 'AKIAABCDEFGHIJKLMNOP', placement: 'wiki', owner: 'soc', authorization_ref: 'SEC-164', isolation: ['authenticates-nowhere'] }), /honeytoken_marker_is_generated/);
  const acc = dc.propose('analyst1', ACC);
  const tok = dc.propose('analyst1', { type: 'honeytoken', placement: 'IT wiki page "old VPN notes"', owner: 'soc-team', authorization_ref: 'SEC-164', isolation: ['authenticates-nowhere'] });
  const file = dc.propose('analyst1', { type: 'decoy-file', ref: '/srv/finance/payroll-2019-backup.xlsx', placement: 'file server fs1', owner: 'soc-team', authorization_ref: 'SEC-164', isolation: ['read-only', 'outside-production-data', 'object-access-audit'] });
  assert.match(tok.marker, /^CGDECOY-[A-Za-z0-9_-]{24}$/); assert.equal(JSON.stringify(s.all('SELECT * FROM decoys')).includes(tok.marker), false, 'the marker itself is not stored, only its hash and a prefix');
  const src = d.createSource('analyst1', { name: 'Logs', stale_seconds: 86400 }), now = () => new Date().toISOString();
  const touch = (id, kind, details) => d.ingest('analyst1', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: id, kind, observed_at: now(), asset, details }] });
  touch('e0', 'auth.failed', { account: 'svc-backup-legacy', source_ip: '198.51.100.20', protocol: 'unknown' });
  assert.equal(s.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-DECOY-TRIGGER-164'").n, 0, 'a proposed decoy does not run');
  assert.throws(() => dc.approve('analyst1', acc.id), /decoy_needs_second_approver/);
  for (const x of [acc, tok, file]) assert.equal(dc.approve('admin2', x.id).status, 'active');
  touch('e1', 'auth.failed', { account: 'LAB\\svc-backup-legacy', source_ip: '198.51.100.20', protocol: 'unknown' });
  touch('e2', 'auth.failed', { account: 'svc-backup-legacy-2', source_ip: '198.51.100.21', protocol: 'unknown' });
  touch('e3', 'security.finding', { title: 'Web request', severity: 'low', description: `GET /api?key=${tok.marker} from 203.0.113.7` });
  touch('e4', 'security.finding', { title: 'File read', severity: 'low', description: 'read /srv/finance/payroll-2019-backup.xlsx by 192.0.2.44' });
  const alerts = s.all("SELECT severity,title FROM alerts WHERE rule_id='CG-DECOY-TRIGGER-164' ORDER BY title");
  assert.equal(alerts.length, 3, 'decoy account, honeytoken marker and decoy file; a similar account name is not a match'); assert.ok(alerts.every(a => a.severity === 'high'));
  assert.ok(alerts.some(a => /svc-backup-legacy \(account LAB\\svc-backup-legacy/.test(a.title)));
  const v = dc.view(); assert.deepEqual(v.decoys.map(x => [x.type, x.state, x.triggers.n]).sort(), [['decoy-account', 'active', 1], ['decoy-file', 'active', 1], ['honeytoken', 'active', 1]]);
  assert.equal(dc.retire('admin2', acc.id).status, 'retired'); touch('e5', 'auth.failed', { account: 'svc-backup-legacy', source_ip: '198.51.100.22', protocol: 'unknown' });
  assert.equal(s.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-DECOY-TRIGGER-164'").n, 3, 'a retired decoy no longer triggers');
});
