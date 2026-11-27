import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { Privacy } from '../lib/privacy.js';

const asset = { external_id: 'srv', hostname: 'srv', os_family: 'linux', device_type: 'server', addresses: [] };

test('sensitive fields are dropped, masked, pseudonymised or encrypted before storage, cards and IBANs are always masked, and decryption is audited (CG-167)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg167-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {}); d.privacy = new Privacy(s, { dataDir: dir });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin', 'admin', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = d.createSource('admin', { name: 'Web', stale_seconds: 86400 }), at = new Date().toISOString();
  d.privacy.addRule('admin', { kind: 'auth.failed', field: 'account', action: 'hash', reason: 'Pseudonymise user names; correlation keeps working' });
  d.privacy.addRule('admin', { kind: 'identity.signin_activity', field: 'signins.*.source_ip', action: 'encrypt', reason: 'Employee home addresses' });
  d.privacy.addRule('admin', { kind: 'security.finding', field: 'description', action: 'mask', reason: 'Free text may hold personal data' });
  assert.throws(() => d.privacy.addRule('admin', { kind: '*', field: 'event_id', action: 'drop', reason: 'x' }), /invalid_privacy_field|privacy_field_is_structural/);
  d.ingest('admin', src.id, { schema_version: 'cg.telemetry/1', events: [
    ...Array.from({ length: 5 }, (_, i) => ({ event_id: `a${i}`, kind: 'auth.failed', observed_at: at, asset, details: { account: 'Mohammed.Alharbi', source_ip: '198.51.100.7', protocol: 'ssh' } })),
    { event_id: 's1', kind: 'identity.signin_activity', observed_at: at, asset, details: { batch_id: 'b1', directory_ref: 'lab', window: { starts_at: at, ends_at: at }, signins: [{ signin_id: 'x', principal_ref: 'user1', at, result: 'success', failure_reason: null, source_ip: '203.0.113.44', country: 'SA', client_app: 'browser', mfa: 'satisfied' }] } },
    { event_id: 'w1', kind: 'security.finding', observed_at: at, asset, details: { title: 'Card in URL 4111 1111 1111 1111 and IBAN SA0380000000608010167519', severity: 'low', description: 'customer note' } }] });
  const payload = id => JSON.parse(s.get('SELECT payload FROM events WHERE external_id=?', id).payload);
  const acc = payload('a0').details.account; assert.match(acc, /^hmac:[0-9a-f]{32}$/); assert.equal(payload('a4').details.account, acc, 'equal values stay equal');
  assert.equal(s.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-AUTH-FAILURES-5-IN-5M'").n, 1, 'correlation still works on pseudonymised accounts');
  assert.equal(JSON.stringify(s.all('SELECT payload FROM events')).includes('Mohammed'), false, 'the clear name is never stored');
  const enc = payload('s1').details.signins[0].source_ip; assert.match(enc, /^enc:v1:/); assert.equal(JSON.stringify(s.all('SELECT payload FROM events')).includes('203.0.113.44'), false);
  const w = payload('w1'); assert.equal(w.details.title, 'Card in URL ************1111 and IBAN ************7519'); assert.equal(w.details.description, '*********note');
  assert.deepEqual(w.privacy.minimized.map(m => m.field).sort(), ['description', 'payment-card', 'saudi-iban']);
  const ev = s.get("SELECT id FROM events WHERE external_id='s1'").id;
  assert.deepEqual(d.privacy.decrypt('admin', { event_id: ev, field: 'signins.0.source_ip', reason: 'Incident IR-167 needs the address' }).value, '203.0.113.44');
  assert.throws(() => d.privacy.decrypt('admin', { event_id: ev, field: 'signins.0.country', reason: 'x' }), /field_not_encrypted/);
  assert.equal(s.get("SELECT COUNT(*) n FROM audit WHERE action='privacy.field_decrypted'").n, 1);
  assert.equal(fs.statSync(path.join(dir, 'field-protection.key')).isFile(), true);
});

test('retention follows the source, source type or evidence kind, never goes below a legal minimum and never purges evidence of open alerts (CG-167)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.now() - 400 * 86400000; const d = new Domain(s, { clock: () => now }), pr = new Privacy(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin', 'admin', 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString());
  const fw = d.createSource('admin', { name: 'Firewall', stale_seconds: 86400, source_type: 'log-forwarder' }), hr = d.createSource('admin', { name: 'HR app', stale_seconds: 86400 });
  const put = (src, id, kind, details) => d.ingest('admin', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: id, kind, observed_at: new Date(now).toISOString(), asset, details }] });
  for (let i = 0; i < 5; i++) put(fw, `fw${i}`, 'auth.failed', { account: 'root', source_ip: '198.51.100.9', protocol: 'ssh' });
  put(hr, 'hr1', 'asset.observed', {});
  assert.throws(() => pr.addRetention('admin', { scope: 'source-type', match: 'log-forwarder', days: 90, legal_basis: 'Contract requires 12 months of security logs', legal_minimum_days: 365 }), /retention_below_legal_minimum/);
  pr.addRetention('admin', { scope: 'source-type', match: 'log-forwarder', days: 365, legal_basis: 'Contract requires 12 months of security logs', legal_minimum_days: 365 });
  pr.addRetention('admin', { scope: 'source', match: fw.id, days: 30, legal_basis: 'Owner wants a short window for this firewall' });
  pr.addRetention('admin', { scope: 'source', match: hr.id, days: 30, legal_basis: 'Personal data minimisation (HR)' });
  now += 200 * 86400000;
  let plan = pr.retentionPlan(false); const byRule = r => plan.rules.find(x => x.rule === r);
  assert.equal(byRule(`source:${fw.id}`).days, 365, 'a shorter source rule cannot undercut the legal minimum of its source type');
  assert.deepEqual([byRule(`source:${hr.id}`).days, byRule(`source:${hr.id}`).expired], [30, 1]);
  now += 200 * 86400000; plan = pr.retentionPlan(false);
  const fwPlan = plan.rules.find(r => r.rule === `source:${fw.id}`); assert.deepEqual([fwPlan.held, fwPlan.expired], [1, 4], 'the open alert evidence is held; the other four failures expired after 365 days');
  const r = pr.retentionPlan(true, 'admin'); assert.equal(r.deleted, 5); assert.equal(s.get('SELECT COUNT(*) n FROM events').n, 1, 'only the held evidence remains');
  assert.equal(s.get("SELECT COUNT(*) n FROM audit WHERE action='privacy.retention_applied'").n, 1);
});
