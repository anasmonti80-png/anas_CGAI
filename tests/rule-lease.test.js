import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { RuleLeases } from '../lib/rule-lease.js';

test('leases are exact, ticketed and second-approved, expire on the enforcement layer, and reconciliation finds overdue, unenforced, orphan and early-removed rules after an outage (CG-172)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.now() - 6 * 3600000; const c = () => now, d = new Domain(s, { clock: c }), rl = new RuleLeases(s, { clock: c, domain: d });
  for (const [u, role] of [['analyst', 'analyst'], ['admin', 'admin']]) s.run('INSERT INTO users VALUES (?,?,?,?,?)', u, u, 'fixture-not-a-password-hash', role, new Date(now).toISOString());
  const fw = d.createSource('admin', { name: 'Firewall connector', stale_seconds: 86400, source_type: 'response-connector' }), asset = { external_id: 'fw-01', hostname: 'FW-01', os_family: 'network', device_type: 'firewall', addresses: [] };
  const report = (id, details) => d.ingest('admin', fw.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: id, kind: 'response.lease_state', observed_at: new Date(now).toISOString(), asset, details: { connector_id: 'FW-172', evidence_ref: `FW-${id}`, enforcement_expires_at: null, ...details } }] });
  const base = { asset_ref: 'fw-01', source: '198.51.100.10', destination: '192.0.2.20', protocol: 'tcp', port: 22, ttl_minutes: 60, owner_ref: 'ops-team', ticket_ref: 'CHG-172', reason: 'Vendor maintenance', connector_id: 'FW-172' };
  assert.throws(() => rl.request('analyst', { ...base, source: 'any' }), /lease_scope_must_be_explicit/);
  const a = rl.request('analyst', base); assert.throws(() => rl.approve('analyst', a.id), /lease_needs_second_approver/);
  const ok = rl.approve('admin', a.id); assert.equal(ok.status, 'approved'); assert.ok(ok.revocation_deadline > ok.expires_at);
  // The device reports its own timer at the approved expiry: installed.
  report('i1', { lease_id: a.id, rule_ref: 'acl-172-1', state: 'installed', enforcement_expires_at: ok.expires_at });
  assert.equal(rl.get(a.id).status, 'installed');
  // A second lease installed without a device-side timer is flagged.
  const b = rl.approve('admin', rl.request('analyst', { ...base, port: 443, ticket_ref: 'CHG-173' }).id);
  report('i2', { lease_id: b.id, rule_ref: 'acl-172-2', state: 'installed', enforcement_expires_at: null });
  assert.equal(rl.get(b.id).status, 'expiry-not-enforced'); assert.equal(s.get("SELECT severity FROM alerts WHERE rule_id='CG-LEASE-172' AND title LIKE '%without a device-side expiry%'").severity, 'high');
  // A third lease removed before its expiry.
  const e = rl.approve('admin', rl.request('analyst', { ...base, port: 3389, ticket_ref: 'CHG-174' }).id);
  report('i3', { lease_id: e.id, rule_ref: 'acl-172-3', state: 'installed', enforcement_expires_at: e.expires_at }); now += 10 * 60000;
  report('r3', { lease_id: e.id, rule_ref: 'acl-172-3', state: 'removed' }); assert.equal(rl.get(e.id).status, 'removed-early');
  // An orphan rule on the device.
  report('o1', { lease_id: 'no-such-lease', rule_ref: 'acl-unknown', state: 'installed' }); assert.ok(s.get("SELECT 1 x FROM alerts WHERE rule_id='CG-LEASE-172' AND title LIKE '%no lease%'"));
  // CyberGuard is down for two hours; on restart the health check reconciles: lease a (device timer) expired on the device
  // and reports removal late, lease b (no timer) was never removed and is overdue.
  now += 2 * 3600000; d.checkHealth();
  assert.equal(rl.get(b.id).status, 'overdue'); assert.ok(s.get("SELECT 1 x FROM alerts WHERE rule_id='CG-LEASE-172' AND title LIKE '%past its revocation deadline%'"));
  assert.equal(rl.get(a.id).status, 'overdue', 'no removal was reported before the deadline either');
  report('r1', { lease_id: a.id, rule_ref: 'acl-172-1', state: 'removed' }); assert.equal(rl.get(a.id).status, 'expired', 'the device confirms removal; its own timer did the work');
  assert.throws(() => report('x', { lease_id: a.id, connector_id: 'OTHER', rule_ref: 'acl-172-1', state: 'removed' }), /lease_connector_mismatch/);
  assert.equal(rl.view().items.length, 3);
});
