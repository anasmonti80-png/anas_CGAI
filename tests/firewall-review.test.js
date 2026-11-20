import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { analyseRuleset, trafficClass, evaluate, whatIf } from '../lib/firewall-analyzer.js';
import { createApp } from '../server.js';

const rule = (rule_id, position, direction, action, src, dst, dst_ports, protocol = 'tcp') => ({ rule_id, name: rule_id, position, enabled: true, direction, action, protocol, src, dst, src_ports: ['any'], dst_ports, application: null, profile: 'any', last_hit_at: null, hit_count: null, expires_at: null, owner: null, created_at: null, filters_readable: true, scope_constraints: [] });
const ruleset = () => ({ ruleset_id: 'FW-EDGE-097', device_ref: 'edge-fw-01', vendor: 'cisco-asa', evaluation: 'first-match', rules: [
  rule('web-in', 1, 'in', 'allow', ['any'], ['10.10.0.20/32'], ['443']),
  rule('block-bad', 2, 'in', 'deny', ['198.51.100.0/24'], ['10.10.0.0/24'], ['any'], 'any'),
  rule('lan-any', 3, 'in', 'allow', ['10.0.0.0/8'], ['10.0.0.0/8'], ['any'], 'any'),
  rule('lan-rdp', 4, 'in', 'allow', ['10.20.0.0/16'], ['10.30.0.0/16'], ['3389']),
  rule('out-any', 5, 'out', 'allow', ['10.0.0.0/8'], ['any'], ['any'], 'any')] });

test('firewall review separates ingress, egress and east-west and finds overlaps, open lateral movement and open egress (CG-097)', () => {
  const rs = ruleset(), r = analyseRuleset(rs, Date.now());
  assert.deepEqual(rs.rules.map(trafficClass), ['ingress', 'ingress', 'east-west', 'east-west', 'egress']); assert.deepEqual(r.traffic_classes, { ingress: 2, egress: 1, 'east-west': 2, unclassified: 0 });
  const types = r.findings.map(f => [f.type, f.rule_id]);
  assert.ok(types.some(([t, id]) => t === 'overlap' && id === 'block-bad'), JSON.stringify(types));
  assert.ok(types.some(([t, id]) => t === 'east-west-broad' && id === 'lan-any')); assert.ok(types.some(([t, id]) => t === 'open-egress' && id === 'out-any'));
  assert.ok(r.findings.filter(f => ['overlap', 'east-west-broad', 'open-egress'].includes(f.type)).every(f => f.detail_ar && /[؀-ۿ]/.test(f.detail_ar)), 'Arabic detail for each new finding');
  assert.deepEqual(evaluate(rs, { direction: 'in', protocol: 'tcp', src: '203.0.113.5', dst: '10.10.0.20', port: 443 }), { action: 'allow', rule_id: 'web-in' });
  assert.deepEqual(evaluate(rs, { direction: 'in', protocol: 'tcp', src: '198.51.100.9', dst: '10.10.0.5', port: 22 }), { action: 'deny', rule_id: 'block-bad' });
  assert.deepEqual(evaluate(rs, { direction: 'in', protocol: 'tcp', src: '203.0.113.5', dst: '10.10.0.21', port: 22 }), { action: 'deny', rule_id: null }, 'default deny');
});

test('what-if shows the impact of a change before it is applied (CG-097)', () => {
  const rs = ruleset();
  const open = whatIf(rs, { op: 'add', rule: rule('ssh-any', 0, 'in', 'allow', ['any'], ['10.10.0.0/24'], ['22']) });
  assert.equal(open.applied, false); assert.ok(open.opened >= 1); assert.equal(open.exposure, 'increases-exposure'); assert.ok(open.new_findings.some(f => f.type === 'broad-admin-exposure' && f.rule_id === 'ssh-any'));
  assert.equal(rs.rules.length, 5, 'the original ruleset is unchanged');
  const tighten = whatIf(rs, { op: 'disable', rule_id: 'lan-any' }); assert.ok(tighten.resolved_findings.some(f => f.type === 'east-west-broad')); assert.ok(tighten.closed >= 1);
  const reorder = whatIf(rs, { op: 'move', rule_id: 'block-bad', position: 0 }); assert.ok(reorder.new_findings.some(f => f.type === 'overlap' && f.rule_id === 'web-in') && reorder.resolved_findings.some(f => f.type === 'overlap' && f.rule_id === 'block-bad'), 'reordering moves which rule wins the overlap'); assert.throws(() => whatIf(rs, { op: 'remove', rule_id: 'missing' }), /rule_not_found/);
});

test('the what-if API evaluates against the latest stored ruleset and changes nothing (CG-097)', async t => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg097-')); const app = createApp({ dataDir, setupToken: 'firewall-setup-token-001', remoteAccess: {} });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const { port } = await app.listen(0), base = `http://127.0.0.1:${port}`, password = 'Firewall-Local-Test-2026!x';
  await fetch(`${base}/api/auth/setup`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ setup_token: 'firewall-setup-token-001', username: 'admin', password }) });
  const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ username: 'admin', password }) }), cookie = login.headers.get('set-cookie').split(';')[0], csrf = (await login.json()).csrf;
  const adminId = app.store.get("SELECT id FROM users WHERE username='admin'").id, src = app.domain.createSource(adminId, { name: 'Firewall exports', stale_seconds: 86400 }), rs = ruleset();
  app.domain.ingest(adminId, src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'fw', kind: 'firewall.ruleset', observed_at: new Date().toISOString(), asset: { external_id: 'edge-fw-01', hostname: 'EDGE-FW-01', os_family: 'network', device_type: 'firewall', addresses: [] }, details: { ruleset_id: rs.ruleset_id, device_ref: rs.device_ref, vendor: 'cisco-asa', evaluation: 'first-match', rules: rs.rules } }] });
  const before = app.store.get('SELECT COUNT(*) n FROM events').n, post = data => fetch(`${base}/api/firewall-rules/what-if`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base, Cookie: cookie, 'X-CSRF-Token': csrf }, body: JSON.stringify(data) }).then(async r => ({ status: r.status, data: await r.json() }));
  const r = await post({ device_ref: 'edge-fw-01', change: { op: 'add', rule: { rule_id: 'rdp-any', name: 'rdp-any', position: 0, direction: 'in', action: 'allow', protocol: 'tcp', src: ['any'], dst: ['10.10.0.0/24'], dst_ports: ['3389'] } } });
  assert.equal(r.status, 200, JSON.stringify(r.data)); assert.equal(r.data.exposure, 'increases-exposure'); assert.ok(r.data.new_findings[0].detail_ar); assert.ok(r.data.claim_ar.includes('محاكاة فقط'));
  assert.equal(app.store.get('SELECT COUNT(*) n FROM events').n, before, 'nothing is stored or changed');
  assert.equal((await post({ device_ref: 'edge-fw-01', change: { op: 'add', rule: { rule_id: 'x', position: 0 } } })).data.error, 'firewall_add_requires_full_rule');
  assert.equal((await post({ device_ref: 'edge-fw-01', change: { op: 'add', rule: { rule_id: 'x', position: 0, direction: 'in', action: 'allow', protocol: 'tcp', src: ['any; rm -rf'], dst: ['any'], dst_ports: ['22'] } } })).data.error, 'invalid_rule_src');
  assert.equal((await post({ device_ref: 'unknown-fw', change: { op: 'remove', rule_id: 'web-in' } })).status, 404);
  assert.equal((await post({ device_ref: 'edge-fw-01', change: { op: 'remove', rule_id: 'nope' } })).data.error, 'rule_not_found');
});
