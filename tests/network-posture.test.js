import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { analyseNetworkPosture } from '../lib/network-posture.js';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), CONFIG = fs.readFileSync(path.join(ROOT, 'tests/fixtures/cisco/posture-running-config.txt'), 'utf8');

test('network posture assesses every area from a real IOS configuration and names each weakness (CG-096)', () => {
  const r = analyseNetworkPosture(CONFIG), area = a => r.areas.find(x => x.area === a), ids = a => area(a).findings.map(f => f.id);
  assert.equal(r.hostname, 'BRANCH-EDGE-01'); assert.equal(r.readable, true); assert.ok(r.areas.every(a => a.state === 'assessed'), JSON.stringify(r.areas.map(a => [a.area, a.state])));
  assert.deepEqual(ids('ipv4'), ['proxy-arp']); assert.deepEqual(ids('ipv6'), ['ipv6-unfiltered']); assert.deepEqual(ids('wifi'), ['wifi-open:GUEST']);
  assert.deepEqual(ids('dns'), ['dns-single-server']); assert.deepEqual(ids('dhcp'), ['dhcp-snooping-off']);
  assert.deepEqual(ids('vpn'), ['vpn-weak-ike:10', 'vpn-weak-esp:LEGACY']); assert.match(area('vpn').findings[0].detail, /encr 3des, hash md5, group 2/);
  assert.deepEqual(ids('vlan'), ['vlan1-access']); assert.equal(area('vlan').findings[0].detail, 'GigabitEthernet1/0/1');
  assert.deepEqual(ids('trunks'), ['dtp-dynamic', 'trunk-all-vlans', 'native-vlan-1', 'trunk-dtp-on']);
  assert.deepEqual(ids('acl'), ['acl-permit-any']); assert.deepEqual(area('nat').findings.map(f => [f.id, f.severity]), [['nat-static:tcp-3389', 'high'], ['nat-static:tcp-443', 'medium']]);
  assert.deepEqual(ids('routing'), ['bgp-no-auth:198.51.100.9', 'bgp-no-filter:198.51.100.9', 'ospf-no-auth:1']);
  assert.ok(r.areas.every(a => a.findings.every(f => f.title_ar && /[؀-ۿ]/.test(f.title_ar))));
});

test('areas not collected, absent or unreadable are never assumed secure (CG-096)', () => {
  const partial = analyseNetworkPosture(CONFIG, { collected: ['acl', 'nat'] });
  assert.deepEqual(partial.areas.filter(a => a.state === 'assessed').map(a => a.area), ['acl', 'nat']); assert.equal(partial.areas.find(a => a.area === 'routing').state, 'not-collected');
  const minimal = analyseNetworkPosture('version 17.9\nhostname LAB-SW\ninterface Vlan1\n ip address 192.0.2.5 255.255.255.0\nend\n');
  assert.equal(minimal.areas.find(a => a.area === 'routing').state, 'not-in-config'); assert.equal(minimal.areas.find(a => a.area === 'wifi').state, 'not-in-config');
  const denied = analyseNetworkPosture('% Command authorization failed.\n');
  assert.equal(denied.readable, false); assert.ok(denied.areas.every(a => a.state === 'not-readable' && a.findings.length === 0));
});

test('the converter produces evidence that raises per-finding alerts and estate coverage (CG-096)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg096-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const input = path.join(dir, 'rc.txt'), out = path.join(dir, 'out.json'); fs.writeFileSync(input, CONFIG);
  const run = spawnSync(process.execPath, [path.join(ROOT, 'scripts/network-posture.js'), input, '--device-ref', 'branch-edge-01', '--authorization-ref', 'CHG-NET-096', '--output', out], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr); assert.equal(JSON.parse(run.stdout).findings, 18);
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, { clock: () => Date.now() });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  d.ingest('admin-a', d.createSource('admin-a', { name: 'Config exports', stale_seconds: 86400 }).id, JSON.parse(fs.readFileSync(out, 'utf8')));
  assert.equal(s.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-NETPOSTURE-096'").n, 18); assert.ok(s.get("SELECT title FROM alerts WHERE rule_id='CG-NETPOSTURE-096' AND title LIKE '%198.51.100.9%' AND severity='high'"));
  const v = d.networkPosture(); assert.equal(v.coverage.trunks.findings, 4); assert.equal(v.coverage.routing.assessed, 1); assert.ok(v.claim_ar.includes('لا يُفترض أنه آمن'));
  const forged = JSON.parse(fs.readFileSync(out, 'utf8')); forged.events[0].event_id = 'x'; forged.events[0].details.areas[0].state = 'not-collected';
  assert.throws(() => d.ingest('admin-a', s.get('SELECT id FROM sources').id, forged), /network_posture_findings_require_assessed_area/);
});
