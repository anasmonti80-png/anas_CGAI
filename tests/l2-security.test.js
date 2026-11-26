import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { parseL2Config, assessL2Posture, l2View } from '../lib/l2-security.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), FX = n => path.join(ROOT, 'tests/fixtures/cisco', n), CFG = FX('l2-running-config.txt'), LOG = FX('l2-syslog.txt');
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg134-')); process.once('exit', () => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const now = Date.now(), d = new Domain(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString()); const src = d.createSource('a', { name: 'Net', stale_seconds: 86400 });
  const run = (script, a) => { const out = path.join(dir, `${script}-${Math.random()}.json`), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts', script), ...a, '--output', out], { encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); const batch = JSON.parse(fs.readFileSync(out, 'utf8')); d.ingest('a', src.id, batch); return batch; };
  const pm = run('port-map.js', ['--switch-ref', 'acc-sw-01', '--authorization-ref', 'NET-134', '--arp', FX('acc-sw-01-arp.txt'), '--mac-table', FX('acc-sw-01-mac.txt'), '--switchport', FX('acc-sw-01-switchport.txt'), '--lldp', FX('acc-sw-01-lldp.txt')]);
  const put = events => d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events });
  return { s, d, run, put, pm, now, l2: (extra = []) => run('l2-security.js', ['--config', CFG, '--device-ref', 'acc-sw-02', '--authorization-ref', 'NET-134', ...extra]) };
}
const alerts = (s, rule) => s.all('SELECT dedup_key,severity,title FROM alerts WHERE rule_id=? ORDER BY dedup_key', rule);

test('DHCP snooping, ARP inspection, IP Source Guard and 802.1X are reported per device with the VLANs and ports they cover (CG-134)', t => {
  const f = Object.fromEntries(assessL2Posture(parseL2Config(fs.readFileSync(CFG, 'utf8'))).map(x => [x.feature, x]));
  assert.equal(f['dhcp-snooping'].state, 'partial'); assert.deepEqual([f['dhcp-snooping'].vlans_covered, f['dhcp-snooping'].vlans_missing], [[10], [30]]);
  assert.equal(f.dai.state, 'partial'); assert.equal(f.dai.findings[0].id, 'l2-dai-without-snooping', 'ARP inspection on VLAN 30 has no snooping bindings and would drop legitimate ARP');
  assert.deepEqual([f['ip-source-guard'].ports_enabled, f['ip-source-guard'].ports_total], [1, 3], 'the shut down port is not counted');
  assert.equal(f['802.1x'].findings[0].id, 'l2-dot1x-global-missing');
  const full = assessL2Posture(parseL2Config('ip dhcp snooping\nip dhcp snooping vlan 10\nip arp inspection vlan 10\naaa new-model\ndot1x system-auth-control\ninterface Gi1/0/1\n switchport mode access\n switchport access vlan 10\n ip verify source\n authentication port-control auto\ninterface Gi1/0/2\n switchport mode trunk\n'));
  assert.deepEqual(full.map(x => x.state), ['partial', 'enabled', 'enabled', 'enabled'], 'an untrusted uplink leaves snooping partial'); assert.equal(full[0].findings[0].id, 'l2-dhcp-snooping-untrusted-uplink');
  assert.deepEqual(assessL2Posture(parseL2Config(''), { unsupported: ['dai'] }).map(x => x.state), ['disabled', 'unsupported', 'not-applicable', 'not-applicable']);
  assert.ok(assessL2Posture(null, { collected: false }).every(x => x.state === 'not-collected'));
});

test('signals are joined across sources and a single source is never treated as proof of an attack (CG-134)', t => {
  const { s, put, l2, now, pm } = fixture(t);
  const flow = JSON.stringify({ TimeFlowStart: Math.floor(now / 1000) - 60, SrcAddr: '10.20.10.41', DstAddr: '10.20.10.200', SrcPort: 67, DstPort: 68, Proto: 17, Bytes: 300, Packets: 1 });
  put([{ event_id: 'f', kind: 'log.batch', observed_at: new Date(now).toISOString(), asset: pm.events[0].asset, details: { batch_id: 'F134', source_name: 'flows', format: 'goflow-json', lines: [flow] } }]);
  l2(['--syslog', LOG]);
  const v = l2View(s, now), by = (type, subject) => v.findings.find(x => x.type === type && x.subject === subject);
  const rogue = by('rogue-dhcp', '10.20.10.41'); assert.equal(rogue.confidence, 'corroborated'); assert.deepEqual(rogue.sources.sort(), ['dhcp-snooping', 'dhcp-traffic']); assert.equal(rogue.severity, 'high');
  const arp = by('arp-conflict', '10.20.10.41'); assert.deepEqual(arp.sources.sort(), ['arp-inspection', 'arp-table']); assert.equal(arp.severity, 'medium');
  const single = by('arp-conflict', '10.20.10.99'); assert.equal(single.confidence, 'single-signal'); assert.equal(single.severity, 'low'); assert.match(single.verdict, /needs corroboration/); assert.ok(single.possible_benign.some(b => /HSRP/.test(b)));
  assert.equal(by('mac-move', '00:11:22:33:44:77').confidence, 'single-signal');
  assert.deepEqual(alerts(s, 'CG-L2-ROGUE-DHCP-134').map(a => [a.dedup_key, a.severity]), [['CG-L2-ROGUE-DHCP-134:10.20.10.41:corroborated', 'high']]);
  assert.match(alerts(s, 'CG-L2-MAC-MOVE-134')[0].title, /single signal \(switch-log\), needs corroboration/);
  assert.deepEqual(alerts(s, 'CG-L2-POSTURE-134').map(a => a.dedup_key), ['CG-L2-POSTURE-134:acc-sw-02:l2-dai-without-snooping', 'CG-L2-POSTURE-134:acc-sw-02:l2-dot1x-global-missing']);
});

test('MAC moves are found in port map history, and a move onto a virtualization host port stays low even when corroborated (CG-134)', t => {
  const { s, put, l2, now, pm } = fixture(t), e = JSON.parse(JSON.stringify(pm.events[0]));
  e.event_id = 'pm-2'; e.observed_at = new Date(now + 60000).toISOString(); e.details.mac_table = e.details.mac_table.map(x => x.mac === 'a4:bb:6d:11:20:21' ? { ...x, interface: 'Gi1/0/12' } : x); put([e]);
  let f = l2View(s, now).findings.find(x => x.type === 'mac-move' && x.subject === 'a4:bb:6d:11:20:21');
  assert.deepEqual([f.sources, f.ports, f.hypervisor_port, f.confidence], [['port-map-history'], ['Gi1/0/5', 'Gi1/0/12'], true, 'single-signal']);
  const log = path.join(os.tmpdir(), `cg134-flap-${process.pid}.txt`); fs.writeFileSync(log, 'Nov 26 03:00:00: %SW_MATM-4-MACFLAP_NOTIF: Host a4bb.6d11.2021 in vlan 10 is flapping between port Gi1/0/5 and port Gi1/0/12\n'); t.after(() => fs.rmSync(log, { force: true }));
  l2(['--syslog', log]); f = l2View(s, now).findings.find(x => x.type === 'mac-move' && x.subject === 'a4:bb:6d:11:20:21');
  assert.equal(f.confidence, 'corroborated'); assert.equal(f.severity, 'low', 'VM migration is a common benign cause');
  assert.throws(() => put([{ event_id: 'bad', kind: 'network.l2_security', observed_at: new Date(now).toISOString(), asset: pm.events[0].asset, details: { device_ref: 'x', authorization_ref: 'y', hostname: null, features: [], authorized_dhcp: [], signals: [] } }]), /invalid_l2_security/);
});
