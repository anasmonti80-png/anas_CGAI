import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { parseWlcConfig, assessWlans, wirelessView } from '../lib/wireless.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), W = n => path.join(ROOT, 'tests/fixtures/wireless', n), C = n => path.join(ROOT, 'tests/fixtures/cisco', n);
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg136-')); process.once('exit', () => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'Net', stale_seconds: 86400 });
  const run = (script, a) => { const out = path.join(dir, `${script}-${Math.random()}.json`), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts', script), ...a, '--output', out], { encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); const b = JSON.parse(fs.readFileSync(out, 'utf8')); d.ingest('a', src.id, b); return b; };
  return { s, d, src, run, portMap: () => run('port-map.js', ['--switch-ref', 'acc-sw-01', '--authorization-ref', 'NET-136', '--arp', C('acc-sw-01-arp.txt'), '--mac-table', C('acc-sw-01-mac.txt'), '--switchport', C('acc-sw-01-switchport.txt'), '--lldp', C('acc-sw-01-lldp.txt')]),
    wifi: () => run('wireless-assurance.js', ['--config', W('wlc-running-config.txt'), '--rogues', W('rogues.json'), '--aps', W('aps.json'), '--controller-ref', 'wlc-01', '--authorization-ref', 'NET-136']) };
}

test('SSIDs are inventoried with their security, 802.1X and RADIUS, management frame protection and guest isolation (CG-136)', () => {
  const { ssids, findings } = assessWlans(parseWlcConfig(fs.readFileSync(W('wlc-running-config.txt'), 'utf8'))), by = n => ssids.find(x => x.ssid === n);
  assert.deepEqual([by('CORP-WiFi').security, by('CORP-WiFi').aaa_list, by('CORP-WiFi').radius_servers, by('CORP-WiFi').pmf, by('CORP-WiFi').vlan], ['wpa2-wpa3-enterprise', 'ISE-AUTH', 2, 'mandatory', '10']);
  assert.deepEqual([by('Guest-WiFi').security, by('Guest-WiFi').guest, by('Guest-WiFi').peer_blocking], ['open-web-auth', true, false]);
  assert.equal(by('IOT-Devices').security, 'wpa2-personal');
  assert.deepEqual(findings.map(f => [f.id, f.severity]), [['wifi-guest-no-isolation:Guest-WiFi', 'medium'], ['wifi-guest-shares-vlan:Guest-WiFi', 'high'], ['wifi-psk-corporate:IOT-Devices', 'medium']]);
  const other = assessWlans(parseWlcConfig('wlan OPEN 1 Office\n no security wpa\n no shutdown\nwlan SEC 2 Secure\n security dot1x authentication-list MISSING\n security wpa wpa3\n no security wpa wpa2\n no shutdown\nwlan G 3 Guests\n no security wpa\n peer-blocking drop\n no shutdown\n'));
  assert.deepEqual(other.findings.map(f => f.id), ['wifi-open-corporate:Office', 'wifi-pmf-not-mandatory:Secure', 'wifi-aaa-missing:Secure'], 'an isolated guest SSID raises nothing');
});

test('rogue APs are corroborated only when seen on the wired network, neighbours are not alerted and RF coverage limits are stated (CG-136)', t => {
  const { s, portMap, wifi } = fixture(t); portMap(); wifi();
  const c = wirelessView(s, new Domain(s, {}).portMaps()).controllers[0], by = b => c.rogues.find(r => r.bssid === b);
  const evil = by('a4:bb:6d:11:20:2f'); assert.deepEqual([evil.kind, evil.confidence, evil.severity, evil.wired.interface], ['rogue-on-network-impersonating', 'corroborated', 'high', 'Gi1/0/5']);
  const air = by('00:24:6c:aa:bb:01'); assert.deepEqual([air.kind, air.confidence, air.severity], ['ssid-impersonation', 'single-signal', 'low']); assert.match(air.note, /needs corroboration/);
  assert.deepEqual([by('3c:7a:aa:00:00:10').kind, by('3c:7a:aa:00:00:10').severity], ['neighbour', null]);
  assert.deepEqual(c.coverage.blind_sites, ['Branch-2']); assert.match(c.coverage.limits, /No active wireless testing/);
  const alerts = s.all("SELECT dedup_key,severity FROM alerts WHERE rule_id='CG-WIFI-ROGUE-136' ORDER BY dedup_key").map(a => [a.dedup_key, a.severity]);
  assert.deepEqual(alerts, [['CG-WIFI-ROGUE-136:00:24:6c:aa:bb:01:single-signal', 'low'], ['CG-WIFI-ROGUE-136:a4:bb:6d:11:20:2f:corroborated', 'high']]);
  assert.equal(s.all("SELECT 1 FROM alerts WHERE rule_id='CG-WIFI-POSTURE-136'").length, 3);
});

test('without switch port maps a rogue over the air stays a single signal, and bad exports are refused (CG-136)', t => {
  const { s, d, src, wifi } = fixture(t); const b = wifi();
  assert.ok(wirelessView(s, d.portMaps()).controllers[0].rogues.every(r => r.confidence !== 'corroborated'));
  const bad = JSON.parse(JSON.stringify(b.events[0])); bad.event_id = 'bad'; bad.details.rogues[0].bssid = 'not-a-mac';
  assert.throws(() => d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [bad] }), /invalid_wifi_rogue/);
});
