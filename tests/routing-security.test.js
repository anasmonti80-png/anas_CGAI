import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { parseVrps, originValidation, parseBgpConfig, routingView } from '../lib/routing-security.js';
import { registerView } from '../lib/research-register.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), FX = n => path.join(ROOT, 'tests/fixtures/cisco', n);
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg135-')); process.once('exit', () => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'Net', stale_seconds: 86400 });
  const run = (extra, config = FX('bgp-running-config.txt')) => { const out = path.join(dir, `rs-${Math.random()}.json`), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/routing-security.js'), '--config', config, '--device-ref', 'border-rtr-01', '--authorization-ref', 'NET-135', ...extra, '--output', out], { encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); d.ingest('a', src.id, JSON.parse(fs.readFileSync(out, 'utf8'))); return JSON.parse(r.stdout); };
  return { s, d, src, dir, run, full: ['--bgp-table', FX('bgp-table.txt'), '--advertised', `192.0.2.9=${FX('bgp-advertised-192.0.2.9.txt')}`, '--vrps', FX('vrps-routinator.json')] };
}

test('route origin validation follows RFC 6811 and own prefixes are checked for ROA coverage and loose maxLength (CG-135)', t => {
  const vrps = parseVrps(JSON.parse(fs.readFileSync(FX('vrps-routinator.json'), 'utf8'))); assert.deepEqual(parseVrps({ roas: [{ asn: 64500, prefix: '192.0.2.0/24', maxLength: 24 }] })[0].asn, 64500, 'rpki-client numeric ASNs are read too');
  assert.equal(originValidation(vrps, '203.0.113.0/24', 65010), 'valid'); assert.equal(originValidation(vrps, '203.0.113.128/25', 65010), 'valid', 'within maxLength 25');
  assert.equal(originValidation(vrps, '203.0.113.128/25', 64666), 'invalid', 'covered but another origin AS'); assert.equal(originValidation(vrps, '203.0.113.0/26', 65010), 'invalid', 'longer than maxLength');
  assert.equal(originValidation(vrps, '198.51.100.0/25', 65010), 'not-found');
  const c = parseBgpConfig(fs.readFileSync(FX('bgp-running-config.txt'), 'utf8')); assert.equal(c.asn, 65010); assert.deepEqual(c.ebgp.map(n => n.ip), ['203.0.113.1', '192.0.2.9'], 'the iBGP neighbour is not external'); assert.deepEqual(c.neighbors_dropping_invalid, ['203.0.113.1']);
  const { run, s, full } = fixture(t); run(full); const dev = routingView(s).devices[0];
  assert.deepEqual(dev.own, [{ prefix: '203.0.113.0/24', rov: 'valid', loose_max_length: ['203.0.113.0/24-25'] }, { prefix: '198.51.100.0/25', rov: 'not-found', loose_max_length: [] }]);
  assert.deepEqual(dev.findings.map(f => f.id).filter(id => /roa|rov/.test(id)), ['bgp-rov-invalid-accepted', 'bgp-roa-loose-maxlength', 'bgp-roa-missing']);
});

test('hijacks, leaks and missing filters raise alerts and the impact lists the services inside the prefix (CG-135)', t => {
  const { s, d, src, run, full } = fixture(t);
  const web = { external_id: 'web-01', hostname: 'WEB-01', os_family: 'linux', device_type: 'server', addresses: ['203.0.113.140'] };
  d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'w', kind: 'asset.observed', observed_at: new Date().toISOString(), asset: web, details: {} }, { event_id: 'wc', kind: 'asset.context', observed_at: new Date().toISOString(), asset: web, details: { owner: { owner_id: 'web', display_name: 'Web team', contact: null }, business_service: 'Customer portal', service_name: null, site: 'DC', data_sensitivity: 'internal', maintenance_windows: [], service_criticality: 'critical' } }] });
  run(full);
  const rules = s.all("SELECT rule_id,severity,dedup_key FROM alerts WHERE rule_id LIKE 'CG-BGP-%' ORDER BY dedup_key").map(a => [a.rule_id, a.severity]);
  assert.deepEqual(rules.filter(r => r[0] !== 'CG-BGP-POSTURE-135'), [['CG-BGP-HIJACK-135', 'high'], ['CG-BGP-LEAK-135', 'high']]);
  assert.equal(rules.filter(r => r[0] === 'CG-BGP-POSTURE-135').length, 4, 'invalid routes accepted, no inbound and no outbound filter on AS64600, missing ROA');
  const hijack = routingView(s).devices[0].findings.find(f => f.id === 'bgp-possible-hijack'); assert.equal(hijack.subject, '203.0.113.128/25'); assert.match(hijack.detail, /Path 64600 64666; RPKI invalid/);
  assert.deepEqual(hijack.impact, { assets: ['WEB-01'], services: ['Customer portal'] });
});

test('a network without BGP is reported as not applicable and announcement changes are shown between exports (CG-135)', t => {
  const { s, run, full, dir } = fixture(t);
  const lan = path.join(dir, 'lan.txt'); fs.writeFileSync(lan, 'hostname SMALL-LAN-RTR\ninterface Gi0/0\n ip address 10.1.1.1 255.255.255.0\n');
  const r = run([], lan); assert.equal(r.applicable, false); let v = routingView(s); assert.equal(v.applicable, false); assert.match(v.devices[0].reason, /does not apply/); assert.equal(s.all("SELECT 1 FROM alerts WHERE rule_id LIKE 'CG-BGP-%'").length, 0);
  run(full); run(['--bgp-table', FX('bgp-advertised-192.0.2.9.txt'), '--own-prefixes', '192.0.2.0/24']);
  v = routingView(s); assert.ok(v.references.some(x => x.id === 'NIST SP 800-189 Rev. 1' && /draft/i.test(x.status) && /not final/.test(x.status)));
  assert.deepEqual(v.devices[0].changes.added, ['192.0.2.0/24 AS64500']);
  const reg = registerView(ROOT); assert.ok(reg.valid, JSON.stringify(reg.errors)); assert.equal(reg.entries.find(e => e.id === 'R-022').decision, 'accepted'); assert.match(reg.entries.find(e => e.id === 'R-022').risks, /draft/);
});
