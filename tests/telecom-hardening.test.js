import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { parseTelecomConfig, assessTelecom, telecomView, ADVISORY_CVES } from '../lib/telecom-hardening.js';
import { registerView } from '../lib/research-register.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), FX = n => path.join(ROOT, 'tests/fixtures/cisco', n), cfg = n => parseTelecomConfig(fs.readFileSync(FX(n), 'utf8'));
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg140-')); process.once('exit', () => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'Net', stale_seconds: 86400 });
  const declared = path.join(dir, 'declared.json'); fs.writeFileSync(declared, JSON.stringify({ mirroring: ['monitor session 1'] }));
  const run = (config, extra = []) => { const out = path.join(dir, `t-${Math.random()}.json`), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/telecom-hardening.js'), '--config', config, '--device-ref', 'pe-edge-01', '--authorization-ref', 'NET-140', '--declared', declared, ...extra, '--output', out], { encoding: 'utf8' }); if (r.status === 0) d.ingest('a', src.id, JSON.parse(fs.readFileSync(out, 'utf8'))); return r; };
  return { s, run };
}

test('hardening gaps from the communications guidance are found in owned device exports and carrier equipment is out of scope without authorization (CG-140)', t => {
  const ids = assessTelecom(cfg('telecom-edge.txt'), { declared: { mirroring: ['monitor session 1'] } }).map(f => f.id);
  assert.deepEqual(ids, ['smart-install-not-disabled', 'web-ui-enabled', 'ssh-nonstandard-port:2222', 'no-off-box-flow-export'], 'the declared mirroring session is not a finding');
  const hardened = parseTelecomConfig('hostname R1\nno vstack\nip ssh version 2\nflow exporter COLLECTOR\n destination 192.0.2.10\ninterface Gi1/0/1\n switchport mode access\n');
  assert.deepEqual(assessTelecom(hardened), [], 'a hardened device has no findings');
  assert.deepEqual(assessTelecom(parseTelecomConfig('hostname R2\nip ssh port 2222 rotary 1\n'), { declared: { ssh_ports: [2222] } }).map(f => f.id), ['no-off-box-flow-export'], 'routers without switchports are not checked for Smart Install; declared SSH ports pass');
  assert.deepEqual(ADVISORY_CVES.map(c => c.cve), ['CVE-2018-0171', 'CVE-2023-20198', 'CVE-2023-20273', 'CVE-2024-3400', 'CVE-2023-46805', 'CVE-2024-21887']);
  const { run } = fixture(t); const r = run(FX('telecom-edge.txt'), ['--scope', 'carrier-unauthorized']); assert.equal(r.status, 2); assert.match(r.stderr, /written authorization/);
});

test('undeclared mirroring and GRE tunnels and ACL entries or static routes added between exports raise technique alerts (CG-140)', t => {
  const { s, run } = fixture(t); assert.equal(run(FX('telecom-edge.txt')).status, 0);
  assert.equal(s.all("SELECT 1 FROM alerts WHERE rule_id='CG-TELECOM-TTP-140'").length, 0, 'the first export has no technique alerts');
  assert.equal(s.all("SELECT 1 FROM alerts WHERE rule_id='CG-TELECOM-HARDEN-140'").length, 3, 'Smart Install, web UI and SSH port; the low flow-export gap is shown but not alerted');
  assert.equal(run(FX('telecom-edge-after.txt')).status, 0);
  const ttp = s.all("SELECT title,severity FROM alerts WHERE rule_id='CG-TELECOM-TTP-140' ORDER BY title").map(a => a.title.split(' / ')[0]);
  assert.equal(ttp.length, 4); assert.ok(ttp.some(x => /permit ip host 198\.51\.100\.66|permit entry added/.test(x))); assert.ok(ttp.some(x => /Undeclared GRE tunnel Tunnel99 to 198\.51\.100\.66/.test(x))); assert.ok(ttp.some(x => /Undeclared traffic mirroring: monitor session 2 erspan-source/.test(x))); assert.ok(ttp.some(x => /static route/.test(x)));
  const v = telecomView(s), dev = v.devices[0]; assert.equal(dev.exports, 2); assert.ok(dev.findings.some(f => f.id === 'guest-shell-enabled'));
  assert.match(dev.findings.find(f => f.id === 'acl-entries-added').detail, /MGMT-ACL: permit ip host 198\.51\.100\.66 any/);
  assert.match(v.claim, /never scanned/); assert.ok(v.references.every(r => r.url.startsWith('https://www.cisa.gov/')));
  const reg = registerView(ROOT); assert.ok(reg.valid, JSON.stringify(reg.errors)); assert.equal(reg.entries.find(e => e.id === 'R-026').decision, 'accepted');
});
