import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { parseMgmtConfig, auditMgmtPlane, selectBaseline, mgmtView } from '../lib/mgmt-plane.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), FX = n => path.join(ROOT, 'tests/fixtures/cisco', n), cfg = n => parseMgmtConfig(fs.readFileSync(FX(n), 'utf8'));
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg137-')); process.once('exit', () => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'Net', stale_seconds: 86400 });
  const run = (config, extra = []) => { const out = path.join(dir, `m-${Math.random()}.json`), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/mgmt-plane-audit.js'), '--config', config, '--device-ref', 'core-sw-01', '--authorization-ref', 'NET-137', ...extra, '--output', out], { encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); d.ingest('a', src.id, JSON.parse(fs.readFileSync(out, 'utf8'))); return JSON.parse(r.stdout); };
  return { s, dir, run };
}

test('controls are compared with a baseline chosen by vendor and version, and the approved servers of the owner are enforced (CG-137)', () => {
  assert.deepEqual(['17.9', '16.12.4', '15.2', '12.4'].map(v => selectBaseline('cisco', v).id), ['cisco-ios-xe-17', 'cisco-ios-xe-16', 'cisco-ios-15', 'cisco-ios-legacy']);
  const good = auditMgmtPlane(cfg('mgmt-good.txt')); assert.equal(good.baseline, 'cisco-ios-xe-17'); assert.equal(good.score, 100);
  const legacy = auditMgmtPlane(cfg('mgmt-legacy.txt')), st = id => legacy.controls.find(c => c.id === id);
  assert.equal(legacy.baseline, 'cisco-ios-15'); assert.equal(st('enable-secret').status, 'pass', 'type 5 is the strongest IOS 15.2 supports');
  assert.equal(auditMgmtPlane(cfg('mgmt-legacy.txt'), { version: '17.9' }).controls.find(c => c.id === 'enable-secret').status, 'fail', 'the same secret fails on a version that supports type 8/9');
  assert.deepEqual(['vty-ssh-only', 'management-acl', 'snmp-v3-priv', 'aaa-central-login', 'config-backup', 'vty-exec-timeout'].map(id => st(id).status), Array(6).fill('fail'));
  assert.equal(st('syslog-hosts').status, 'pass'); assert.equal(st('vty-ssh-only').observed, 'telnet ssh');
  const org = auditMgmtPlane(cfg('mgmt-good.txt'), { org: { ntp_servers: ['192.0.2.123', '192.0.2.200'], syslog_hosts: ['192.0.2.81'], backup: 'external' } }), oc = id => org.controls.find(c => c.id === id);
  assert.deepEqual([oc('ntp-servers').status, oc('syslog-hosts').status, oc('config-backup').status], ['fail', 'fail', 'pass'], 'servers outside the approved list fail; an external backup declared by the owner passes');
});

test('a control that passed before and fails now raises a regression alert, and unknown vendors or versions get no baseline (CG-137)', t => {
  const { s, dir, run } = fixture(t); run(FX('mgmt-good.txt'));
  assert.equal(s.all("SELECT 1 FROM alerts WHERE rule_id LIKE 'CG-MGMT-%'").length, 0, 'a compliant device raises nothing');
  const weakened = path.join(dir, 'weak.txt'); fs.writeFileSync(weakened, fs.readFileSync(FX('mgmt-good.txt'), 'utf8').replace(/\r\n/g, '\n').replace('logging host 192.0.2.80\n', '').replace(/ transport input ssh\n/g, ' transport input telnet ssh\n'));
  run(weakened); const v = mgmtView(s).devices[0];
  assert.deepEqual(v.regressions.sort(), ['syslog-hosts', 'vty-ssh-only']);
  assert.deepEqual(s.all("SELECT severity FROM alerts WHERE rule_id='CG-MGMT-DRIFT-137'").map(a => a.severity), ['high', 'high']);
  assert.equal(s.all("SELECT 1 FROM alerts WHERE rule_id='CG-MGMT-PLANE-137'").length, 2);
  assert.equal(auditMgmtPlane(cfg('mgmt-good.txt'), { vendor: 'juniper' }).baseline, null);
  const noVer = auditMgmtPlane(parseMgmtConfig('hostname X\n')); assert.equal(noVer.baseline, null); assert.match(noVer.reason, /version unknown/);
  assert.equal(run(FX('mgmt-good.txt'), ['--vendor', 'fortinet']).baseline, null);
});
