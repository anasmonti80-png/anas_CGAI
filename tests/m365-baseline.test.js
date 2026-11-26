import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { parseScubaResults, summarize, m365View, PERMISSIONS, PRODUCTS } from '../lib/m365-baseline.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), FX = path.join(ROOT, 'tests/fixtures/m365/ScubaResults_synthetic.json');
const raw = () => JSON.parse(fs.readFileSync(FX, 'utf8'));
const ctl = (j, id) => Object.values(j.Results).flatMap(g => g.flatMap(x => x.Controls)).find(c => c['Control ID'] === id);

test('ScubaGear results keep the baseline policy and tool version, and untested, third-party, omitted, errored or unassessed controls are never counted as compliant (CG-146)', () => {
  const r = parseScubaResults(fs.readFileSync(FX, 'utf8')), c = id => r.controls.find(x => x.id === id);
  assert.equal(r.tool_version, '2.0.0'); assert.deepEqual([c('MS.AAD.3.5v2').policy, c('MS.AAD.3.5v2').policy_version], ['MS.AAD.3.5', 2]);
  assert.deepEqual([c('MS.AAD.3.1v1').status, c('MS.AAD.3.1v1').severity, c('MS.AAD.3.1v1').bod_25_01], ['deviation', 'high', true]);
  assert.equal(c('MS.AAD.3.1v1').requirement, 'Phishing-resistant MFA SHALL be enforced for all users.', 'HTML badges are removed from the requirement');
  assert.deepEqual([c('MS.AAD.3.8v1').status, c('MS.AAD.3.8v1').severity], ['deviation', 'medium'], 'a SHOULD warning is a deviation of lower severity');
  assert.equal(c('MS.AAD.7.9v1').status, 'manual-check', 'a Not-Implemented control is not compliant just because the tool says N/A');
  assert.equal(c('MS.SECURITYSUITE.2.1v1').status, 'third-party-evidence'); assert.equal(c('MS.AAD.7.4v1').status, 'not-assessed');
  assert.equal(c('MS.EXO.4.4v1').status, 'omitted-by-owner'); assert.match(c('MS.EXO.4.4v1').details, /SEC-146/, 'the owner rationale is kept');
  const s = summarize(r.controls, r.products_assessed);
  assert.deepEqual([s.shall_deviations, s.should_deviations, s.meets, s.automated_score], [1, 1, 6, 75], 'only evaluated automated results count toward the percentage');
  assert.deepEqual(s.products_not_assessed, ['PowerBI', 'PowerPlatform', 'SharePoint'], 'products not in the run are listed, never assumed compliant');
  const legacy = raw(); legacy.Results.Defender = [{ GroupName: 'Preset', Controls: [{ 'Control ID': 'MS.DEFENDER.1.1v1', Requirement: 'x', Result: 'Pass', Criticality: 'Shall', Details: '' }] }];
  const l = parseScubaResults(legacy).controls.find(x => x.id === 'MS.DEFENDER.1.1v1'); assert.equal(l.product, 'SecuritySuite'); assert.match(l.superseded, /SECURITYSUITE/);
  assert.throws(() => parseScubaResults({ MetaData: { Tool: 'Other' }, Results: {} }), /not_scubagear_results/);
  assert.deepEqual(PERMISSIONS.map(p => p.product), PRODUCTS.map(p => p.code), 'least-privilege guidance exists for every product');
  assert.deepEqual(PERMISSIONS.filter(p => !p.read_only).map(p => p.product), ['PowerPlatform', 'SharePoint'], 'write-capable access is labelled as such');
});

test('a SHALL deviation raises an alert, and a control that met the baseline before and deviates now raises a regression while a policy version change does not (CG-146)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg146-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'M365', stale_seconds: 86400 });
  const run = file => { const out = path.join(dir, `m-${Math.random()}.json`), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/m365-baseline.js'), '--scuba', file, '--tenant-ref', 'tenant-lab', '--authorization-ref', 'SEC-146', '--output', out], { encoding: 'utf8' });
    if (r.status === 0) d.ingest('a', src.id, JSON.parse(fs.readFileSync(out, 'utf8'))); return r; };
  assert.equal(run(FX).status, 0);
  assert.deepEqual(s.all("SELECT title FROM alerts WHERE rule_id='CG-M365-BASELINE-146'").map(a => /MS\.AAD\.3\.1v1/.test(a.title)), [true], 'only the SHALL deviation alerts');
  const next = raw(); next.MetaData.ReportUUID = '00000000-0000-4000-8000-000000000147'; next.MetaData.TimestampZulu = '2026-10-22T08:00:00.000Z';
  Object.assign(ctl(next, 'MS.EXO.1.1v2'), { Result: 'Fail', Details: 'Forwarding allowed by a remote domain' });
  Object.assign(ctl(next, 'MS.TEAMS.2.1v2'), { 'Control ID': 'MS.TEAMS.2.1v3', Result: 'Fail' });
  const f2 = path.join(dir, 'next.json'); fs.writeFileSync(f2, JSON.stringify(next)); assert.equal(run(f2).status, 0);
  const v = m365View(s).tenants[0];
  assert.deepEqual(v.drift.regressions, ['MS.EXO.1.1v2']); assert.deepEqual(v.drift.version_changes, [{ policy: 'MS.TEAMS.2.1', from: 2, to: 3 }], 'a new policy version is a reference change');
  assert.equal(v.imports, 2); assert.equal(v.controls[0].status, 'deviation', 'deviations are listed first');
  assert.deepEqual(s.all("SELECT severity FROM alerts WHERE rule_id='CG-M365-DRIFT-146'").map(a => a.severity), ['high']);
  assert.equal(s.all("SELECT 1 FROM alerts WHERE rule_id='CG-M365-BASELINE-146'").length, 3);
  const bad = path.join(dir, 'bad.json'); fs.writeFileSync(bad, '{"MetaData":{"Tool":"x"}}'); assert.equal(run(bad).status, 2, 'files that are not ScubaGear results are refused');
});
