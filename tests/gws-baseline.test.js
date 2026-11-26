import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { parseScubaGoggles, compareAreas, gwsView, ACCESS } from '../lib/gws-baseline.js';
import { summarize } from '../lib/m365-baseline.js';
import { PRODUCTS } from '../lib/gws-baseline.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), FX = path.join(ROOT, 'tests/fixtures/gws/ScubaResults_synthetic.json'), M365 = path.join(ROOT, 'tests/fixtures/m365/ScubaResults_synthetic.json');
const raw = () => JSON.parse(fs.readFileSync(FX, 'utf8'));

test('ScubaGoggles results are judged against the declared edition and the APIs used: license-dependent features and log checks without events are never compliance or deviation (CG-147)', () => {
  const plus = parseScubaGoggles(raw(), { edition: 'enterprise-plus' }), biz = parseScubaGoggles(raw(), { edition: 'business-plus' }), unk = parseScubaGoggles(raw());
  const st = (r, id) => r.controls.find(c => c.id === id).status;
  assert.deepEqual([st(plus, 'GWS.COMMONCONTROLS.2.1v1'), st(plus, 'GWS.COMMONCONTROLS.18.1v1')], ['deviation', 'deviation'], 'on Enterprise Plus, the edition the baselines assume, a missing feature is a deviation');
  assert.deepEqual([st(biz, 'GWS.COMMONCONTROLS.2.1v1'), st(biz, 'GWS.COMMONCONTROLS.18.1v1')], ['license-dependent', 'license-dependent'], 'Context-Aware Access and DLP are not documented for Business Plus');
  assert.equal(st(unk, 'GWS.COMMONCONTROLS.18.1v1'), 'license-dependent', 'an undeclared edition is never assumed to be Enterprise Plus');
  assert.equal(st(plus, 'GWS.COMMONCONTROLS.1.4v1'), 'no-log-events'); assert.match(plus.controls.find(c => c.id === 'GWS.COMMONCONTROLS.1.4v1').license_note, /six months/);
  assert.equal(st(plus, 'GWS.DRIVEDOCS.1.10v2'), 'manual-check');
  assert.deepEqual(plus.products_assessed, ['commoncontrols', 'gmail', 'drive'], 'products come from the control IDs');
  const s = summarize(biz.controls, biz.products_assessed, PRODUCTS);
  assert.deepEqual([s.shall_deviations, s.license_dependent, s.no_log_events], [2, 2, 1]); assert.ok(s.products_not_assessed.includes('meet'));
  const v = raw(); v.Results.commoncontrols[0].Controls[0]['Control ID'] = 'GWS.CALENDAR.3.2v0.5'; assert.equal(parseScubaGoggles(v).controls[0].policy_version, 0.5, 'decimal policy versions are kept');
  assert.throws(() => parseScubaGoggles({ MetaData: { Tool: 'ScubaGear', ToolVersion: '2.0.0' }, Results: {} }), /not_scubagoggles_results/);
  assert.equal(ACCESS.scopes_read_only.length, 9); assert.deepEqual(ACCESS.scopes_not_read_only, ['apps.licensing', 'apps.groups.settings']);
});

test('Google Workspace is compared with Microsoft 365 per area and a SHALL deviation or regression raises an alert (CG-147)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg147-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'SaaS', stale_seconds: 86400 });
  const run = (script, args) => { const out = path.join(dir, `o-${Math.random()}.json`), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts', script), ...args, '--output', out], { encoding: 'utf8' }); if (r.status === 0) d.ingest('a', src.id, JSON.parse(fs.readFileSync(out, 'utf8'))); return r; };
  assert.equal(run('gws-baseline.js', ['--scubagoggles', FX, '--domain-ref', 'gws-lab', '--authorization-ref', 'SEC-147', '--edition', 'business-plus']).status, 0);
  assert.equal(gwsView(s).domains[0].areas.find(a => a.area === 'mfa').m365.state, 'not-assessed', 'no Microsoft 365 import yet');
  assert.equal(run('m365-baseline.js', ['--scuba', M365, '--tenant-ref', 'tenant-lab', '--authorization-ref', 'SEC-146']).status, 0);
  const areas = Object.fromEntries(gwsView(s).domains[0].areas.map(a => [a.area, [a.gws.state, a.m365.state]]));
  assert.deepEqual(areas.mfa, ['shall-deviation', 'shall-deviation']); assert.deepEqual(areas.mail, ['should-deviation', 'meets']);
  assert.deepEqual(areas.sharing, ['unproven', 'not-assessed'], 'a manual check leaves sharing unproven; SharePoint was not in the Microsoft 365 run');
  assert.deepEqual(compareAreas([]).map(a => a.gws.state), ['not-assessed', 'not-assessed', 'not-assessed', 'not-assessed']);
  assert.deepEqual(s.all("SELECT title FROM alerts WHERE rule_id='CG-GWS-BASELINE-147' ORDER BY title").map(a => a.title.split(': ')[1].split(' ')[0]), ['GWS.COMMONCONTROLS.1.1v1', 'GWS.COMMONCONTROLS.10.4v1'], 'license-dependent controls raise no alert');
  const next = raw(); next.MetaData.ReportUUID = '00000000-0000-4000-8000-000000000149'; next.MetaData.TimestampZulu = '2026-10-30T09:00:00.000Z';
  next.Results.drive[0].Controls[0].Result = 'Fail'; const f2 = path.join(dir, 'next.json'); fs.writeFileSync(f2, JSON.stringify(next));
  assert.equal(run('gws-baseline.js', ['--scubagoggles', f2, '--domain-ref', 'gws-lab', '--authorization-ref', 'SEC-147', '--edition', 'business-plus']).status, 0);
  assert.deepEqual(gwsView(s).domains[0].drift.regressions, ['GWS.DRIVEDOCS.1.1v1']);
  assert.deepEqual(s.all("SELECT severity FROM alerts WHERE rule_id='CG-GWS-DRIFT-147'").map(a => a.severity), ['high']);
  assert.equal(run('gws-baseline.js', ['--scubagoggles', FX, '--domain-ref', 'x', '--authorization-ref', 'y', '--edition', 'premium']).status, 2, 'unknown editions are refused');
});
