import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { assessCompleteness, parseListRegions, completenessView, STATEMENTS } from '../lib/aws-completeness.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), F = n => path.join(ROOT, 'tests/fixtures/aws/regions', n), read = n => JSON.parse(fs.readFileSync(F(n), 'utf8'));

test('every enabled Region of every account is checked for Security Hub CSPM, Config, GuardDuty and CloudTrail and unassessed accounts are never complete (CG-155)', () => {
  const c = assessCompleteness({ inventory: read('inventory.json'), accountsRegions: [parseListRegions(read('list-regions-111122223333.json'), '111122223333'), parseListRegions(read('list-regions-444455556666.json'), '444455556666')], hubs: read('hubs.json'), aggregation: read('aggregation.json') });
  const a = id => c.accounts.find(x => x.account_id === id), r = (id, reg) => a(id).regions.find(x => x.region === reg);
  assert.deepEqual(r('111122223333', 'us-east-1').gaps, []);
  assert.deepEqual(r('111122223333', 'eu-west-1').gaps, ['config']); assert.ok(r('111122223333', 'eu-west-1').notes.some(n => /without AWS Config/.test(n)));
  assert.ok(r('111122223333', 'eu-west-1').notes.some(n => /not linked/.test(n)), 'an unlinked Region keeps its findings');
  assert.deepEqual(r('111122223333', 'me-central-1').gaps, ['security-hub', 'config', 'guardduty', 'cloudtrail'], 'an opt-in Region that was enabled but never inspected is a full gap');
  assert.deepEqual(a('111122223333').disabled_regions, ['af-south-1']);
  assert.equal(r('111122223333', 'eu-west-1').security_hub_since, '2026-10-15T00:00:00Z', 'the enablement date bounds the available history');
  assert.equal(a('444455556666').complete, true); assert.deepEqual(a('444455556666').changing_regions, ['me-central-1 (ENABLING)']);
  assert.deepEqual([a('777788889999').assessed, a('777788889999').complete], [false, false], 'access denied is not assessed, never complete');
  assert.deepEqual(c.summary, { accounts: 3, not_assessed: 1, complete: 1, region_gaps: 2, disabled_regions: 1 });
  assert.ok(STATEMENTS.some(s => /does not retroactively collect/.test(s.text)));
  assert.throws(() => parseListRegions({ Regions: [] }, 'bad'), /not_list_regions_export/);
});

test('Region gaps and unassessed accounts raise alerts from the import joined with the account inventory (CG-155)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg155-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'AWS', stale_seconds: 86400 });
  const asset = { external_id: 'aws-org:o-example', hostname: 'AWS', os_family: 'unknown', device_type: 'unknown', addresses: [] };
  d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'inv-155', kind: 'cloud.account_inventory', observed_at: new Date().toISOString(), asset, details: read('inventory.json') }] });
  const out = path.join(dir, 'r.json'), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/aws-region-completeness.js'), '--organization-ref', 'o-example', '--authorization-ref', 'SEC-155', '--regions', `111122223333=${F('list-regions-111122223333.json')}`, '--regions', `444455556666=${F('list-regions-444455556666.json')}`, '--hubs', F('hubs.json'), '--aggregation', F('aggregation.json'), '--output', out], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr); d.ingest('a', src.id, JSON.parse(fs.readFileSync(out, 'utf8')));
  const titles = s.all("SELECT title,severity FROM alerts WHERE rule_id='CG-AWS-REGION-GAP-155'").map(x => `${x.severity}:${x.title.split(' / ')[0]}`).sort();
  assert.deepEqual(titles, ['high:AWS 111122223333 me-central-1: enabled Region without security-hub, config, guardduty, cloudtrail', 'medium:AWS 111122223333 eu-west-1: enabled Region without config', 'medium:AWS account 777788889999 not assessed (access denied)']);
  assert.equal(completenessView(s).summary.complete, 1);
});
