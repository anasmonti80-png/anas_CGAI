import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { parseSccFindings, assessGcpExposure, gcpExposureView } from '../lib/gcp-attack-exposure.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), FX = path.join(ROOT, 'tests/fixtures/gcp/scc/findings.json'), raw = () => JSON.parse(fs.readFileSync(FX, 'utf8'));

test('SCC attack exposure scores and toxic combinations are used as calculated, and no score is invented when the tier, activation or calculation is missing (CG-154)', () => {
  const findings = parseSccFindings(raw());
  assert.equal(findings.length, 7, 'wrapped list results are unwrapped');
  const a = assessGcpExposure({ findings, tier: 'premium', activation: 'organization', high_value_set: true });
  assert.equal(a.availability.available, true);
  assert.deepEqual(a.counts, { active: 5, scored: 3, toxic: 2, chokepoints: 1 }, 'inactive and muted findings are not counted');
  assert.deepEqual(a.combos.map(c => [c.category, c.risk]), [['TOXIC_COMBINATION_PUBLIC_VM_TO_SENSITIVE_BUCKET', 'critical'], ['TOXIC_COMBINATION_SA_KEY_TO_BQ', 'high'], ['CHOKEPOINT_SHARED_SERVICE_ACCOUNT', 'critical']], 'score 10 or more is critical; chokepoints are critical');
  assert.deepEqual(a.scored.map(f => f.exposure.score), [12.4, 8.7, 6.1]);
  assert.equal(a.unscored[0].exposure, null, 'NOT_CALCULATED stays without a score, never zero'); assert.equal(a.unscored[0].exposure_state, 'NOT_CALCULATED');
  const std = assessGcpExposure({ findings, tier: 'standard', activation: 'organization', high_value_set: true });
  assert.equal(std.availability.available, false); assert.match(std.notes[0].text, /Standard/);
  const proj = assessGcpExposure({ findings: parseSccFindings([{ name: 'x', category: 'PUBLIC_IP_ADDRESS', findingClass: 'MISCONFIGURATION', state: 'ACTIVE' }]), tier: 'premium', activation: 'project', high_value_set: false });
  assert.equal(proj.availability.available, false); assert.equal(proj.scored.length, 0);
  const noSet = assessGcpExposure({ findings, tier: 'enterprise', activation: 'organization', high_value_set: false }); assert.ok(noSet.notes.some(n => /default set/.test(n.text)));
  assert.throws(() => parseSccFindings({ items: [] }), /not_scc_findings_export/);
});

test('active toxic combinations and chokepoints raise alerts and the view shows availability notes (CG-154)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg154-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'GCP', stale_seconds: 86400 });
  const run = extra => { const out = path.join(dir, `o-${Math.random()}.json`), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/gcp-attack-exposure.js'), '--organization-id', '123456789012', '--authorization-ref', 'SEC-154', '--findings', FX, ...extra, '--output', out], { encoding: 'utf8' }); if (r.status === 0) d.ingest('a', src.id, JSON.parse(fs.readFileSync(out, 'utf8'))); return r; };
  assert.equal(run(['--tier', 'premium', '--activation', 'organization', '--high-value-set', 'yes']).status, 0);
  assert.deepEqual(s.all("SELECT severity FROM alerts WHERE rule_id='CG-GCP-TOXIC-154' ORDER BY severity").map(x => x.severity), ['critical', 'critical', 'high']);
  const v = gcpExposureView(s).organizations[0]; assert.equal(v.counts.toxic, 2); assert.equal(v.notes.length, 0);
  assert.equal(run(['--tier', 'gold']).status, 2, 'unknown tiers are refused');
});
