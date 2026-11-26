import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { parseAnalyzers, parseFindings, assessAnalyzer, accessAnalyzerView, ANALYSES } from '../lib/access-analyzer.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), D = n => path.join(ROOT, 'tests/fixtures/aws/access-analyzer', n), read = n => JSON.parse(fs.readFileSync(D(n), 'utf8'));

test('external, internal and unused access are separate analyses with their own zone, region scope and price, and an analysis that is not active never reads as no exposure (CG-148)', () => {
  const analyzers = parseAnalyzers(read('list-analyzers-us-east-1.json')), findings = [...parseFindings(read('findings-external-account.json'), 'external-account'), ...parseFindings(read('findings-unused-account.json'), 'unused-account')];
  assert.deepEqual(analyzers.map(a => [a.analysis, a.zone, a.region]), [['external', 'account', 'us-east-1'], ['unused', 'account', 'us-east-1']]);
  const a = assessAnalyzer({ analyzers, findings, regions: ['us-east-1', 'eu-west-1'] }), by = k => a.analyses.find(x => x.analysis === k);
  assert.equal(by('external').state, 'partial'); assert.deepEqual(by('external').regions_missing, ['eu-west-1'], 'external access is regional');
  assert.equal(by('unused').state, 'active'); assert.deepEqual(by('unused').regions_missing, [], 'one unused access analyzer covers the partition');
  assert.equal(by('internal').state, 'not-active'); assert.equal(by('internal').active_findings, null, 'not active is not zero findings'); assert.match(by('internal').note, /paid analysis/);
  assert.equal(by('external').active_findings, 1, 'archived findings are not counted');
  assert.deepEqual([ANALYSES.external.paid, ANALYSES.unused.paid, ANALYSES.internal.paid], [false, true, true]);
  assert.deepEqual(a.counts, { ExternalAccess: 1, UnusedIAMRole: 1, UnusedIAMUserAccessKey: 1, UnusedIAMUserPassword: 0, UnusedPermission: 1, InternalAccess: 0 });
  const org = parseAnalyzers({ analyzers: [{ arn: 'arn:aws:access-analyzer:eu-west-1:111122223333:analyzer/org', name: 'org', type: 'ORGANIZATION', status: 'ACTIVE' }, { arn: 'arn:aws:access-analyzer:eu-west-1:111122223333:analyzer/int', name: 'int', type: 'ORGANIZATION_INTERNAL_ACCESS', status: 'FAILED', statusReason: { code: 'SERVICE_LINKED_ROLE_CREATION_FAILED' } }] });
  const b = assessAnalyzer({ analyzers: [...analyzers, ...org], findings: [], regions: ['us-east-1', 'eu-west-1'] });
  assert.equal(b.analyses.find(x => x.analysis === 'external').state, 'active'); assert.deepEqual(b.zones.sort(), ['account', 'organization']);
  assert.equal(b.analyses.find(x => x.analysis === 'internal').state, 'not-active', 'a failed analyzer is not active'); assert.equal(b.analyses.find(x => x.analysis === 'internal').analyzers_not_active[0].reason, 'SERVICE_LINKED_ROLE_CREATION_FAILED');
  assert.throws(() => parseFindings({ items: [] }, 'x'), /not_list_findings_v2_output/);
});

test('active external access findings and regions without an external analyzer raise alerts while unused access findings do not (CG-148)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg148-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'AWS', stale_seconds: 86400 });
  const run = extra => { const out = path.join(dir, `o-${Math.random()}.json`), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/aws-access-analyzer.js'), '--account-id', '111122223333', '--authorization-ref', 'SEC-148', ...extra, '--output', out], { encoding: 'utf8' }); if (r.status === 0) d.ingest('a', src.id, JSON.parse(fs.readFileSync(out, 'utf8'))); return r; };
  const r = run(['--regions', 'us-east-1,eu-west-1', '--analyzers', D('list-analyzers-us-east-1.json'), '--analyzers', D('list-analyzers-eu-west-1.json'), '--findings', `external-account=${D('findings-external-account.json')}`, '--findings', `unused-account=${D('findings-unused-account.json')}`]);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(s.all("SELECT rule_id FROM alerts WHERE rule_id LIKE 'CG-AWS-%-148' ORDER BY rule_id").map(x => x.rule_id), ['CG-AWS-ANALYZER-GAP-148', 'CG-AWS-EXTERNAL-ACCESS-148'], 'one external finding and one region gap; unused findings raise nothing');
  assert.match(s.get("SELECT title FROM alerts WHERE rule_id='CG-AWS-ANALYZER-GAP-148'").title, /eu-west-1/);
  const v = accessAnalyzerView(s).accounts[0]; assert.equal(v.findings.length, 4, 'only active findings are listed'); assert.deepEqual(v.zones, ['account']);
  assert.equal(run(['--regions', 'us-east-1', '--analyzers', D('list-analyzers-eu-west-1.json')]).status, 0);
  assert.match(s.all("SELECT title FROM alerts WHERE rule_id='CG-AWS-ANALYZER-GAP-148'").map(x => x.title).join('|'), /no active analyzer/, 'no external analyzer at all is a gap');
  assert.equal(run(['--analyzers', D('list-analyzers-us-east-1.json'), '--findings', `missing=${D('findings-external-account.json')}`]).status, 2, 'findings must belong to an exported analyzer');
});
