import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { domainOf } from '../lib/cloud-coverage.js';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), FX = p => path.join(ROOT, 'tests', 'fixtures', p);

test('cloud operations are classified into detection domains (CG-104)', () => {
  assert.deepEqual(['iam:CreateAccessKey', 'kms:ScheduleKeyDeletion', 's3:PutBucketPolicy', 'storage.buckets.setIamPolicy', 'ec2:RunInstances', 'cloudtrail:StopLogging', 'microsoft.keyvault/vaults/accesspolicies/write', 'microsoft.authorization/roleassignments/write', 'v1.compute.firewalls.insert', 'something.unknown'].map(domainOf),
    ['identity', 'keys', 'storage', 'storage', 'compute', 'logging', 'keys', 'identity', 'network', null]);
});

test('coverage per provider and domain comes from the sources actually received, and inventoried clouds without audit logs alert (CG-104)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg104-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const run = (script, args) => { const out = path.join(dir, `${script}-${args[0]}-${Math.random().toString(36).slice(2)}.json`); execFileSync(process.execPath, [path.join(ROOT, 'scripts', `${script}.js`), ...args, '--output', out], { stdio: 'pipe' }); return JSON.parse(fs.readFileSync(out, 'utf8')); };
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, { clock: () => Date.now() });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = d.createSource('admin-a', { name: 'Cloud', stale_seconds: 86400 }), ingest = b => d.ingest('admin-a', src.id, b);
  ingest(run('aws-connector', ['inventory', '--input', FX('aws/list-accounts.json'), '--services', FX('aws/services.json'), '--access', FX('aws/access.json')]));
  ingest(run('aws-connector', ['cloudtrail', '--input', FX('aws/cloudtrail.json')])); ingest(run('aws-connector', ['findings-guardduty', '--input', FX('aws/guardduty-findings.json')])); ingest(run('aws-connector', ['vpc-flow', '--input', FX('aws/vpc-flow.txt')]));
  ingest(run('gcp-connector', ['inventory', '--input', FX('gcp/projects.json'), '--subnets', FX('gcp/subnets.json'), '--access', FX('gcp/access.json'), '--scc', 'enabled']));
  const c = d.cloudDetectionCoverage(), aws = c.coverage.aws, dom = n => aws.domains.find(x => x.domain === n);
  assert.ok(aws.sources.audit_log > 0 && aws.sources.threat_findings > 0 && aws.sources.flow_logs > 0, JSON.stringify(aws.sources));
  assert.ok(aws.domains.some(x => x.state === 'covered')); assert.equal(dom('storage').state, 'control-plane-only'); assert.equal(dom('identity').state, 'covered'); assert.ok(dom('identity').provider_findings >= 1, 'GuardDuty finding counted'); assert.match(dom('storage').note, /data events/);
  assert.ok(dom('identity').cyberguard_rules > 0 && dom('logging').cyberguard_rules > 0);
  assert.ok(c.coverage.gcp.domains.every(x => x.state === 'blind')); assert.ok(c.coverage.azure.domains.every(x => x.state === 'blind'));
  assert.deepEqual(c.inventoried_providers.sort(), ['aws', 'gcp']);
  const alert = s.get("SELECT severity,title FROM alerts WHERE rule_id='CG-CLOUD-COVERAGE-104'"); assert.equal(alert.severity, 'high'); assert.match(alert.title, /GCP/);
  assert.equal(s.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-CLOUD-COVERAGE-104'").n, 1, 'AWS has an audit log so only GCP is blind'); assert.ok(c.claim_ar.includes('مستوى التحكم فقط'));
});
