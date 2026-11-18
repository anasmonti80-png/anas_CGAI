import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { awsResources, azureResources, gcpResources, categoryOf, serviceCharges } from '../lib/cloud-inventory.js';
import { awsServices } from '../lib/connectors/aws.js';
import { azureServices } from '../lib/connectors/azure.js';
import { gcpServices } from '../lib/connectors/gcp.js';

const fixtures = fileURLToPath(new URL('./fixtures/', import.meta.url)), fx = (d, n) => fs.readFileSync(path.join(fixtures, d, n), 'utf8');

test('AWS Resource Explorer, Azure Resource Graph and Cloud Asset Inventory become one categorised inventory (CG-050)', () => {
  const aws = awsResources(fx('cloud-inventory', 'aws-resources.json'));
  assert.deepEqual(aws.map(r => [r.region, r.category]), [['us-east-1', 'compute'], ['us-east-1', 'network'], ['us-east-1', 'storage'], ['eu-west-1', 'database'], ['eu-west-1', 'serverless'], ['ap-south-1', 'compute'], ['global', 'identity']]);
  assert.equal(aws[0].name, 'web-1'); assert.deepEqual(aws[0].tags, { Name: 'web-1', env: 'prod' });
  const az = azureResources(fx('cloud-inventory', 'azure-resources.json'));
  assert.deepEqual(az.map(r => r.category), ['compute', 'network', 'storage', 'database', 'container', 'compute', 'identity']);
  assert.deepEqual(az.map(r => r.public), [null, true, true, false, null, null, null], 'public exposure is taken only from what Resource Graph states');
  const gcp = gcpResources(fx('cloud-inventory', 'gcp-resources.json'), { 111111111111: 'example-prod-1234' });
  assert.deepEqual(gcp.map(r => [r.account_id, r.category]), [['example-prod-1234', 'compute'], ['example-prod-1234', 'storage'], ['example-prod-1234', 'network'], ['example-prod-1234', 'database'], ['example-prod-1234', 'container'], ['example-prod-1234', 'identity']]);
  assert.equal(categoryOf('something.unknown/Thing'), 'other');
  for (const [p, list] of [['aws', awsServices], ['azure', azureServices], ['gcp', gcpServices]]) for (const s of list) { const c = serviceCharges[p][s]; assert.ok(c && ['yes', 'no', 'partial'].includes(c.billed) && c.ar && c.en && /^https:\/\/(aws\.amazon\.com|azure\.microsoft\.com|learn\.microsoft\.com|www\.microsoft\.com|cloud\.google\.com)\//.test(c.url), `${p} ${s} has a charge model and an official pricing page`); }
});

test('the unified view joins inventory, alerts, policies, access and gaps across providers, accounts and regions (CG-050)', t => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cg050-')); t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const run = (script, mode, extra) => { const out = path.join(tmp, `${script}-${mode}-${Math.random().toString(36).slice(2)}.json`); execFileSync(process.execPath, [fileURLToPath(new URL(`../scripts/${script}.js`, import.meta.url)), mode, ...extra, '--output', out]); return JSON.parse(fs.readFileSync(out, 'utf8')); };
  const F = (d, n) => path.join(fixtures, d, n);
  const s = new Store(':memory:'); t.after(() => s.close());
  const d = new Domain(s, { clock: () => Date.now() });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = d.createSource('admin-a', { name: 'Cloud connectors', stale_seconds: 86400, source_type: 'generic' }), ingest = f => d.ingest('admin-a', src.id, f);
  ingest(run('aws-connector', 'inventory', ['--input', F('aws', 'list-accounts.json'), '--services', F('aws', 'services.json'), '--access', F('aws', 'access.json')]));
  ingest(run('aws-connector', 'resources', ['--input', F('cloud-inventory', 'aws-resources.json')]));
  ingest(run('aws-connector', 'findings-asff', ['--input', F('aws', 'securityhub-findings.json')]));
  ingest(run('aws-connector', 'security-groups', ['--input', F('aws', 'security-groups.json'), '--device-ref', 'aws:444455556666:vpc-0abc1230001']));
  ingest(run('azure-connector', 'inventory', ['--input', F('azure', 'subscriptions.json'), '--graph', F('azure', 'resource-graph.json'), '--pricings', F('azure', 'pricings.json'), '--diagnostics', F('azure', 'diagnostics.json'), '--sentinel', F('azure', 'sentinel.json'), '--access', F('azure', 'access.json'), '--entra', 'enabled']));
  ingest(run('azure-connector', 'resources', ['--input', F('cloud-inventory', 'azure-resources.json')]));
  ingest(run('azure-connector', 'firewall-policy', ['--input', F('azure', 'firewall-policy.json'), '--device-ref', 'azure:prod:hub-policy']));
  ingest(run('gcp-connector', 'inventory', ['--input', F('gcp', 'projects.json'), '--apis', F('gcp', 'apis.json'), '--subnets', F('gcp', 'subnets.json'), '--firewalls', F('gcp', 'firewalls-by-project.json'), '--armor', F('gcp', 'armor-by-project.json'), '--iam', F('gcp', 'iam-by-project.json'), '--access', F('gcp', 'access.json'), '--scc', 'enabled']));
  ingest(run('gcp-connector', 'resources', ['--input', F('cloud-inventory', 'gcp-resources.json'), '--projects', F('gcp', 'projects.json')]));
  ingest(run('cloud-access-review', 'aws-root', ['--summary', F('cloud-access', 'aws-account-summary.json'), '--account', '444455556666']));
  const u = d.cloudUnified(), by = Object.fromEntries(u.summary.map(x => [x.provider, x]));
  assert.deepEqual([by.aws.resources, by.azure.resources, by.gcp.resources], [7, 7, 6]);
  assert.deepEqual([by.aws.regions, by.azure.regions, by.gcp.regions], [4, 2, 4], 'GCP zones roll up to their region'); assert.equal(by.azure.public, 2);
  assert.deepEqual(u.by_category.compute, { aws: 2, azure: 2, gcp: 1 });
  const gaps = u.region_gaps.map(g => `${g.provider}:${g.region}:${g.service}:${g.status}`);
  assert.ok(gaps.includes('aws:ap-south-1:cloudtrail:not-checked'), 'a region holding resources that was never checked is a gap');
  assert.ok(gaps.includes('aws:eu-west-1:vpc-flow-logs:not-checked')); assert.ok(!gaps.some(g => g.startsWith('aws:us-east-1:')), 'us-east-1 has CloudTrail and flow logs enabled');
  assert.ok(gaps.includes('azure:uaenorth:network-watcher:disabled')); assert.ok(gaps.includes('gcp:me-central1:vpc-flow-logs:disabled')); assert.ok(!gaps.some(g => g.startsWith('gcp:europe-west1:')), 'a zone inside a covered region is covered'); assert.ok(gaps.includes('gcp:us-central1:vpc-flow-logs:not-checked'));
  assert.ok(!gaps.some(g => g.includes(':global:')), 'global resources are not regional gaps');
  const alerts = Object.fromEntries(u.alerts.map(a => [a.provider, a]));
  assert.equal(alerts.aws.by_rule['CG-CLOUD-FINDING-046'], 3, 'the three high or critical active Security Hub findings'); assert.ok(alerts.aws.by_rule['CG-CLOUD-ACCESS-049'] === 1); assert.ok(alerts.azure.by_rule['CG-FW-ANYANY-018'] === 1);
  const pol = Object.fromEntries(u.policies.map(p => [p.provider, p])); assert.deepEqual([pol.aws.rulesets, pol.azure.rulesets, pol.gcp.rulesets], [1, 1, 0]); assert.ok(pol.aws.by_type['broad-admin-exposure'] >= 2);
  assert.equal(u.access.find(a => a.provider === 'aws').violation, 1);
  const gd = u.charges.find(c => c.provider === 'aws' && c.service === 'guardduty'); assert.deepEqual([gd.billed, gd.enabled_in, gd.accounts], ['yes', 2, 4]);
  assert.equal(u.charges.length, awsServices.length + azureServices.length + gcpServices.length);
});
