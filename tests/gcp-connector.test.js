import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { normalizeLogLines } from '../lib/log-normalizer.js';
import { analyseRuleset } from '../lib/firewall-analyzer.js';
import { projects, gcpServiceStatus, sccFindings, iamSnapshot, publicBindingFindings, vpcFirewallRules, cloudArmorRules, logEntryLines } from '../lib/connectors/gcp.js';

const dir = fileURLToPath(new URL('./fixtures/gcp/', import.meta.url)), fx = n => fs.readFileSync(path.join(dir, n), 'utf8'), j = n => JSON.parse(fx(n));
const PROD = 'example-prod-1234', DEV = 'example-dev-5678', LOCK = 'example-finance-9012', OLD = 'example-oldlab-3456';

test('Google Cloud converters read projects, SCC, IAM and service state without guessing (CG-048)', () => {
  const access = j('access.json'), accounts = projects(fx('projects.json')).map(a => ({ ...a, access: access[a.account_id] || a.access }));
  assert.equal(accounts.find(a => a.account_id === OLD).status, 'pending-closure');
  const rows = gcpServiceStatus({ accounts, enabledApis: j('apis.json'), subnets: j('subnets.json'), firewalls: j('firewalls-by-project.json'), armor: j('armor-by-project.json'), iam: j('iam-by-project.json'), scc: 'enabled' });
  const st = (p, s, r) => rows.filter(x => x.account_id === p && x.service === s && (!r || x.region === r)).map(x => x.status);
  assert.deepEqual([st(PROD, 'asset-inventory')[0], st(DEV, 'asset-inventory')[0]], ['enabled', 'disabled']);
  assert.deepEqual([st(PROD, 'vpc-flow-logs', 'europe-west1')[0], st(PROD, 'vpc-flow-logs', 'me-central1')[0]], ['enabled', 'disabled'], 'a region with one subnet without flow logs is not covered');
  assert.deepEqual([st(PROD, 'cloud-audit-logs')[0], st(DEV, 'cloud-audit-logs')[0]], ['enabled', 'disabled']);
  assert.match(rows.find(r => r.account_id === DEV && r.service === 'cloud-audit-logs').detail, /Admin Activity only/);
  assert.deepEqual([st(PROD, 'firewall-rules-logging')[0], st(DEV, 'cloud-armor')[0]], ['disabled', 'disabled']);
  assert.equal(rows.filter(r => [LOCK, OLD].includes(r.account_id)).length, 0, 'unreadable or closing projects get no service rows');
  const scc = sccFindings(fx('scc-findings.json'));
  assert.deepEqual(scc.map(f => [f.title, f.severity, f.status]), [['PUBLIC_BUCKET_ACL', 'high', 'active'], ['OPEN_SSH_PORT', 'high', 'active'], ['Malware: Bad Domain', 'critical', 'active'], ['OPEN_RDP_PORT', 'high', 'resolved'], ['PUBLIC_IP_ADDRESS', 'medium', 'suppressed']]);
  assert.deepEqual(scc[0].types, ['MISCONFIGURATION', 'cis 2.0']);
  const iam = iamSnapshot(fx('iam-policy.json'), PROD);
  assert.equal(iam.details.directory.type, 'gcp-iam'); assert.equal(iam.details.connector.read_only, true);
  assert.deepEqual(iam.details.principals.filter(p => p.privileged).map(p => p.principal_ref).sort(), ['group:platform@example.com', 'serviceAccount:111111111111-compute@developer.gserviceaccount.com', 'user:contractor@example.net', 'user:owner@example.com']);
  assert.ok(iam.details.privileges.some(p => p.privilege === 'roles/iam.serviceAccountTokenCreator if expires 2026-12-31'), 'conditional bindings keep their condition');
  const pub = publicBindingFindings(iam.publicBindings, PROD); assert.equal(pub.length, 1); assert.equal(pub[0].title, 'Public IAM binding: allUsers has roles/storage.objectViewer');
});

test('VPC firewall rules and Cloud Armor policies feed the CG-020 analyzer in GCP evaluation order (CG-048)', () => {
  const fw = vpcFirewallRules(fx('firewall-rules.json')), now = Date.parse('2026-11-18T00:00:00Z');
  assert.deepEqual(fw.rules.map(r => r.name), ['deny-rdp', 'allow-all-legacy', 'egress-block-smtp', 'web-https', 'app-from-web', 'default-allow-ssh', 'implied deny ingress', 'implied allow egress'], 'lowest priority first and deny before allow at equal priority, implied rules last');
  assert.equal(fw.rules.find(r => r.name === 'app-from-web').filters_readable, false, 'source tags are not resolved to addresses');
  assert.deepEqual(fw.rules.find(r => r.name === 'web-https').scope_constraints, ['target tag web']);
  const f = analyseRuleset({ vendor: 'gcp-vpc-firewall', evaluation: 'first-match', rules: fw.rules }, now, null);
  assert.ok(f.findings.some(x => x.type === 'any-any-allow' && x.rule_name === 'allow-all-legacy'), 'an untargeted allow-all from 0.0.0.0/0 applies to every instance in the network');
  assert.ok(f.findings.some(x => x.type === 'broad-admin-exposure' && x.rule_name === 'default-allow-ssh'));
  const armor = cloudArmorRules(fx('armor-policy.json'));
  assert.deepEqual(armor.rules.map(r => [r.action, r.enabled, r.filters_readable]), [['deny', true, true], ['deny', true, false], ['deny', false, false], ['allow', true, false], ['allow', true, true]]);
  assert.equal(armor.rules[3].profile, 'rate-limited'); assert.ok(armor.rules[2].scope_constraints.includes('preview mode: logged, not enforced'));
  const a = analyseRuleset({ vendor: 'gcp-cloud-armor', evaluation: 'first-match', rules: armor.rules }, now, null);
  assert.ok(!a.findings.some(x => x.type === 'any-any-allow'), 'the default allow of a backend security policy is scoped to that backend');
});

test('Cloud Audit Logs, VPC Flow Logs, Firewall Rules Logging and Cloud Armor logs normalise into the common event model (CG-048)', () => {
  const audit = normalizeLogLines('gcp-audit-json', logEntryLines(fx('audit-logs.json'))).records;
  assert.deepEqual(audit.map(r => [r.signature, r.outcome]), [['v1.compute.firewalls.insert', 'success'], ['google.logging.v2.ConfigServiceV2.DeleteSink', 'success'], ['SetIamPolicy', 'failure'], ['v1.compute.instances.start', 'success']]);
  assert.equal(audit[0].user, 'ops@example.com'); assert.equal(audit[0].host, PROD);
  const flow = normalizeLogLines('gcp-vpc-flow-json', logEntryLines(fx('vpc-flow.json'))).records[0];
  assert.deepEqual([flow.src_ip, flow.dst_port, flow.protocol, flow.bytes, flow.host], ['10.10.0.5', 443, 'tcp', 5400, 'web-1']);
  const fw = normalizeLogLines('gcp-firewall-json', logEntryLines(fx('firewall-logs.json'))).records[0];
  assert.deepEqual([fw.action, fw.dst_port, fw.signature], ['allowed', 22, 'network:default/firewall:default-allow-ssh']);
  const waf = normalizeLogLines('gcp-armor-json', logEntryLines(fx('armor-logs.json'))).records[0];
  assert.deepEqual([waf.category, waf.action, waf.signature, waf.src_ip], ['waf', 'blocked', 'owasp-crs-v030301-id942100-sqli', '203.0.113.66']);
});

test('Google Cloud inventory, SCC, IAM and logs raise alerts and show coverage gaps per project and service (CG-048)', t => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cg048-')); t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const script = fileURLToPath(new URL('../scripts/gcp-connector.js', import.meta.url)), F = n => path.join(dir, n);
  const conv = (mode, input, extra = []) => { const out = path.join(tmp, `${mode}.json`); execFileSync(process.execPath, [script, mode, '--input', F(input), '--output', out, ...extra]); return JSON.parse(fs.readFileSync(out, 'utf8')); };
  const s = new Store(':memory:'); t.after(() => s.close());
  const now = Date.now(), d = new Domain(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString());
  const src = d.createSource('admin-a', { name: 'Google Cloud read-only connector', stale_seconds: 86400, source_type: 'generic' }), ingest = file => d.ingest('admin-a', src.id, file);
  ingest(conv('inventory', 'projects.json', ['--apis', F('apis.json'), '--subnets', F('subnets.json'), '--firewalls', F('firewalls-by-project.json'), '--armor', F('armor-by-project.json'), '--iam', F('iam-by-project.json'), '--access', F('access.json'), '--scc', 'enabled', '--organization-id', '123456789012']));
  ingest(conv('scc-findings', 'scc-findings.json')); ingest(conv('iam', 'iam-policy.json', ['--project', PROD]));
  ingest(conv('firewall-rules', 'firewall-rules.json', ['--device-ref', `gcp:${PROD}:default`])); ingest(conv('armor-policy', 'armor-policy.json', ['--device-ref', `gcp:${PROD}:web-edge-policy`]));
  for (const m of ['audit-logs', 'vpc-flow', 'firewall-logs', 'armor-logs']) ingest(conv(m, `${m}.json`));
  const p = d.cloudPosture('gcp');
  assert.equal(p.counts.accounts, 4); assert.equal(p.counts.active_findings, 4, 'three SCC findings and one public IAM binding'); assert.equal(p.counts.critical, 1);
  const prod = p.accounts.find(a => a.account_id === PROD); assert.equal(prod.services['vpc-flow-logs'].status, 'partial'); assert.equal(prod.services.scc.status, 'enabled');
  assert.deepEqual(p.gaps.filter(g => [LOCK, OLD].includes(g.account_id)).map(g => [g.service, g.status]).sort(), [['all', 'access-denied'], ['all', 'suspended']]);
  assert.match(p.gaps.find(g => g.account_id === LOCK).reason, /viewer role binding/);
  const rules = Object.groupBy(d.list('alerts', { limit: 300 }).items, a => a.rule_id);
  assert.equal(rules['CG-CLOUD-FINDING-046'].length, 4);
  assert.ok(rules['CG-CLOUD-FINDING-046'].some(a => /Public IAM binding: allUsers/.test(a.title)));
  const audit = rules['CG-CLOUD-AUDIT-048'].map(a => a.title).join('\n');
  assert.match(audit, /v1.compute.firewalls.insert by ops@example.com/); assert.match(audit, /DeleteSink/); assert.doesNotMatch(audit, /SetIamPolicy/, 'a denied SetIamPolicy is not a successful change');
  assert.ok(rules['CG-FW-ANYANY-018'].some(a => /allow-all-legacy/.test(a.title)));
  assert.ok(rules['CG-WAF-025'].some(a => /942100-sqli/.test(a.title)), 'Cloud Armor blocks reuse the WAF rule');
  assert.equal(d.cloudPosture('aws').counts.accounts, 0); assert.equal(d.cloudPosture('azure').counts.accounts, 0);
});

test('the Google Cloud access list grants viewer and reviewer roles only (CG-048)', () => {
  const r = JSON.parse(fs.readFileSync(new URL('../deploy/gcp/cyberguard-viewer-roles.json', import.meta.url), 'utf8'));
  assert.ok(r.roles.every(x => /viewer|Viewer|Reviewer|roles\/viewer/.test(x.role)), 'every granted role is a viewer or reviewer role');
  for (const bad of ['roles/owner', 'roles/editor']) { assert.ok(!r.roles.some(x => x.role === bad)); assert.ok(r.never_required.includes(bad)); }
});
