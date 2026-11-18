import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { normalizeLogLines } from '../lib/log-normalizer.js';
import { analyseRuleset } from '../lib/firewall-analyzer.js';
import { organizationsAccounts, asffFindings, guarddutyFindings, securityGroupRules, cloudtrailLines, eventBridgeEnvelopes, probeError } from '../lib/connectors/aws.js';

const fx = name => fs.readFileSync(new URL(`./fixtures/aws/${name}`, import.meta.url), 'utf8');
const PROD = '444455556666', DEV = '777788889999';

test('AWS converters read Organizations, ASFF, GuardDuty, security groups and EventBridge without guessing (CG-046)', () => {
  const accounts = organizationsAccounts(fx('list-accounts.json'));
  assert.equal(accounts.length, 4); assert.equal(accounts.find(a => a.name === 'Retired sandbox').status, 'suspended');
  assert.ok(accounts.every(a => a.access === 'not-attempted'), 'access is never assumed without a real assume-role result');
  const asff = asffFindings(fx('securityhub-findings.json')), by = Object.fromEntries(asff.map(f => [f.product + ':' + f.severity + ':' + f.status, f]));
  assert.deepEqual(asff.map(f => f.product).sort(), ['config', 'guardduty', 'inspector', 'security-hub', 'security-hub']);
  assert.equal(by['security-hub:critical:active'].compliance, 'failed');
  assert.equal(asff.find(f => f.account_id === DEV && f.product === 'security-hub').status, 'resolved', 'a PASSED control is not an active finding');
  assert.equal(asff.find(f => f.product === 'config').status, 'suppressed');
  const gd = guarddutyFindings(fx('guardduty-findings.json'));
  assert.deepEqual(gd.map(f => [f.severity, f.status]), [['high', 'active'], ['low', 'resolved']]);
  assert.equal(gd[0].resource_id, 'access-key:GeneratedFindingUserName');
  const sg = securityGroupRules(fx('security-groups.json'));
  assert.equal(sg.vendor, 'aws-security-group'); assert.equal(sg.unreadable, 1, 'a rule that references another security group is not evaluated as any');
  const ssh = sg.rules.find(r => r.dst_ports[0] === '22'); assert.deepEqual([ssh.src, ssh.direction, ssh.protocol], [['any'], 'in', 'tcp']);
  const result = analyseRuleset({ vendor: 'aws-security-group', evaluation: 'first-match', rules: sg.rules }, Date.parse('2026-11-18T00:00:00Z'), null);
  assert.deepEqual(result.findings.filter(f => f.type === 'broad-admin-exposure').map(f => f.rule_name.split(' ')[0]).sort(), ['bastion', 'legacy-open'], 'SSH and all traffic from 0.0.0.0/0 are flagged by the CG-020 analyzer');
  assert.ok(!result.findings.some(f => f.type === 'any-any-allow'), 'a security group only reaches its member interfaces, so it is scoped, never any-to-any');
  assert.ok(!result.findings.some(f => f.type === 'duplicate'), 'the IPv4 and IPv6 any ranges of one permission become one rule');
  const eb = eventBridgeEnvelopes(fx('eventbridge.jsonl'));
  assert.equal(eb.findings[0].product, 'guardduty'); assert.equal(eb.cloudtrail.length, 1); assert.match(eb.unsupported[0].reason, /EC2 Instance State-change/);
  assert.equal(probeError('An error occurred (AccessDeniedException) when calling the DescribeHub operation'), 'access-denied');
  assert.equal(probeError('An error occurred (InvalidAccessException): Account 444455556666 is not subscribed to AWS Security Hub'), 'disabled');
  assert.throws(() => asffFindings({ nope: [] }), /ASFF/);
});

test('CloudTrail, VPC Flow Logs and Network Firewall logs normalise into the common event model (CG-046)', () => {
  const ct = normalizeLogLines('aws-cloudtrail-json', cloudtrailLines(fx('cloudtrail.json'))).records;
  assert.equal(ct.length, 9); assert.equal(ct[1].signature, 'cloudtrail:StopLogging'); assert.equal(ct[2].outcome, 'failure'); assert.equal(ct[3].user, 'root');
  assert.equal(ct.filter(r => r.action === 'ConsoleLogin' && r.outcome === 'failure').length, 5);
  const flow = normalizeLogLines('aws-vpc-flow', fx('vpc-flow.log').split('\n'));
  assert.equal(flow.records.length, 3); assert.equal(flow.rejected.length, 1, 'NODATA lines are rejected, not invented');
  assert.deepEqual([flow.records[0].dst_port, flow.records[0].protocol, flow.records[0].action], [22, 'tcp', 'allowed']); assert.equal(flow.records[1].action, 'blocked'); assert.equal(flow.records[0].time, '2026-11-17T08:00:00.000Z');
  const nfw = normalizeLogLines('aws-network-firewall-json', fx('network-firewall.jsonl').split('\n')).records;
  assert.deepEqual(nfw.map(r => r.category), ['ids', 'flow']); assert.equal(nfw[0].severity, 1); assert.equal(nfw[0].time, '2026-11-17T09:05:00.711Z');
});

test('AWS inventory, findings and logs raise cloud alerts and show coverage gaps per account and service (CG-046)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg046-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const F = new URL('./fixtures/aws/', import.meta.url), f = n => path.join(F.pathname.replace(/^\/([A-Za-z]:)/, '$1'), n), script = new URL('../scripts/aws-connector.js', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
  const conv = (mode, input, extra = []) => { const out = path.join(dir, `${mode}.json`); execFileSync(process.execPath, [script, mode, '--input', f(input), '--output', out, ...extra]); return JSON.parse(fs.readFileSync(out, 'utf8')); };
  const s = new Store(':memory:'); t.after(() => s.close());
  const now = Date.now(), d = new Domain(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString());
  const src = d.createSource('admin-a', { name: 'AWS read-only connector', stale_seconds: 86400, source_type: 'generic' });
  const ingest = file => d.ingest('admin-a', src.id, file);
  ingest(conv('inventory', 'list-accounts.json', ['--services', f('services.json'), '--access', f('access.json')]));
  for (const [mode, input] of [['findings-asff', 'securityhub-findings.json'], ['findings-guardduty', 'guardduty-findings.json'], ['cloudtrail', 'cloudtrail.json'], ['vpc-flow', 'vpc-flow.log'], ['network-firewall', 'network-firewall.jsonl'], ['eventbridge', 'eventbridge.jsonl']]) ingest(conv(mode, input));
  ingest(conv('security-groups', 'security-groups.json', ['--device-ref', `aws:${PROD}:vpc-0abc1230001`]));
  const p = d.cloudPosture();
  assert.equal(p.counts.accounts, 4); assert.equal(p.counts.active_findings, 5); assert.equal(p.counts.critical, 2);
  const prod = p.accounts.find(a => a.account_id === PROD);
  assert.equal(prod.access, 'assumed'); assert.equal(prod.services.guardduty.status, 'partial'); assert.equal(prod.services.inspector.status, 'access-denied'); assert.equal(prod.services.eventbridge.status, 'disabled');
  assert.ok(p.gaps.some(g => g.account_id === DEV && g.service === 'all' && g.status === 'access-denied'), 'a refused read-only role is a gap, not coverage');
  assert.ok(p.gaps.every(g => g.reason_ar), 'every gap has an Arabic reason');
  assert.deepEqual(p.gaps.filter(g => g.account_id === '123456789012').map(g => [g.service, g.status]), [['all', 'suspended']], 'a suspended account is one gap, not nine unchecked services');
  const rules = Object.groupBy(d.list('alerts', { limit: 200 }).items, a => a.rule_id);
  assert.equal(rules['CG-CLOUD-FINDING-046'].length, 5, 'high and critical active findings from Security Hub, GuardDuty and EventBridge');
  assert.ok(rules['CG-CLOUD-GAP-046'].some(a => /guardduty disabled/.test(a.title)) && rules['CG-CLOUD-GAP-046'].some(a => /777788889999/.test(a.title)));
  const trail = rules['CG-CLOUD-TRAIL-046'].map(a => a.title).join('\n');
  assert.match(trail, /cloudtrail:StopLogging/); assert.match(trail, /by root/); assert.match(trail, /ec2:AuthorizeSecurityGroupIngress/); assert.match(trail, /svc-report/);
  assert.doesNotMatch(trail, /DeleteDetector/, 'a denied DeleteDetector call is not reported as a successful change');
  assert.ok(rules['CG-LOG-IDS-014'].some(a => /onion/.test(a.title)), 'Network Firewall alerts reuse the IDS rule');
});

test('the AWS read-only role template grants SecurityAudit only, denies writes and limits sessions to one hour (CG-046)', () => {
  const y = fs.readFileSync(new URL('../deploy/aws/cyberguard-readonly-role.yaml', import.meta.url), 'utf8');
  assert.match(y, /MaxSessionDuration: 3600/); assert.match(y, /sts:ExternalId/); assert.match(y, /policy\/SecurityAudit/);
  assert.doesNotMatch(y, /AdministratorAccess|PowerUserAccess|ReadOnlyAccess/);
  const allow = y.split('- Effect: Deny')[0].split('- Effect: Allow').slice(2).join('');
  assert.ok(allow.split('\n').filter(l => /^\s+- [a-z0-9-]+:/.test(l)).every(l => /:(Get|List|Describe|BatchGet)/.test(l)), 'every inline allow is a read action');
  for (const w of ['cloudtrail:Stop*', 'guardduty:Delete*', 'ec2:Authorize*', 'iam:Create*', 'organizations:Leave*']) assert.ok(y.includes(`- ${w}`), `${w} is explicitly denied`);
});
