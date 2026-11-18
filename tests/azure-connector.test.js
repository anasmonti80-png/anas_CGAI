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
import { detailAr } from '../lib/i18n-ar.js';
import { analyseRuleset } from '../lib/firewall-analyzer.js';
import { subscriptions, azureServiceStatus, defenderAlerts, defenderAssessments, sentinelIncidents, entraSignins, entraDirectoryAudits, nsgRules, azureFirewallPolicyRules, vnetFlowLines } from '../lib/connectors/azure.js';

const dir = fileURLToPath(new URL('./fixtures/azure/', import.meta.url)), fx = n => fs.readFileSync(path.join(dir, n), 'utf8'), j = n => JSON.parse(fx(n));
const PROD = '11111111-1111-4111-8111-111111111111', DEV = '22222222-2222-4222-8222-222222222222', LOCK = '44444444-4444-4444-8444-444444444444', OLD = '33333333-3333-4333-8333-333333333333', DIR = 'entra:72f988bf-0000-4000-8000-00000000c0de';

test('Azure converters read subscriptions, Resource Graph, Defender, Sentinel and Entra without guessing (CG-047)', () => {
  const subs = subscriptions(fx('subscriptions.json')), access = j('access.json'), accounts = subs.map(a => ({ ...a, access: access[a.account_id] || a.access }));
  assert.equal(subs.find(s => s.account_id === OLD).status, 'suspended');
  const rows = azureServiceStatus({ accounts, graph: j('resource-graph.json').data, pricings: j('pricings.json'), diagnostics: j('diagnostics.json'), sentinel: j('sentinel.json'), entra: 'enabled' });
  const st = (sub, svc, region) => rows.filter(r => r.account_id === sub && r.service === svc && (!region || r.region === region)).map(r => r.status);
  assert.deepEqual(st(PROD, 'vnet-flow-logs'), ['enabled']); assert.deepEqual(st(DEV, 'vnet-flow-logs'), ['disabled']);
  assert.match(rows.find(r => r.account_id === DEV && r.service === 'vnet-flow-logs').detail, /only 1 NSG flow log.*2027-09-30/, 'NSG flow logs alone are reported as retiring (CG-051)');
  assert.deepEqual(st(PROD, 'network-watcher', 'westeurope'), ['enabled']); assert.deepEqual(st(PROD, 'network-watcher', 'uaenorth'), ['disabled'], 'a region with VNets but no Network Watcher is a gap');
  assert.deepEqual([st(PROD, 'defender-for-cloud')[0], st(DEV, 'defender-for-cloud')[0], st(DEV, 'azure-monitor')[0], st(DEV, 'sentinel')[0], st(DEV, 'azure-firewall')[0]], ['enabled', 'disabled', 'disabled', 'disabled', 'disabled']);
  assert.equal(rows.filter(r => r.account_id === LOCK || r.account_id === OLD).length, 0, 'unreadable or disabled subscriptions get no service rows, so nothing looks covered');
  const alerts = defenderAlerts(fx('defender-alerts.json'));
  assert.deepEqual(alerts.map(a => [a.severity, a.status, a.account_id]), [['high', 'active', PROD], ['medium', 'suppressed', PROD]]);
  const recs = defenderAssessments(fx('defender-assessments.json')); assert.deepEqual(recs.map(r => [r.status, r.compliance]), [['active', 'failed'], ['resolved', 'passed']]);
  const inc = sentinelIncidents(fx('sentinel-incidents.json')); assert.equal(inc[0].title, '#3177 Multi-stage attack involving password spray and mailbox rule'); assert.deepEqual(inc[0].types, ['CredentialAccess', 'Persistence']); assert.equal(inc[1].status, 'resolved');
  const si = entraSignins(fx('entra-signins.json'), DIR); assert.equal(si.signins.length, 13); assert.equal(si.signins.filter(s => s.result === 'failure').length, 12); assert.equal(si.signins.at(-1).mfa, 'satisfied');
  const au = entraDirectoryAudits(fx('entra-audits.json'), DIR); assert.deepEqual(au.changes.map(c => [c.setting, c.action]), [['conditional-access', 'modified'], ['federation', 'modified']]); assert.equal(au.skipped, 1);
  assert.match(au.changes[0].after_summary, /disabled/);
  assert.equal(detailAr('modified by admin@contoso.example without authorization reference'), 'عُدّل بواسطة admin@contoso.example دون مرجع تفويض', 'the identity-provider change action is shown in Arabic');
});

test('NSG and Azure Firewall policies feed the CG-020 analyzer with ASGs, service tags and IP groups left unevaluated (CG-047)', () => {
  const nsg = nsgRules(fx('nsg.json')), now = Date.parse('2026-11-18T00:00:00Z');
  assert.equal(nsg.vendor, 'azure-nsg'); assert.ok(nsg.rules.find(r => r.name.endsWith('DenyAllInBound')), 'default rules are included');
  assert.deepEqual(nsg.rules.filter(r => !r.filters_readable).map(r => r.name.split(' ')[1]).sort(), ['AllowAzureLoadBalancerInBound', 'AllowVnetInBound', 'allow-https-asg']);
  const rdp = nsg.rules.find(r => r.name.endsWith('allow-rdp-internet')); assert.deepEqual([rdp.src, rdp.dst_ports, rdp.position], [['any'], ['3389'], 100]);
  const n = analyseRuleset({ vendor: 'azure-nsg', evaluation: 'first-match', rules: nsg.rules }, now, null);
  assert.ok(n.findings.some(f => f.type === 'broad-admin-exposure' && f.rule_name.includes('allow-rdp-internet')), 'RDP from Internet is flagged');
  const fw = azureFirewallPolicyRules(fx('firewall-policy.json'));
  assert.deepEqual(fw.rules.map(r => r.name), ['allow-dns dns-out', 'temp-any any-any', 'ipgroup block-partners', 'web windows-update'], 'rule collection groups then collections in priority order');
  assert.equal(fw.rules[2].filters_readable, false); assert.equal(fw.rules[3].application, 'WindowsUpdate');
  const f = analyseRuleset({ vendor: 'azure-firewall', evaluation: 'first-match', rules: fw.rules }, now, null);
  assert.ok(f.findings.some(x => x.type === 'any-any-allow' && x.rule_name === 'temp-any any-any'), 'a policy allow any-any is critical, since the firewall filters everything routed through it');
});

test('Activity log, VNet flow logs and Azure Firewall logs normalise into the common event model (CG-047)', () => {
  const act = normalizeLogLines('azure-activity-json', j('activity.json').records.map(r => JSON.stringify(r))).records;
  assert.deepEqual(act.map(r => [r.signature, r.outcome]), [['microsoft.network/networksecuritygroups/securityrules/write', 'success'], ['microsoft.insights/diagnosticsettings/delete', 'success'], ['microsoft.authorization/roleassignments/write', 'failure'], ['microsoft.compute/virtualmachines/start/action', 'success']]);
  assert.equal(act[0].user, 'ops@contoso.example'); assert.equal(act[0].host, PROD);
  const flow = normalizeLogLines('azure-vnet-flow-json', vnetFlowLines(fx('vnet-flow.json'))).records;
  assert.deepEqual(flow.map(r => [r.action, r.dst_port, r.outcome]), [['allowed', 443, 'begin'], ['allowed', 443, 'end'], ['blocked', 445, 'denied']]);
  assert.equal(flow[1].bytes, 2347); assert.equal(flow[2].src_ip, '203.0.113.77'); assert.equal(flow[2].time, '2026-11-17T08:11:40.000Z');
  const fw = normalizeLogLines('azure-firewall-json', j('firewall-logs.json').records.map(r => JSON.stringify(r))).records;
  assert.deepEqual(fw.map(r => [r.category, r.action]), [['firewall', 'allowed'], ['ids', 'blocked'], ['firewall', 'blocked']]); assert.equal(fw[1].severity, 1); assert.equal(fw[2].query, 'example.org');
});

test('Azure inventory, findings, Entra and logs raise alerts and show coverage gaps per subscription and service (CG-047)', t => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cg047-')); t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const script = fileURLToPath(new URL('../scripts/azure-connector.js', import.meta.url)), F = n => path.join(dir, n);
  const conv = (mode, input, extra = []) => { const out = path.join(tmp, `${mode}.json`); execFileSync(process.execPath, [script, mode, '--input', F(input), '--output', out, ...extra]); return JSON.parse(fs.readFileSync(out, 'utf8')); };
  const s = new Store(':memory:'); t.after(() => s.close());
  const now = Date.now(), d = new Domain(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString());
  const src = d.createSource('admin-a', { name: 'Azure read-only connector', stale_seconds: 86400, source_type: 'generic' }), ingest = file => d.ingest('admin-a', src.id, file);
  ingest(conv('inventory', 'subscriptions.json', ['--graph', F('resource-graph.json'), '--pricings', F('pricings.json'), '--diagnostics', F('diagnostics.json'), '--sentinel', F('sentinel.json'), '--access', F('access.json'), '--entra', 'enabled', '--tenant-id', '72f988bf-0000-4000-8000-00000000c0de']));
  for (const m of ['defender-alerts', 'defender-assessments', 'sentinel-incidents', 'activity', 'vnet-flow', 'firewall-logs']) ingest(conv(m, `${m}.json`));
  ingest(conv('entra-signins', 'entra-signins.json', ['--directory-ref', DIR])); ingest(conv('entra-audits', 'entra-audits.json', ['--directory-ref', DIR]));
  ingest(conv('nsg', 'nsg.json', ['--device-ref', 'azure:prod:web-nsg'])); ingest(conv('firewall-policy', 'firewall-policy.json', ['--device-ref', 'azure:prod:hub-policy']));
  const p = d.cloudPosture('azure');
  assert.equal(p.provider, 'azure'); assert.equal(p.counts.accounts, 4); assert.equal(p.counts.active_findings, 3); assert.equal(p.counts.high, 3);
  assert.deepEqual(p.services, ['resource-graph', 'entra-logs', 'defender-for-cloud', 'sentinel', 'azure-monitor', 'vnet-flow-logs', 'azure-firewall', 'nsg', 'network-watcher']);
  const prod = p.accounts.find(a => a.account_id === PROD); assert.equal(prod.services['network-watcher'].status, 'partial'); assert.equal(prod.services['vnet-flow-logs'].status, 'enabled');
  assert.deepEqual(p.gaps.filter(g => [LOCK, OLD].includes(g.account_id)).map(g => [g.service, g.status]).sort(), [['all', 'access-denied'], ['all', 'suspended']]);
  assert.match(p.gaps.find(g => g.account_id === LOCK).reason, /reader role assignment/);
  assert.equal(p.gaps.find(g => g.account_id === DEV && g.service === 'vnet-flow-logs').reason, 'nsg-flow-logs-only', 'a subscription with NSG flow logs only is told to move to VNet flow logs');
  assert.equal(p.findings.find(f => f.product === 'defender-for-cloud' && f.types[0] === 'VM_SuspiciousCommandLineExecution').resource_type, 'Microsoft.Compute/virtualMachines');
  assert.equal(d.cloudPosture('aws').counts.accounts, 0, 'providers are kept apart');
  const rules = Object.groupBy(d.list('alerts', { limit: 300 }).items, a => a.rule_id);
  assert.equal(rules['CG-CLOUD-FINDING-046'].length, 3, 'Defender alert, Defender recommendation and Sentinel incident');
  const gaps = rules['CG-CLOUD-GAP-046'].map(a => a.title).join('\n');
  assert.match(gaps, /defender-for-cloud disabled in 22222222/); assert.match(gaps, /azure-monitor disabled in 22222222/); assert.match(gaps, /reader role assignment missing in 44444444/);
  const act = rules['CG-CLOUD-ACTIVITY-047'].map(a => a.title).join('\n');
  assert.match(act, /securityrules\/write by ops@contoso.example/); assert.match(act, /diagnosticsettings\/delete/); assert.doesNotMatch(act, /roleassignments/, 'a failed role assignment is not a successful change');
  assert.ok(rules['CG-LOG-IDS-014'].some(a => /Metasploit/.test(a.title)), 'Azure Firewall IDPS reuses the IDS rule');
  assert.ok(rules['CG-FW-ANYANY-018'].some(a => /temp-any/.test(a.title)));
  assert.ok(Object.keys(rules).some(r => /^CG-ID/.test(r)), 'Entra sign-ins and conditional-access changes reach the identity threat rules');
});

test('the Azure read-only role allows only read operations and no data actions (CG-047)', () => {
  const role = JSON.parse(fs.readFileSync(new URL('../deploy/azure/cyberguard-reader-role.json', import.meta.url), 'utf8'));
  assert.ok(role.Actions.length > 10 && role.Actions.every(a => /\/read$/.test(a)), 'every action ends in /read');
  assert.deepEqual([role.DataActions, role.NotDataActions], [[], []]); assert.ok(!role.Actions.some(a => a.includes('*')));
});
