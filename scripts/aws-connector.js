// CG-046 AWS read-only connector. Converts saved AWS read outputs, or collects them live through the AWS CLI with the
// owner's own profile, into a cg.telemetry/1 file. It never writes to AWS and never stores credentials.
//
// Offline modes (--input is a saved AWS CLI/API output):
//   inventory          --input list-accounts.json [--services service-status.json] [--access {"<account>":"management|assumed|denied"}.json] --output out.json
//   resources          --input <resource-explorer-2 search --view-arn <aggregator view> --query-string "*"> --output out.json   (CG-050)
//   findings-asff      --input securityhub-get-findings.json --output out.json
//   findings-guardduty --input guardduty-get-findings.json --output out.json
//   security-groups    --input describe-security-groups.json --output out.json [--device-ref aws:<account>:<vpc>]
//   cloudtrail         --input <CloudTrail log file {"Records":[...]}> --output out.json
//   vpc-flow           --input <VPC Flow Logs text> --output out.json
//   network-firewall   --input <Network Firewall alert/flow JSON lines> --output out.json
//   eventbridge        --input <EventBridge events: object, array or JSON lines> --output out.json
// Live mode (owner runs it with their own AWS CLI profile; read-only calls only):
//   live --profile <name> --regions us-east-1,eu-west-1 [--role-name CyberGuardReadOnly] [--external-id-env CG_AWS_EXTERNAL_ID] --output out.json
//   Uses organizations list-accounts (falls back to the calling account), sts assume-role into each member account with the
//   template in deploy/aws/cyberguard-readonly-role.yaml (SecurityAudit; sessions of --session-seconds, default 900, at most 3600), then one read call per service
//   and region and securityhub get-findings for active findings. Temporary credentials live only in the child process env.
import fs from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { awsRoleGrant, awsRootGrant } from '../lib/cloud-access.js';
import { awsResources } from '../lib/cloud-inventory.js';
import { organizationsAccounts, asffFindings, guarddutyFindings, securityGroupRules, cloudtrailLines, networkFirewallLines, eventBridgeEnvelopes, serviceProbes, probeError, awsServices } from '../lib/connectors/aws.js';

const run = promisify(execFile);
const [mode, ...rest] = process.argv.slice(2);
const args = Object.fromEntries(rest.reduce((pairs, v, i, all) => (v.startsWith('--') ? [...pairs, [v.slice(2), all[i + 1] && !all[i + 1].startsWith('--') ? all[i + 1] : true]] : pairs), []));
const modes = ['inventory', 'resources', 'findings-asff', 'findings-guardduty', 'security-groups', 'cloudtrail', 'vpc-flow', 'network-firewall', 'eventbridge', 'live'];
if (!modes.includes(mode)) { console.error(`Usage: node scripts/aws-connector.js <${modes.join('|')}> ... (see the header of this file)`); process.exit(2); }
if (!args.output) { console.error('Missing --output'); process.exit(2); }
if (fs.existsSync(args.output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(1); }
const read = p => fs.readFileSync(p, 'utf8').replace(/^﻿/, '');
const now = () => new Date().toISOString();
const collector = ref => ({ external_id: `aws:${ref}`.slice(0, 200), hostname: `AWS ${ref}`.slice(0, 200), os_family: 'unknown', device_type: 'unknown', addresses: [] });
const event = (kind, asset, details) => ({ event_id: `aws-${randomUUID()}`, kind, observed_at: now(), asset, details });
const logBatch = (format, lines, name) => event('log.batch', collector(name), { batch_id: `${format}-${randomUUID()}`, source_name: name, format, lines: lines.slice(0, 5000) });
const findingEvents = list => list.map(f => event('cloud.finding', collector(f.account_id), f));
const events = [];

if (mode === 'live') {
  const profile = args.profile, regions = String(args.regions || '').split(',').map(r => r.trim()).filter(Boolean);
  if (!profile || !regions.length) { console.error('live needs --profile <aws-cli-profile> and --regions <r1,r2>'); process.exit(2); }
  const aws = async (cli, env = {}, region) => { const { stdout } = await run('aws', [...cli, '--output', 'json', ...(region ? ['--region', region] : [])], { env: { ...process.env, ...env, AWS_PAGER: '' }, maxBuffer: 64 * 1024 * 1024 }); return JSON.parse(stdout || 'null'); };
  const base = { AWS_PROFILE: profile };
  let me; try { me = await aws(['sts', 'get-caller-identity'], base); } catch (e) { console.error(e.code === 'ENOENT' ? 'AWS CLI v2 is not installed or not on PATH.' : `The AWS profile could not be used: ${String(e.stderr || e.message).trim().slice(0, 300)}`); process.exit(1); }
  let accounts, organizationId = null, collectedBy = 'organizations';
  try { accounts = organizationsAccounts(await aws(['organizations', 'list-accounts'], base)); organizationId = (await aws(['organizations', 'describe-organization'], base))?.Organization?.Id || null; }
  catch { accounts = [{ account_id: me.Account, name: null, status: 'active', access: 'management' }]; collectedBy = 'single-account'; }
  const grants = [], services = [], findings = [], roleName = args['role-name'] || 'CyberGuardReadOnly', externalId = args['external-id-env'] ? process.env[args['external-id-env']] : null;
  for (const a of accounts.filter(x => x.status === 'active')) {
    let env = base;
    if (a.account_id === me.Account) { a.access = 'management'; try { const g = awsRootGrant(await aws(['iam', 'get-account-summary'], base), a.account_id); if (g) grants.push(g); } catch { /* summary not readable */ } }
    else {
      try { const c = (await aws(['sts', 'assume-role', '--role-arn', `arn:aws:iam::${a.account_id}:role/${roleName}`, '--role-session-name', 'cyberguard-readonly', '--duration-seconds', String(Math.min(Number(args['session-seconds']) || 900, 3600)), ...(externalId ? ['--external-id', externalId] : [])], base)).Credentials;
        env = { AWS_PROFILE: '', AWS_ACCESS_KEY_ID: c.AccessKeyId, AWS_SECRET_ACCESS_KEY: c.SecretAccessKey, AWS_SESSION_TOKEN: c.SessionToken }; a.access = 'assumed';
        try { grants.push(awsRoleGrant(await aws(['iam', 'get-role', '--role-name', roleName], env), await aws(['iam', 'list-attached-role-policies', '--role-name', roleName], env), a.account_id)); } catch { /* role metadata not readable with SecurityAudit */ } }
      catch { a.access = 'denied'; continue; }
    }
    for (const region of regions) for (const service of awsServices) {
      try { const v = await aws(serviceProbes[service].args, env, region); services.push({ account_id: a.account_id, region, service, status: serviceProbes[service].enabled(v) ? 'enabled' : 'disabled', detail: serviceProbes[service].detail(v) }); }
      catch (e) { services.push({ account_id: a.account_id, region, service, status: probeError(e.stderr), detail: null }); }
    }
    for (const region of regions) try { findings.push(...asffFindings(await aws(['securityhub', 'get-findings', '--filters', '{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}', '--max-items', '1000'], env, region))); } catch { /* Security Hub disabled or denied: already recorded as a service gap */ }
  }
  events.push(event('cloud.account_inventory', collector(organizationId || me.Account), { inventory_id: `aws:${organizationId || me.Account}`, provider: 'aws', organization_id: organizationId, collected_by: collectedBy, accounts, services }), ...findingEvents(findings));
  try { const r = awsResources(await aws(['resource-explorer-2', 'search', '--query-string', '*', '--max-results', '1000'], base)); if (r.length) events.push(event('cloud.resource_inventory', collector('resource-explorer'), { inventory_id: `aws-resources-${randomUUID()}`, provider: 'aws', source: 'aws-resource-explorer', resources: r })); } catch { /* Resource Explorer aggregator index not set up */ }
  if (grants.length) events.push(event('cloud.access_grant', collector('access-review'), { review_id: `aws-live-${randomUUID()}`, grants }));
  console.log(`AWS live read: ${accounts.length} account(s), ${services.length} service check(s), ${findings.length} active finding(s).`);
} else {
  if (!args.input) { console.error('Missing --input <saved AWS output>'); process.exit(2); }
  const raw = read(args.input);
  if (mode === 'inventory') {
    const access = args.access ? JSON.parse(read(args.access)) : {}, accounts = organizationsAccounts(raw).map(a => ({ ...a, access: access[a.account_id] || a.access })), status = args.services ? JSON.parse(read(args.services)) : [];
    events.push(event('cloud.account_inventory', collector('organization'), { inventory_id: `aws:${args['inventory-id'] || 'organization'}`, provider: 'aws', organization_id: args['organization-id'] || null, collected_by: 'manual-import', accounts, services: status }));
    console.log(`AWS Organizations: ${accounts.length} account(s), ${status.length} service status row(s).`);
  }
  if (mode === 'resources') { const r = awsResources(raw); events.push(event('cloud.resource_inventory', collector('resource-explorer'), { inventory_id: `aws-resources-${randomUUID()}`, provider: 'aws', source: 'aws-resource-explorer', resources: r })); console.log(`Resource Explorer: ${r.length} resource(s) in ${new Set(r.map(x => x.account_id)).size} account(s) and ${new Set(r.map(x => x.region)).size} region(s).`); }
  if (mode === 'findings-asff') { const f = asffFindings(raw); events.push(...findingEvents(f)); console.log(`Security Hub ASFF: ${f.length} finding(s), ${f.filter(x => x.status === 'active').length} active.`); }
  if (mode === 'findings-guardduty') { const f = guarddutyFindings(raw); events.push(...findingEvents(f)); console.log(`GuardDuty: ${f.length} finding(s).`); }
  if (mode === 'security-groups') {
    const r = securityGroupRules(raw), ref = args['device-ref'] || 'aws-security-groups';
    if (!r.rules.length) { console.error('No security group rules found in the input.'); process.exit(1); }
    events.push(event('firewall.ruleset', { external_id: `firewall-${ref}`.slice(0, 200), hostname: ref, os_family: 'network', device_type: 'firewall', addresses: [] }, { ruleset_id: `aws-security-group:${ref}`, device_ref: ref, vendor: 'aws-security-group', evaluation: 'first-match', rules: r.rules.slice(0, 5000) }));
    console.log(`Security groups: ${r.groups} group(s), ${r.rules.length} rule(s), ${r.unreadable} referencing groups or prefix lists (not evaluated).`);
  }
  if (mode === 'cloudtrail') { const lines = cloudtrailLines(raw); events.push(logBatch('aws-cloudtrail-json', lines, 'aws-cloudtrail')); console.log(`CloudTrail: ${lines.length} record(s).`); }
  if (mode === 'vpc-flow') { const lines = raw.split(/\r?\n/).filter(l => l.trim()); events.push(logBatch('aws-vpc-flow', lines, 'aws-vpc-flow-logs')); console.log(`VPC Flow Logs: ${lines.length} line(s).`); }
  if (mode === 'network-firewall') { const lines = networkFirewallLines(raw); events.push(logBatch('aws-network-firewall-json', lines, 'aws-network-firewall')); console.log(`Network Firewall: ${lines.length} line(s).`); }
  if (mode === 'eventbridge') {
    const r = eventBridgeEnvelopes(raw); events.push(...findingEvents(r.findings)); if (r.cloudtrail.length) events.push(logBatch('aws-cloudtrail-json', r.cloudtrail, 'aws-eventbridge-cloudtrail'));
    console.log(`EventBridge: ${r.findings.length} finding(s), ${r.cloudtrail.length} CloudTrail call(s), ${r.unsupported.length} unsupported event(s).`);
  }
}
if (!events.length) { console.error('Nothing to write.'); process.exit(1); }
fs.writeFileSync(args.output, JSON.stringify({ schema_version: 'cg.telemetry/1', events }));
console.log('Wrote the requested private file. No upload performed.');
