// CG-048 Google Cloud read-only connector. Converts saved gcloud / Google Cloud API outputs, or collects them live through
// the gcloud session the owner already signed in with ("gcloud auth login"), into a cg.telemetry/1 file. Nothing is
// written to Google Cloud and no credential or token is stored.
//
// Offline modes (--input is a saved gcloud / API output):
//   inventory       --input projects.json [--apis {"<project>":<services list --enabled>}.json] [--subnets {"<project>":<networks subnets list>}.json]
//                   [--firewalls {"<project>":<firewall-rules list>}.json] [--armor {"<project>":<security-policies list>}.json]
//                   [--iam {"<project>":<get-iam-policy>|"access-denied"}.json] [--access {"<project>":"assumed|denied"}.json]
//                   [--scc enabled|disabled|access-denied] [--organization-id <number>] --output out.json
//   scc-findings    --input <gcloud scc findings list ORG> --output out.json
//   iam             --input <gcloud projects get-iam-policy P> --project <id> --output out.json
//   firewall-rules  --input <gcloud compute firewall-rules list> --device-ref gcp:<project>:<network> [--network <name>] --output out.json
//   armor-policy    --input <gcloud compute security-policies describe NAME> --device-ref gcp:<project>:<policy> --output out.json
//   audit-logs | vpc-flow | firewall-logs | armor-logs  --input <gcloud logging read --format=json, an export, or JSON lines> --output out.json
// Live mode (owner's own gcloud session; read calls only):
//   live --projects <id1,id2> [--organization-id <number>] [--impersonate-service-account <sa-email>] --output out.json
//   With --impersonate-service-account every call uses a short-lived token of that read-only service account (CG-049).
//   Grant roles/viewer, roles/iam.securityReviewer, roles/securitycenter.findingsViewer and roles/logging.viewer (see
//   deploy/gcp/cyberguard-viewer-roles.json); no owner, editor or organisation admin role is needed.
import fs from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { gcpMemberGrants } from '../lib/cloud-access.js';
import { projects, gcpServiceStatus, sccFindings, iamSnapshot, publicBindingFindings, vpcFirewallRules, cloudArmorRules, logEntryLines } from '../lib/connectors/gcp.js';

const run = promisify(execFile);
const [mode, ...rest] = process.argv.slice(2);
const args = Object.fromEntries(rest.reduce((pairs, v, i, all) => (v.startsWith('--') ? [...pairs, [v.slice(2), all[i + 1] && !all[i + 1].startsWith('--') ? all[i + 1] : true]] : pairs), []));
const modes = ['inventory', 'scc-findings', 'iam', 'firewall-rules', 'armor-policy', 'audit-logs', 'vpc-flow', 'firewall-logs', 'armor-logs', 'live'];
if (!modes.includes(mode)) { console.error(`Usage: node scripts/gcp-connector.js <${modes.join('|')}> ... (see the header of this file)`); process.exit(2); }
if (!args.output) { console.error('Missing --output'); process.exit(2); }
if (fs.existsSync(args.output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(1); }
const read = p => fs.readFileSync(p, 'utf8').replace(/^﻿/, '');
const json = p => (p ? JSON.parse(read(p)) : undefined);
const now = () => new Date().toISOString();
const collector = ref => ({ external_id: `gcp:${ref}`.slice(0, 200), hostname: `Google Cloud ${ref}`.slice(0, 200), os_family: 'unknown', device_type: 'unknown', addresses: [] });
const event = (kind, asset, details) => ({ event_id: `gcp-${randomUUID()}`, kind, observed_at: now(), asset, details });
const logBatch = (format, lines, name) => event('log.batch', collector(name), { batch_id: `${format}-${randomUUID()}`, source_name: name, format, lines: lines.slice(0, 5000) });
const findingEvents = list => list.map(f => event('cloud.finding', collector(f.account_id), f));
const ruleset = (r, ref) => event('firewall.ruleset', { external_id: `firewall-${ref}`.slice(0, 200), hostname: ref, os_family: 'network', device_type: 'firewall', addresses: [] }, { ruleset_id: `${r.vendor}:${ref}`, device_ref: ref, vendor: r.vendor, evaluation: 'first-match', rules: r.rules });
const inventoryEvent = (accounts, services, org, by) => event('cloud.account_inventory', collector(org ? `organization-${org}` : 'projects'), { inventory_id: `gcp:${org || 'projects'}`, provider: 'gcp', organization_id: org || null, collected_by: by, accounts, services });
const events = [];

if (mode === 'live') {
  const impersonate = args['impersonate-service-account'] || null;
  const gcloud = async cli => { const { stdout } = await run(process.platform === 'win32' ? 'gcloud.cmd' : 'gcloud', [...cli, '--format=json', '--quiet', ...(impersonate ? [`--impersonate-service-account=${impersonate}`] : [])], { maxBuffer: 128 * 1024 * 1024, shell: process.platform === 'win32' }); return JSON.parse(stdout || 'null'); };
  let all; try { all = projects(await gcloud(['projects', 'list'])); } catch (e) { console.error(e.code === 'ENOENT' ? 'Google Cloud CLI is not installed or not on PATH.' : `The gcloud session could not be used (run "gcloud auth login" first): ${String(e.stderr || e.message).trim().slice(0, 300)}`); process.exit(1); }
  const keep = args.projects ? new Set(String(args.projects).split(',')) : null, accounts = keep ? all.filter(p => keep.has(p.account_id)) : all, org = args['organization-id'] || null;
  const me = impersonate ? `serviceAccount:${impersonate}` : await gcloud(['config', 'get-value', 'account']).then(v => (String(v).includes('gserviceaccount.com') ? `serviceAccount:${v}` : `user:${v}`)).catch(() => null), grants = [];
  const apis = {}, subnets = {}, firewalls = {}, armor = {}, iam = {}, denied = e => (/PERMISSION_DENIED|403|does not have/i.test(String(e.stderr || '')) ? 'access-denied' : undefined);
  for (const a of accounts.filter(x => x.status === 'active')) {
    const P = ['--project', a.account_id];
    try { iam[a.account_id] = await gcloud(['projects', 'get-iam-policy', a.account_id]); a.access = 'assumed'; } catch (e) { iam[a.account_id] = denied(e) || undefined; if (iam[a.account_id] === 'access-denied') { a.access = 'denied'; continue; } }
    try { apis[a.account_id] = await gcloud(['services', 'list', '--enabled', ...P]); } catch (e) { apis[a.account_id] = denied(e); }
    try { subnets[a.account_id] = await gcloud(['compute', 'networks', 'subnets', 'list', ...P]); } catch (e) { subnets[a.account_id] = denied(e); }
    try { firewalls[a.account_id] = await gcloud(['compute', 'firewall-rules', 'list', ...P]); events.push(ruleset(vpcFirewallRules(firewalls[a.account_id]), `gcp:${a.account_id}:all-networks`)); } catch (e) { firewalls[a.account_id] = denied(e); }
    try { armor[a.account_id] = await gcloud(['compute', 'security-policies', 'list', ...P]); for (const pol of armor[a.account_id] || []) events.push(ruleset(cloudArmorRules(pol), `gcp:${a.account_id}:${pol.name}`)); } catch (e) { armor[a.account_id] = denied(e); }
    if (me && iam[a.account_id] && iam[a.account_id] !== 'access-denied') grants.push(...gcpMemberGrants(iam[a.account_id], me, `projects/${a.account_id}`, { impersonated: Boolean(impersonate) }));
    if (iam[a.account_id] && iam[a.account_id] !== 'access-denied') { const r = iamSnapshot(iam[a.account_id], a.account_id, { method: 'cloud-api', credentialRef: 'gcloud-session:owner' }); events.push(event('identity.directory_snapshot', collector(a.account_id), r.details), ...findingEvents(publicBindingFindings(r.publicBindings, a.account_id, iam[a.account_id].etag))); }
  }
  let scc, findings = [];
  if (org) { try { findings = sccFindings(await gcloud(['scc', 'findings', 'list', `organizations/${org}`, '--filter=state="ACTIVE"', '--page-size=1000', '--limit=5000'])); scc = 'enabled'; } catch (e) { scc = denied(e) || (/not enabled|has not been activated|FAILED_PRECONDITION/i.test(String(e.stderr || '')) ? 'disabled' : undefined); } }
  events.unshift(inventoryEvent(accounts, gcpServiceStatus({ accounts, enabledApis: apis, subnets, firewalls, armor, iam, scc }), org, org ? 'organizations' : 'single-account'));
  events.push(...findingEvents(findings));
  if (grants.length) events.push(event('cloud.access_grant', collector('access-review'), { review_id: `gcp-live-${randomUUID()}`, grants }));
  console.log(`Google Cloud live read: ${accounts.length} project(s), ${findings.length} active SCC finding(s), SCC ${scc || 'not checked (give --organization-id)'}.`);
} else {
  if (!args.input) { console.error('Missing --input <saved gcloud output>'); process.exit(2); }
  const raw = read(args.input);
  if (mode === 'inventory') {
    const access = json(args.access) || {}, accounts = projects(raw).map(a => ({ ...a, access: access[a.account_id] || a.access }));
    const services = gcpServiceStatus({ accounts, enabledApis: json(args.apis) || {}, subnets: json(args.subnets) || {}, firewalls: json(args.firewalls) || {}, armor: json(args.armor) || {}, iam: json(args.iam) || {}, scc: args.scc });
    events.push(inventoryEvent(accounts, services, args['organization-id'], 'manual-import'));
    console.log(`Google Cloud projects: ${accounts.length}, ${services.length} service status row(s).`);
  }
  if (mode === 'scc-findings') { const f = sccFindings(raw); events.push(...findingEvents(f)); console.log(`Security Command Center: ${f.length} finding(s), ${f.filter(x => x.status === 'active').length} active.`); }
  if (mode === 'iam') { if (!args.project) { console.error('Missing --project <id>'); process.exit(2); } const r = iamSnapshot(raw, args.project); events.push(event('identity.directory_snapshot', collector(args.project), r.details), ...findingEvents(publicBindingFindings(r.publicBindings, args.project, JSON.parse(raw).etag))); console.log(`IAM policy: ${r.details.principals.length} principal(s), ${r.details.privileges.length} role binding(s), ${r.publicBindings.length} public binding(s)${r.publicBindings.length ? ': ' + r.publicBindings.map(b => `${b.member} ${b.role}`).join(', ') : ''}.`); }
  if (mode === 'firewall-rules') { const r = vpcFirewallRules(raw, args.network || null); events.push(ruleset(r, args['device-ref'] || 'gcp-vpc-firewall')); console.log(`VPC firewall: ${r.rules.length} rule(s) including the two implied rules, ${r.unreadable} matching source tags or service accounts (not evaluated).`); }
  if (mode === 'armor-policy') { const r = cloudArmorRules(raw); events.push(ruleset(r, args['device-ref'] || 'gcp-cloud-armor')); console.log(`Cloud Armor: ${r.rules.length} rule(s), ${r.preview} in preview (not enforced), ${r.unreadable} expression rule(s) (not evaluated).`); }
  const logs = { 'audit-logs': ['gcp-audit-json', 'gcp-cloud-audit-logs'], 'vpc-flow': ['gcp-vpc-flow-json', 'gcp-vpc-flow-logs'], 'firewall-logs': ['gcp-firewall-json', 'gcp-firewall-rules-logging'], 'armor-logs': ['gcp-armor-json', 'gcp-cloud-armor'] };
  if (logs[mode]) { const l = logEntryLines(raw); events.push(logBatch(logs[mode][0], l, logs[mode][1])); console.log(`${logs[mode][1]}: ${l.length} log entr(ies).`); }
}
if (!events.length) { console.error('Nothing to write.'); process.exit(1); }
fs.writeFileSync(args.output, JSON.stringify({ schema_version: 'cg.telemetry/1', events }));
console.log('Wrote the requested private file. No upload performed.');
