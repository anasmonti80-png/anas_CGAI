// CG-047 Azure and Microsoft Entra read-only connector. Converts saved read outputs, or collects them live through the
// Azure CLI session the owner already signed in with ("az login"), into a cg.telemetry/1 file. Nothing is written to Azure
// and no credential or token is stored.
//
// Offline modes (--input is a saved Azure CLI / ARM / Microsoft Graph output):
//   inventory            --input subscriptions.json [--graph resource-graph.json] [--pricings {"<sub>":<az security pricing list>}.json]
//                        [--diagnostics {"<sub>":<az monitor diagnostic-settings subscription list>}.json] [--sentinel {"<sub>":[workspace ids]}.json]
//                        [--access {"<sub>":"assumed|denied"}.json] [--entra enabled|access-denied] [--tenant-id <guid>] --output out.json
//   defender-alerts      --input <Microsoft.Security/alerts list> --output out.json
//   defender-assessments --input <assessments list or Resource Graph securityresources rows> --output out.json
//   sentinel-incidents   --input <Microsoft.SecurityInsights/incidents list> --output out.json
//   entra-signins        --input <Graph auditLogs/signIns> --directory-ref entra:<tenant> --output out.json
//   entra-audits         --input <Graph auditLogs/directoryAudits> --directory-ref entra:<tenant> --output out.json
//   nsg                  --input <az network nsg list|show> --device-ref azure:<sub>:<name> --output out.json
//   firewall-policy      --input <az network firewall policy rule-collection-group list> --device-ref azure:<sub>:<policy> --output out.json
//   activity             --input <activity log export {"records":[...]}, az monitor activity-log list, or JSON lines> --output out.json
//   vnet-flow            --input <VNet flow log blob {"records":[...]}> --output out.json
//   firewall-logs        --input <Azure Firewall structured logs {"records":[...]} or JSON lines> --output out.json
// Live mode (owner's own "az login"; every call is a read):
//   live [--subscriptions <id1,id2>] [--tenant-id <guid>] --output out.json
//   Grant the reader roles in deploy/azure/cyberguard-reader-role.json (Reader, Security Reader, Microsoft Sentinel Reader
//   or the custom read-only role) and, for Entra logs, AuditLog.Read.All delegated or application permission.
import fs from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { azureRoleGrants } from '../lib/cloud-access.js';
import { subscriptions, azureServiceStatus, defenderAlerts, defenderAssessments, sentinelIncidents, entraSignins, entraDirectoryAudits, nsgRules, azureFirewallPolicyRules, vnetFlowLines } from '../lib/connectors/azure.js';

const run = promisify(execFile);
const [mode, ...rest] = process.argv.slice(2);
const args = Object.fromEntries(rest.reduce((pairs, v, i, all) => (v.startsWith('--') ? [...pairs, [v.slice(2), all[i + 1] && !all[i + 1].startsWith('--') ? all[i + 1] : true]] : pairs), []));
const modes = ['inventory', 'defender-alerts', 'defender-assessments', 'sentinel-incidents', 'entra-signins', 'entra-audits', 'nsg', 'firewall-policy', 'activity', 'vnet-flow', 'firewall-logs', 'live'];
if (!modes.includes(mode)) { console.error(`Usage: node scripts/azure-connector.js <${modes.join('|')}> ... (see the header of this file)`); process.exit(2); }
if (!args.output) { console.error('Missing --output'); process.exit(2); }
if (fs.existsSync(args.output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(1); }
const read = p => fs.readFileSync(p, 'utf8').replace(/^﻿/, '');
const json = p => (p ? JSON.parse(read(p)) : undefined);
const now = () => new Date().toISOString();
const collector = ref => ({ external_id: `azure:${ref}`.slice(0, 200), hostname: `Azure ${ref}`.slice(0, 200), os_family: 'unknown', device_type: 'unknown', addresses: [] });
const event = (kind, asset, details) => ({ event_id: `azure-${randomUUID()}`, kind, observed_at: now(), asset, details });
const logBatch = (format, lines, name) => event('log.batch', collector(name), { batch_id: `${format}-${randomUUID()}`, source_name: name, format, lines: lines.slice(0, 5000) });
const findingEvents = list => list.map(f => event('cloud.finding', collector(f.account_id), f));
const records = raw => { const t = raw.trim(); if (t.startsWith('{')) { const v = JSON.parse(t); return (v.records || v.value || [v]).map(r => JSON.stringify(r)); } if (t.startsWith('[')) return JSON.parse(t).map(r => JSON.stringify(r)); return t.split(/\r?\n/).filter(Boolean); };
const ruleset = (r, ref) => event('firewall.ruleset', { external_id: `firewall-${ref}`.slice(0, 200), hostname: ref, os_family: 'network', device_type: 'firewall', addresses: [] }, { ruleset_id: `${r.vendor}:${ref}`, device_ref: ref, vendor: r.vendor, evaluation: 'first-match', rules: r.rules });
const inventoryEvent = (accounts, services, tenant, by) => event('cloud.account_inventory', collector(tenant || 'tenant'), { inventory_id: `azure:${tenant || 'tenant'}`, provider: 'azure', organization_id: tenant || null, collected_by: by, accounts, services });
const events = [];

if (mode === 'live') {
  const az = async (cli) => { const { stdout } = await run(process.platform === 'win32' ? 'az.cmd' : 'az', [...cli, '--output', 'json', '--only-show-errors'], { maxBuffer: 128 * 1024 * 1024, shell: process.platform === 'win32' }); return JSON.parse(stdout || 'null'); };
  let accounts; try { accounts = subscriptions(await az(['account', 'list', '--all'])); } catch (e) { console.error(e.code === 'ENOENT' ? 'Azure CLI is not installed or not on PATH.' : `The Azure CLI session could not be used (run "az login" first): ${String(e.stderr || e.message).trim().slice(0, 300)}`); process.exit(1); }
  if (args.subscriptions) { const keep = new Set(String(args.subscriptions).toLowerCase().split(',')); accounts = accounts.filter(a => keep.has(a.account_id)); }
  const tenant = args['tenant-id'] || (await az(['account', 'show']).catch(() => null))?.tenantId || null, ids = accounts.map(a => a.account_id);
  let graph = null; try { graph = []; let skip = null; do { const r = await az(['graph', 'query', '-q', "resources | where type in~ ('microsoft.network/virtualnetworks','microsoft.network/networkwatchers','microsoft.network/networkwatchers/flowlogs','microsoft.network/azurefirewalls','microsoft.network/networksecuritygroups','microsoft.network/applicationsecuritygroups','microsoft.operationsmanagement/solutions') | project id,name,type,location,subscriptionId,properties", '--first', '1000', '--subscriptions', ...ids, ...(skip ? ['--skip-token', skip] : [])]); graph.push(...(r.data || [])); skip = r.skip_token || null; } while (skip && graph.length < 20000); } catch { graph = null; }
  const pricings = {}, diagnostics = {}, sentinel = {}, findings = [], grants = [];
  for (const a of accounts.filter(x => x.status === 'active')) {
    try { pricings[a.account_id] = await az(['security', 'pricing', 'list', '--subscription', a.account_id]); a.access = 'assumed'; } catch (e) { pricings[a.account_id] = 'access-denied'; }
    try { diagnostics[a.account_id] = await az(['monitor', 'diagnostic-settings', 'subscription', 'list', '--subscription', a.account_id]); a.access = 'assumed'; } catch { diagnostics[a.account_id] = 'access-denied'; }
    if (pricings[a.account_id] === 'access-denied' && diagnostics[a.account_id] === 'access-denied') a.access = 'denied';
    try { const base = `https://management.azure.com/subscriptions/${a.account_id}/providers/Microsoft.Authorization`; grants.push(...azureRoleGrants(await az(['rest', '--method', 'get', '--url', `${base}/roleAssignmentScheduleInstances?api-version=2020-10-01&$filter=asTarget()`]), await az(['rest', '--method', 'get', '--url', `${base}/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=asTarget()`]).catch(() => null))); } catch { /* PIM read not permitted */ }
    try { findings.push(...defenderAlerts(await az(['security', 'alert', 'list', '--subscription', a.account_id]))); } catch { /* recorded as a Defender gap */ }
    if (graph) { const ws = graph.filter(r => r.subscriptionId === a.account_id && String(r.type).toLowerCase() === 'microsoft.operationsmanagement/solutions' && /^SecurityInsights/i.test(r.name)).map(r => r.properties?.workspaceResourceId).filter(Boolean); sentinel[a.account_id] = ws;
      for (const w of ws) try { findings.push(...sentinelIncidents(await az(['rest', '--method', 'get', '--url', `https://management.azure.com${w}/providers/Microsoft.SecurityInsights/incidents?api-version=2024-03-01&$filter=properties/status ne 'Closed'&$top=200`]))); } catch { /* Sentinel Reader missing: shown as no incidents read */ } }
  }
  let entra; const directoryRef = `entra:${tenant || 'tenant'}`;
  try { const s = await az(['rest', '--method', 'get', '--url', 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=500']); entra = 'enabled'; try { events.push(event('identity.signin_activity', collector(directoryRef), entraSignins(s, directoryRef))); } catch { /* no sign-ins in the window */ }
    const audits = entraDirectoryAudits(await az(['rest', '--method', 'get', '--url', 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$top=500']), directoryRef); for (const c of audits.changes) events.push(event('identity.idp_change', collector(directoryRef), c)); } catch { entra = entra || 'access-denied'; }
  events.unshift(inventoryEvent(accounts, azureServiceStatus({ accounts, graph, pricings, diagnostics, sentinel, entra }), tenant, 'tenant'));
  events.push(...findingEvents(findings));
  if (grants.length) events.push(event('cloud.access_grant', collector('access-review'), { review_id: `azure-live-${randomUUID()}`, grants }));
  console.log(`Azure live read: ${accounts.length} subscription(s), Resource Graph ${graph ? graph.length + ' row(s)' : 'not readable'}, ${findings.length} finding(s), Entra logs ${entra}.`);
} else {
  if (!args.input) { console.error('Missing --input <saved Azure output>'); process.exit(2); }
  const raw = read(args.input), dref = args['directory-ref'];
  if (mode === 'inventory') {
    const access = json(args.access) || {}, accounts = subscriptions(raw).map(a => ({ ...a, access: access[a.account_id] || a.access })), graph = args.graph ? (j => j.data || j.value || j)(json(args.graph)) : null;
    const services = azureServiceStatus({ accounts, graph, pricings: json(args.pricings) || {}, diagnostics: json(args.diagnostics) || {}, sentinel: json(args.sentinel) || {}, entra: args.entra });
    events.push(inventoryEvent(accounts, services, args['tenant-id'], 'manual-import'));
    console.log(`Azure subscriptions: ${accounts.length}, ${services.length} service status row(s).`);
  }
  if (mode === 'defender-alerts') { const f = defenderAlerts(raw); events.push(...findingEvents(f)); console.log(`Defender for Cloud alerts: ${f.length}.`); }
  if (mode === 'defender-assessments') { const f = defenderAssessments(raw); events.push(...findingEvents(f)); console.log(`Defender for Cloud recommendations: ${f.length}, ${f.filter(x => x.status === 'active').length} unhealthy.`); }
  if (mode === 'sentinel-incidents') { const f = sentinelIncidents(raw); events.push(...findingEvents(f)); console.log(`Sentinel incidents: ${f.length}, ${f.filter(x => x.status === 'active').length} open.`); }
  if (mode === 'entra-signins' || mode === 'entra-audits') { if (!dref) { console.error('Missing --directory-ref entra:<tenant>'); process.exit(2); } }
  if (mode === 'entra-signins') { const d = entraSignins(raw, dref); events.push(event('identity.signin_activity', collector(dref), d)); console.log(`Entra sign-ins: ${d.signins.length}.`); }
  if (mode === 'entra-audits') { const a = entraDirectoryAudits(raw, dref); for (const c of a.changes) events.push(event('identity.idp_change', collector(dref), c)); console.log(`Entra directory audits: ${a.changes.length} identity-provider change(s), ${a.skipped} other record(s) not imported.`); }
  if (mode === 'nsg') { const r = nsgRules(raw); events.push(ruleset(r, args['device-ref'] || 'azure-nsg')); console.log(`NSG: ${r.rules.length} rule(s) including defaults, ${r.unreadable} referencing ASGs or service tags (not evaluated).`); }
  if (mode === 'firewall-policy') { const r = azureFirewallPolicyRules(raw); events.push(ruleset(r, args['device-ref'] || 'azure-firewall')); console.log(`Azure Firewall policy: ${r.rules.length} rule(s), ${r.unreadable} with IP groups or names (not evaluated).`); }
  if (mode === 'activity') { const l = records(raw); events.push(logBatch('azure-activity-json', l, 'azure-activity-log')); console.log(`Activity log: ${l.length} record(s).`); }
  if (mode === 'vnet-flow') { const l = vnetFlowLines(raw); events.push(logBatch('azure-vnet-flow-json', l, 'azure-vnet-flow-logs')); console.log(`VNet flow logs: ${l.length} flow tuple(s).`); }
  if (mode === 'firewall-logs') { const l = records(raw); events.push(logBatch('azure-firewall-json', l, 'azure-firewall')); console.log(`Azure Firewall logs: ${l.length} record(s).`); }
}
if (!events.length) { console.error('Nothing to write.'); process.exit(1); }
fs.writeFileSync(args.output, JSON.stringify({ schema_version: 'cg.telemetry/1', events }));
console.log('Wrote the requested private file. No upload performed.');
