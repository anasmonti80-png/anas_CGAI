// CG-149 Entra workload identity security import from read-only Microsoft Graph exports made by the tenant owner
// (Application.Read.All, AuditLog.Read.All, Policy.Read.All; no write permission):
//   GET /servicePrincipals                     > sps.json
//   GET /applications                          > apps.json
//   GET /beta/auditLogs/signIns?$filter=signInEventTypes/any(t: t eq 'servicePrincipal')   > sp-signins.json  (Entra ID P1/P2)
//   GET /auditLogs/directoryAudits?$filter=category eq 'ApplicationManagement'               > audits.json
//   GET /identity/conditionalAccess/policies   > ca.json
//   node scripts/entra-workload-identity.js --tenant-id <guid> --authorization-ref <ref> --service-principals sps.json
//        [--applications apps.json] [--signins sp-signins.json] [--audits audits.json] [--ca-policies ca.json] --output wl.json
import fs from 'node:fs';
import { parseWorkloadExports, assessWorkloads } from '../lib/workload-identity.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const tenant = flag('--tenant-id'), auth = flag('--authorization-ref'), out = flag('--output'), sps = flag('--service-principals');
if (!tenant || !auth || !out || !sps) { console.error('usage: entra-workload-identity.js --tenant-id <guid> --authorization-ref <ref> --service-principals sps.json [--applications f] [--signins f] [--audits f] [--ca-policies f] --output wl.json'); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
const read = f => f ? JSON.parse(fs.readFileSync(f, 'utf8').replace(/^﻿/, '')) : undefined;
let d; try { d = parseWorkloadExports({ tenantId: tenant, servicePrincipals: read(sps), applications: read(flag('--applications')), signIns: read(flag('--signins')), audits: read(flag('--audits')), policies: read(flag('--ca-policies')) }); }
catch (e) { console.error(`Not a Graph export: ${e.code || e.message}`); process.exit(2); }
if (d.service_principals.length > 5000 || d.applications.length > 5000) { console.error('Too many objects in one import.'); process.exit(2); }
const at = new Date().toISOString(), details = { authorization_ref: auth, ...d };
const event = { event_id: `workload-identities:${d.tenant_id}:${at}`, kind: 'identity.workload_identities', observed_at: at, asset: { external_id: `entra:${d.tenant_id}`, hostname: `Entra ${d.tenant_id}`, os_family: 'unknown', device_type: 'unknown', addresses: [] }, details };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
const a = assessWorkloads(d, Date.now());
console.log(JSON.stringify({ tenant: d.tenant_id, counts: a.counts, coverage: a.coverage, credential_findings: a.credentials.length, deviations: a.deviations.length, changes: a.changes.length, output: out }));
