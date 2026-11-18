// CG-049 Convert saved cloud permission read-outs into a cg.telemetry/1 cloud.access_grant review (read only; no upload).
//   aws-role     --role <iam get-role> --attached <iam list-attached-role-policies> --account <id> --output out.json
//   aws-root     --summary <iam get-account-summary> --account <id> --output out.json
//   azure-rbac   --active <roleAssignmentScheduleInstances> [--eligible <roleEligibilityScheduleInstances>] --output out.json
//   entra-roles  --active <Graph directory roleAssignmentScheduleInstances> [--eligible <...EligibilityScheduleInstances>] --tenant <id> --output out.json
//   gcp-bindings --policy <getIamPolicy> --member <user:|serviceAccount:|group:...> --scope projects/<id> [--impersonated] --output out.json
// The live modes of scripts/aws-connector.js, azure-connector.js and gcp-connector.js add the same review for the
// identity they run as. Nothing is changed in any cloud.
import fs from 'node:fs';
import { randomUUID } from 'node:crypto';
import { awsRoleGrant, awsRootGrant, azureRoleGrants, entraDirectoryRoleGrants, gcpMemberGrants, reviewGrant } from '../lib/cloud-access.js';

const [mode, ...rest] = process.argv.slice(2);
const args = Object.fromEntries(rest.reduce((pairs, v, i, all) => (v.startsWith('--') ? [...pairs, [v.slice(2), all[i + 1] && !all[i + 1].startsWith('--') ? all[i + 1] : true]] : pairs), []));
const modes = ['aws-role', 'aws-root', 'azure-rbac', 'entra-roles', 'gcp-bindings'];
if (!modes.includes(mode) || !args.output) { console.error(`Usage: node scripts/cloud-access-review.js <${modes.join('|')}> ... --output out.json (see the header of this file)`); process.exit(2); }
if (fs.existsSync(args.output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(1); }
const read = p => (p ? fs.readFileSync(p, 'utf8').replace(/^﻿/, '') : null);
let grants = [];
if (mode === 'aws-role') grants = [awsRoleGrant(read(args.role), read(args.attached), args.account)];
if (mode === 'aws-root') grants = [awsRootGrant(read(args.summary), args.account)].filter(Boolean);
if (mode === 'azure-rbac') grants = azureRoleGrants(read(args.active), read(args.eligible));
if (mode === 'entra-roles') grants = entraDirectoryRoleGrants(read(args.active), read(args.eligible), args.tenant || 'tenant');
if (mode === 'gcp-bindings') grants = gcpMemberGrants(read(args.policy), args.member, args.scope, { impersonated: args.impersonated === true });
if (!grants.length) { console.log('No grants to review (for aws-root: no root access keys exist).'); process.exit(0); }
const provider = mode.startsWith('aws') ? 'aws' : mode.startsWith('gcp') ? 'gcp' : 'azure', asset = { external_id: `${provider}:access-review`, hostname: `${{ aws: 'AWS', azure: 'Azure', gcp: 'Google Cloud' }[provider]} access review`, os_family: 'unknown', device_type: 'unknown', addresses: [] };
fs.writeFileSync(args.output, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [{ event_id: `access-${randomUUID()}`, kind: 'cloud.access_grant', observed_at: new Date().toISOString(), asset, details: { review_id: `${mode}-${randomUUID()}`, grants } }] }));
for (const g of grants) { const r = reviewGrant(g); console.log(`${r.status.padEnd(9)} ${g.roles.join(',')} -> ${g.principal_ref} on ${g.scope_ref} [${g.mechanism}]${r.reasons.length ? ' ' + r.reasons.join(', ') : ''}`); }
console.log('Wrote the requested private file. No upload performed.');
