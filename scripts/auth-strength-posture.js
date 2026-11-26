// CG-150 Phishing-resistant authentication posture from read-only Entra exports made by the tenant owner
// (AuditLog.Read.All, Policy.Read.All, UserAuthenticationMethod.Read.All; no write permission):
//   GET /reports/authenticationMethods/userRegistrationDetails     > registrations.json
//   GET /identity/conditionalAccess/policies                       > ca.json   (authentication strengths expanded)
//   GET /auditLogs/signIns?$filter=createdDateTime ge <date>       > signins.json (Entra ID P1/P2)
//   exceptions.json (owner): [{ "app", "reason", "owner", "compensating", "review_by" }] for apps that cannot use these methods
//   node scripts/auth-strength-posture.js --tenant-id <guid> --authorization-ref <ref> --registrations registrations.json
//        [--ca-policies ca.json] [--signins signins.json] [--exceptions exceptions.json] --output auth.json
import fs from 'node:fs';
import { parseAuthPosture, assessAuthPosture } from '../lib/phishing-resistant.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const tenant = flag('--tenant-id'), auth = flag('--authorization-ref'), out = flag('--output'), regs = flag('--registrations');
if (!tenant || !auth || !out || !regs) { console.error('usage: auth-strength-posture.js --tenant-id <guid> --authorization-ref <ref> --registrations f [--ca-policies f] [--signins f] [--exceptions f] --output auth.json'); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
const read = f => f ? JSON.parse(fs.readFileSync(f, 'utf8').replace(/^﻿/, '')) : undefined;
let d; try { d = parseAuthPosture({ tenantId: tenant, registrations: read(regs), policies: read(flag('--ca-policies')), signIns: read(flag('--signins')), exceptions: read(flag('--exceptions')) || [] }); }
catch (e) { console.error(`Not an Entra export: ${e.code || e.message}`); process.exit(2); }
const at = new Date().toISOString();
const event = { event_id: `auth-strength:${d.tenant_id}:${at}`, kind: 'identity.auth_strength_posture', observed_at: at, asset: { external_id: `entra:${d.tenant_id}`, hostname: `Entra ${d.tenant_id}`, os_family: 'unknown', device_type: 'unknown', addresses: [] }, details: { authorization_ref: auth, ...d } };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
const a = assessAuthPosture(d);
console.log(JSON.stringify({ tenant: d.tenant_id, users: a.users, admins_without_phishing_resistant: a.admins_without_phishing_resistant.length, enforcement: a.enforcement, legacy_blocked: a.legacy_blocked, legacy_signins: a.legacy.signins, exceptions: a.exceptions.length, output: out }));
