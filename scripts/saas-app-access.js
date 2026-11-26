// CG-159 SaaS app-to-app access import. CyberGuard does not sign in to the tenant; the owner exports read-only:
//  Entra:  GET /policies/authorizationPolicy, GET /servicePrincipals, GET /oauth2PermissionGrants (Graph, read-only)
//    node scripts/saas-app-access.js --provider entra --tenant-ref <ref> --authorization-ref <ref> --authorization-policy ap.json
//         --service-principals sp.json --grants grants.json [--tenant-id <guid>] [--sharing anyone|new-and-existing-guests|existing-guests|only-organization]
//         [--anyone-link-expiry-days <n>] --output saas.json
//  Google: Directory API tokens.list per user (concatenated into one items array), the API controls app list and the
//          unconfigured third-party apps setting:
//    node scripts/saas-app-access.js --provider google --tenant-ref <ref> --authorization-ref <ref> --tokens tokens.json
//         [--app-access apps.json] [--unconfigured allow-all|sign-in-only|block] --output saas.json
//  File sharing (optional, both providers' Drive-style permission lists) is counted only with a privacy policy reference:
//         --file-permissions perms.json --internal-domains example.com,example.org --privacy-policy-ref <ref>
// User identifiers are reduced to counts and file names are never read. Mail, file and chat content is never requested.
import fs from 'node:fs';
import { parseEntra, parseGoogle, countFileExposure, assessAppAccess, SHARING_LEVELS } from '../lib/saas-app-access.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const die = m => { console.error(m); process.exit(2); };
const read = f => { try { return JSON.parse(fs.readFileSync(f, 'utf8').replace(/^﻿/, '')); } catch { die(`Cannot read JSON from ${f}`); } };
const provider = flag('--provider'), tenant = flag('--tenant-ref'), auth = flag('--authorization-ref'), out = flag('--output');
if (!['entra', 'google'].includes(provider) || !tenant || !auth || !out) die('usage: saas-app-access.js --provider entra|google --tenant-ref <ref> --authorization-ref <ref> ... --output saas.json');
if (fs.existsSync(out)) die('Output already exists. Choose a new file path.');
for (const bad of ['--messages', '--mail', '--file-content', '--chat']) if (args.includes(bad)) die('Content is never imported: CyberGuard inventories app access, not employee mail, files or chats.');
let r;
try {
  if (provider === 'entra') { for (const f of ['--authorization-policy', '--service-principals', '--grants']) if (!flag(f)) die(`Missing ${f}`);
    r = parseEntra({ authorizationPolicy: read(flag('--authorization-policy')), servicePrincipals: read(flag('--service-principals')), grants: read(flag('--grants')), tenantId: flag('--tenant-id') }); }
  else { if (!flag('--tokens')) die('Missing --tokens');
    r = parseGoogle({ tokens: read(flag('--tokens')), appAccess: flag('--app-access') ? read(flag('--app-access')) : [], unconfigured: flag('--unconfigured') }); }
} catch (e) { die(`Not a supported export: ${e.code || e.message}`); }
const level = flag('--sharing'); if (level && !SHARING_LEVELS.includes(level)) die(`Unknown sharing level. Use one of: ${SHARING_LEVELS.join(', ')}`);
const expiry = flag('--anyone-link-expiry-days') ? Number(flag('--anyone-link-expiry-days')) : null; if (expiry !== null && !(Number.isInteger(expiry) && expiry > 0 && expiry <= 730)) die('Invalid --anyone-link-expiry-days');
let file_exposure = null; const privacy = flag('--privacy-policy-ref');
if (flag('--file-permissions')) { if (!privacy) die('File sharing is counted only under a declared employee privacy policy: add --privacy-policy-ref <ref>.');
  const domains = String(flag('--internal-domains') || '').split(',').map(s => s.trim()).filter(Boolean); if (!domains.length) die('Missing --internal-domains');
  file_exposure = countFileExposure(read(flag('--file-permissions')), domains); }
const at = new Date().toISOString(), details = { provider, tenant_ref: tenant, authorization_ref: auth, privacy_policy_ref: privacy || null, consent_policy: r.consent_policy, sharing: level ? { level, anyone_link_expiration_days: expiry } : null, file_exposure, apps: r.apps };
const event = { event_id: `saas-app-access:${provider}:${tenant}:${at}`, kind: 'identity.saas_app_access', observed_at: at, asset: { external_id: `${provider}:${tenant}`, hostname: `${provider === 'entra' ? 'Microsoft 365' : 'Google Workspace'} ${tenant}`, os_family: 'unknown', device_type: 'unknown', addresses: [] }, details };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
const a = assessAppAccess(details);
console.log(JSON.stringify({ provider, tenant, consent_policy: r.consent_policy, ...a.summary, findings: a.findings.length, file_exposure: !!file_exposure, output: out }));
