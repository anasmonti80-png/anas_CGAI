// CG-151 Service-to-service zero trust review (NIST SP 800-207A) from read-only exports made by the owner:
//   kubectl get ns -o json > ns.json
//   kubectl get peerauthentications.security.istio.io -A -o json > pa.json
//   kubectl get authorizationpolicies.security.istio.io -A -o json > ap.json
//   workload certificates (X.509-SVIDs or service certificates, PEM, public part only) in a folder
//   inventory.json (owner): [{ "from", "to", "method", "credential_store", "last_rotated", "rotation_days", "expires" }]
//   node scripts/service-zero-trust.js --environment-ref <ref> --authorization-ref <ref> [--namespaces ns.json --peer-authentications pa.json
//        --authorization-policies ap.json] [--certs <dir>] [--inventory inventory.json] [--max-cert-hours 24] --output s2s.json
import fs from 'node:fs';
import path from 'node:path';
import { assessMesh, parseCertificates, assessCredentials } from '../lib/service-zero-trust.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const env = flag('--environment-ref'), auth = flag('--authorization-ref'), out = flag('--output'), maxHours = Number(flag('--max-cert-hours') || 24);
if (!env || !auth || !out || !(maxHours > 0)) { console.error('usage: service-zero-trust.js --environment-ref <ref> --authorization-ref <ref> [--namespaces f --peer-authentications f --authorization-policies f] [--certs dir] [--inventory f] [--max-cert-hours 24] --output s2s.json'); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
const read = f => f ? JSON.parse(fs.readFileSync(f, 'utf8').replace(/^\uFEFF/, '')) : null, items = (f, n) => { const j = read(f); if (!j) return []; if (!Array.isArray(j.items)) throw Object.assign(new Error(n), { code: `not_kubectl_${n}_list` }); return j.items; };
let mesh, certificates = [], credentials = [];
try {
  const ns = items(flag('--namespaces'), 'namespace').map(n => n.metadata?.name).filter(Boolean);
  mesh = assessMesh({ namespaces: ns, peerAuth: items(flag('--peer-authentications'), 'peerauthentication'), authz: items(flag('--authorization-policies'), 'authorizationpolicy') });
  if (flag('--certs')) { const dir = flag('--certs'); const pems = fs.readdirSync(dir).filter(f => /\.(pem|crt)$/i.test(f)).slice(0, 2000).map(f => ({ name: f, pem: fs.readFileSync(path.join(dir, f), 'utf8') }));
    if (pems.some(p => /PRIVATE KEY/.test(p.pem))) { console.error('A private key was found in the certificate folder. Export certificates only.'); process.exit(2); }
    certificates = parseCertificates(pems, { maxLifetimeHours: maxHours }); }
  credentials = assessCredentials(read(flag('--inventory')) || []);
} catch (e) { console.error(`Invalid export: ${e.code || e.message}`); process.exit(2); }
const at = new Date().toISOString(), details = { environment_ref: env, authorization_ref: auth, max_cert_hours: maxHours, mesh, certificates, credentials };
const event = { event_id: `s2s:${env}:${at}`, kind: 'network.service_zero_trust', observed_at: at, asset: { external_id: `s2s:${env}`, hostname: `Services ${env}`, os_family: 'unknown', device_type: 'unknown', addresses: [] }, details };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ environment: env, mesh: mesh.mesh, namespaces: mesh.namespaces.map(n => `${n.namespace}:${n.mtls}:${n.authz}`), certificates: certificates.length, long_lived: certificates.filter(c => c.long_lived).length, credentials: credentials.length, credential_findings: credentials.filter(c => c.findings.length).length, output: out }));
