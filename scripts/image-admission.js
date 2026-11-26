// CG-158 Container image admission review from read-only exports by the cluster owner (nothing is changed):
//   kubectl get ns -o json > ns.json
//   kubectl get clusterimagepolicies.policy.sigstore.dev -o json > cip.json
//   kubectl get configmap config-policy-controller -n cosign-system -o json > cfg.json    (optional; default no-match-policy is deny)
//   kubectl get pods -A -o json > pods.json
//   cosign verify --key cosign.pub <image@digest> > verify-<n>.json   (save "FAILED" in the file when verification fails)
//   node scripts/image-admission.js --cluster-ref <ref> --authorization-ref <ref> --namespaces ns.json --cluster-image-policies cip.json
//        [--config cfg.json] --pods pods.json [--cosign <image@digest>=verify.json ...] --output adm.json
import fs from 'node:fs';
import { parseAdmission, assessAdmission } from '../lib/artifact-admission.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; }, all = n => args.flatMap((a, i) => a === n ? [args[i + 1]] : []);
const cluster = flag('--cluster-ref'), auth = flag('--authorization-ref'), out = flag('--output');
if (!cluster || !auth || !out || !flag('--namespaces') || !flag('--cluster-image-policies') || !flag('--pods')) { console.error('usage: image-admission.js --cluster-ref <ref> --authorization-ref <ref> --namespaces f --cluster-image-policies f [--config f] --pods f [--cosign <image>=<file> ...] --output f'); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
const raw = f => fs.readFileSync(f, 'utf8').replace(/^﻿/, ''), read = f => JSON.parse(raw(f));
let d;
try {
  const cosign = all('--cosign').map(spec => { const i = spec.lastIndexOf('='), image = spec.slice(0, i), text = raw(spec.slice(i + 1)).trim(); let ok = false, digest = (image.match(/sha256:[a-f0-9]{64}/) || [])[0] || null;
    try { const j = JSON.parse(text); ok = Array.isArray(j) && j.length > 0 && j.every(x => (x.critical || x.Critical)); const dg = (j[0]?.critical?.image?.['docker-manifest-digest'] || j[0]?.Critical?.Image?.['Docker-manifest-digest']); if (dg) digest = dg; } catch { ok = false; }
    return { image, digest, verified: ok, method: 'cosign' }; });
  d = parseAdmission({ namespaces: read(flag('--namespaces')), policies: read(flag('--cluster-image-policies')), config: flag('--config') ? read(flag('--config')) : null, pods: read(flag('--pods')), cosign });
} catch (e) { console.error(`Invalid export: ${e.code || e.message}`); process.exit(2); }
const at = new Date().toISOString(), details = { cluster_ref: cluster, authorization_ref: auth, ...d };
const event = { event_id: `image-admission:${cluster}:${at}`, kind: 'k8s.image_admission', observed_at: at, asset: { external_id: `k8s:${cluster}`, hostname: `Kubernetes ${cluster}`, os_family: 'linux', device_type: 'container', addresses: [] }, details };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ cluster, ...assessAdmission(d).summary, output: out }));
