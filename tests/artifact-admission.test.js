import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { RuleSigner } from '../lib/rule-signing.js';
import { parseAdmission, assessAdmission, ArtifactAdmission } from '../lib/artifact-admission.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), F = n => path.join(ROOT, 'tests/fixtures/k8s/admission', n), read = n => JSON.parse(fs.readFileSync(F(n), 'utf8'));
const A = 'a'.repeat(64), C = 'c'.repeat(64);
const cosign = [{ image: `ghcr.io/lab/api@sha256:${A}`, digest: `sha256:${A}`, verified: true, method: 'cosign' }, { image: `registry.partner.example/app@sha256:${C}`, digest: `sha256:${C}`, verified: false, method: 'cosign' }];

test('images are admitted only in opted-in namespaces under an enforcing policy, warn mode and tag references are flagged, and failed signatures raise alerts (CG-158)', t => {
  const d = parseAdmission({ namespaces: read('namespaces.json'), policies: read('cluster-image-policies.json'), config: read('config.json'), pods: read('pods.json'), cosign });
  assert.equal(d.no_match_policy, 'warn'); assert.deepEqual(d.policies.map(p => [p.name, p.mode, p.authorities[0]]), [['lab-images-signed', 'enforce', 'key'], ['partner-images-warn', 'warn', 'keyless']]);
  const a = assessAdmission(d), img = n => a.images.find(i => i.image.includes(n));
  assert.deepEqual([img('lab/api').admission, img('lab/api').signature, img('lab/api').findings], ['enforced', 'verified', []]);
  assert.deepEqual([img('busybox').admission, img('busybox').findings], ['not-enforced', ['no-policy-warn', 'referenced-by-tag', 'no-signature-evidence']], 'no matching policy with no-match warn is not enforced');
  assert.deepEqual([img('partner').admission, img('partner').signature], ['not-enforced', 'failed']); assert.ok(img('partner').findings.includes('warn-mode-only'));
  assert.equal(img('lab/tool').admission, 'not-covered', 'a namespace without the opt-in label is not covered');
  assert.equal(assessAdmission({ ...d, no_match_policy: 'deny' }).images.find(i => i.image.includes('busybox')).admission, 'enforced', 'with the default deny, unmatched images are rejected');
  const s = new Store(':memory:'); t.after(() => s.close()); const dom = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = dom.createSource('a', { name: 'K8s', stale_seconds: 86400 });
  dom.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'adm-158', kind: 'k8s.image_admission', observed_at: new Date().toISOString(), asset: { external_id: 'k8s:prod', hostname: 'prod', os_family: 'linux', device_type: 'container', addresses: [] }, details: { cluster_ref: 'prod', authorization_ref: 'SEC-158', ...d } }] });
  assert.deepEqual(s.all("SELECT severity FROM alerts WHERE rule_id='CG-IMAGE-ADMISSION-158' ORDER BY severity").map(x => x.severity), ['high', 'medium'], 'the failed partner signature and the unenforced busybox sidecar; the dev namespace is shown, not alerted');
});

test('the integrity register reports the signed release manifest, signed rule versions and image admission from what verifies now (CG-158)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg158-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const signer = new RuleSigner(dir);
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  s.run("INSERT INTO detection_hypotheses(id,title,source_type,source_ref,technique_ids,severity,rationale,logic,status,author,created_at,version,active_version) VALUES (1,'r','internal','x','[]','high','x','{}','approved','a','2026-11-01T00:00:00Z',1,1)");
  const content = { id: 1, version: 1, title: 'r' }; s.run('INSERT INTO hypothesis_versions(hypothesis_id,version,content,signature,signer_fingerprint,approved_by,approved_at) VALUES (1,1,?,?,?,?,?)', JSON.stringify(content), signer.sign(content), signer.fingerprint, 'a', '2026-11-01T00:00:00Z');
  let release = { state: 'unsigned', changed: [], added: [], missing: [] };
  const v = () => new ArtifactAdmission(s, { selfDefense: { release: () => release }, signer }).view(), st = (x, k) => x.register.find(r => r.artifact === k).state;
  let x = v(); assert.deepEqual([st(x, 'application'), st(x, 'agent'), st(x, 'rules'), st(x, 'images')], ['unsigned', 'unsigned', 'verified', 'not-imported']);
  release = { state: 'modified', changed: ['lib/domain.js'], added: [], missing: [] }; x = v(); assert.match(x.register[0].detail, /1 changed/);
  s.run("UPDATE hypothesis_versions SET content=? WHERE hypothesis_id=1", JSON.stringify({ ...content, title: 'changed' })); assert.equal(st(v(), 'rules'), 'tampered', 'a rule changed after signing no longer verifies');
  const out = path.join(dir, 'a.json'), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/image-admission.js'), '--cluster-ref', 'prod', '--authorization-ref', 'SEC-158', '--namespaces', F('namespaces.json'), '--cluster-image-policies', F('cluster-image-policies.json'), '--config', F('config.json'), '--pods', F('pods.json'), '--cosign', `ghcr.io/lab/api@sha256:${A}=${F('verify-api.json')}`, '--cosign', `registry.partner.example/app@sha256:${C}=${F('verify-partner.txt')}`, '--output', out], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr); assert.deepEqual(JSON.parse(r.stdout.trim()).verified, 1, 'the FAILED file is not a verification');
});
