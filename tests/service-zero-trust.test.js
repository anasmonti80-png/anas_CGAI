import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { assessMesh, parseCertificates, assessCredentials, s2sView } from '../lib/service-zero-trust.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), FX = path.join(ROOT, 'tests/fixtures/s2s'), read = n => JSON.parse(fs.readFileSync(path.join(FX, n), 'utf8'));
const NS = read('namespaces.json').items.map(n => n.metadata.name);

test('namespaces are judged by effective mTLS mode and identity-tier authorization, and without a mesh the checks are not applicable (CG-151)', () => {
  const m = assessMesh({ namespaces: NS, peerAuth: read('peer-authentications.json').items, authz: read('authorization-policies.json').items }), ns = n => m.namespaces.find(x => x.namespace === n);
  assert.equal(m.mesh_mode, 'PERMISSIVE'); assert.deepEqual(m.namespaces.map(x => x.namespace), ['payments', 'billing', 'reporting'], 'system namespaces are skipped');
  assert.deepEqual([ns('payments').mtls, ns('payments').mtls_source, ns('payments').authz], ['STRICT', 'namespace', 'identity-tier']);
  assert.deepEqual(ns('payments').overrides, [{ name: 'metrics-port', mode: 'STRICT', ports: ['9090'] }], 'a port with mTLS disabled is an exception even under STRICT');
  assert.deepEqual([ns('billing').mtls, ns('billing').mtls_source, ns('billing').authz], ['PERMISSIVE', 'mesh', 'network-tier-only'], 'IP blocks are network-tier, not identity');
  assert.equal(ns('reporting').authz, 'allow-all');
  assert.deepEqual(assessMesh({ namespaces: ['a'], peerAuth: [], authz: [] }), { mesh: false, namespaces: [] }, 'no mesh is not applicable, not a failure');
  const unset = assessMesh({ namespaces: ['x'], peerAuth: [{ kind: 'PeerAuthentication', metadata: { name: 'p', namespace: 'x' }, spec: {} }], authz: [{ kind: 'AuthorizationPolicy', metadata: { name: 'a', namespace: 'x' }, spec: { rules: [{ from: [{ source: { principals: ['cluster.local/ns/y/sa/z'] } }] }] } }] });
  assert.equal(unset.namespaces[0].mtls, 'PERMISSIVE', 'UNSET without a parent is PERMISSIVE');
  assert.ok(unset.namespaces[0].findings.some(f => f.id === 'identity-policy-without-strict-mtls' && f.severity === 'high'), 'identity rules need strict mTLS');
  const certs = parseCertificates(['svid-short.pem', 'static-long.pem'].map(n => ({ name: n, pem: fs.readFileSync(path.join(FX, n), 'utf8') })), { now: Date.parse('2026-11-27T00:00:00Z') });
  assert.deepEqual(certs.map(c => [c.spiffe_id, c.lifetime_hours, c.long_lived]), [['spiffe://lab.example/ns/payments/sa/api', 1, false], [null, 17520, true]]);
  assert.equal(parseCertificates([{ name: 'x', pem: 'nope' }])[0].error, 'not a PEM certificate');
});

test('service credentials are reviewed for authentication, secrets, lifetime and rotation and gaps raise alerts (CG-151)', t => {
  const c = assessCredentials(read('inventory.json'), Date.parse('2026-11-27T00:00:00Z'));
  assert.deepEqual(c.map(x => [x.class, x.findings]), [['identity', []], ['static-credential', ['rotation-overdue']], ['static-credential', []], ['static-credential', ['rotation-unknown', 'no-rotation-period']], ['none', ['no-authentication']]]);
  assert.throws(() => assessCredentials([{ from: 'a', to: 'b', method: 'magic' }]), /invalid_s2s_entry_0/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg151-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'K8s', stale_seconds: 86400 });
  const run = extra => { const out = path.join(dir, `o-${Math.random()}.json`), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/service-zero-trust.js'), '--environment-ref', 'prod-cluster', '--authorization-ref', 'SEC-151', ...extra, '--output', out], { encoding: 'utf8' }); if (r.status === 0) d.ingest('a', src.id, JSON.parse(fs.readFileSync(out, 'utf8'))); return r; };
  const r = run(['--namespaces', path.join(FX, 'namespaces.json'), '--peer-authentications', path.join(FX, 'peer-authentications.json'), '--authorization-policies', path.join(FX, 'authorization-policies.json'), '--certs', FX, '--inventory', path.join(FX, 'inventory.json')]);
  assert.equal(r.status, 0, r.stderr);
  const titles = s.all("SELECT title,severity FROM alerts WHERE rule_id='CG-S2S-ZT-151'").map(a => `${a.severity}:${a.title.split(' / ')[0].replace('Services prod-cluster: ', '')}`).sort();
  assert.ok(titles.includes('high:reporting/cron → reporting/db-proxy: no service authentication'));
  assert.ok(titles.some(x => x.startsWith('medium:payments/api → billing/ledger: credential rotation overdue')));
  assert.ok(titles.some(x => x.startsWith('medium:certificate static-long.pem lives 17520 hours')));
  assert.ok(titles.some(x => x.startsWith('medium:billing: mTLS is PERMISSIVE')) && titles.some(x => x.startsWith('medium:reporting: No authorization')));
  assert.ok(!titles.some(x => x.includes('network attributes')), 'network-tier-only is a low finding without an alert');
  assert.equal(s2sView(s).environments[0].mesh.namespaces.length, 3);
  const withKey = path.join(dir, 'keys'); fs.mkdirSync(withKey); fs.writeFileSync(path.join(withKey, 'k.pem'), '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n');
  assert.equal(run(['--certs', withKey]).status, 2, 'private keys are refused');
  assert.equal(run(['--inventory', path.join(FX, 'inventory.json')]).status, 0, 'works without a mesh export');
  assert.equal(s2sView(s).environments[0].mesh.mesh, false);
});
