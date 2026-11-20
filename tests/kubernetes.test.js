import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { auditRisk, rbacFindings, trivySummary } from '../lib/kubernetes.js';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), FX = n => path.join(ROOT, 'tests/fixtures/k8s', n), json = n => JSON.parse(fs.readFileSync(FX(n), 'utf8'));

test('Kubernetes audit events flag exec, secret reads, cluster-admin grants, privileged workloads and anonymous access (CG-105)', () => {
  const events = fs.readFileSync(FX('audit.jsonl'), 'utf8').trim().split('\n').map(l => JSON.parse(l)), risks = events.map(e => auditRisk(e)?.id || null);
  assert.deepEqual(risks, [null, 'pod-exec', 'secret-read', 'cluster-admin-granted', 'privileged-workload', null, 'anonymous-access', null, null], 'system controllers and denied requests are not flagged');
  assert.equal(auditRisk(events[3]).severity, 'critical'); assert.equal(auditRisk(events[2]).severity, 'high', 'listing every secret in a namespace is high');
});

test('RBAC, Pod Security Admission and Trivy findings come from kubectl and trivy JSON (CG-105)', () => {
  const r = rbacFindings({ clusterRoleBindings: json('clusterrolebindings.json').items, clusterRoles: json('clusterroles.json').items, namespaces: json('namespaces.json').items });
  assert.deepEqual(r.findings.map(f => [f.id, f.severity]), [['cluster-admin:temp-admin:User:contractor-x', 'high'], ['broad-subject:view-all:system:authenticated', 'critical'], ['wildcard-role:legacy-ops', 'medium'], ['psa-missing:shop', 'medium'], ['psa-missing:default', 'medium']], 'the built-in system:masters binding is not reported');
  assert.deepEqual(r.pod_security, [{ name: 'payments', enforce: 'restricted' }, { name: 'shop', enforce: null }, { name: 'default', enforce: 'privileged' }]);
  const t = trivySummary(json('trivy.json')); assert.deepEqual([t.image, t.os, t.critical, t.high, t.medium], ['registry.example/shop/web:1.4.2', 'debian 12.5', 2, 1, 1]); assert.deepEqual(t.fixable_critical.map(v => v.id), ['CVE-2024-0001'], 'only fixable critical vulnerabilities are listed for action');
});

test('the converter feeds cluster evidence that raises alerts and shows source coverage (CG-105)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg105-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const run = (mode, extra) => { const out = path.join(dir, `${mode}.json`), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/k8s-to-telemetry.js'), mode, '--cluster-ref', 'prod-eu', '--output', out, ...extra], { encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); return JSON.parse(fs.readFileSync(out, 'utf8')); };
  const audit = run('audit', ['--input', FX('audit.jsonl')]), rbac = run('rbac', ['--clusterrolebindings', FX('clusterrolebindings.json'), '--clusterroles', FX('clusterroles.json'), '--namespaces', FX('namespaces.json')]), trivy = run('trivy', ['--input', FX('trivy.json')]);
  assert.equal(audit.events[0].details.events_total, 9); assert.equal(audit.events[0].details.risky.length, 5); assert.ok(!JSON.stringify(audit).includes('securityContext'), 'request bodies are not copied');
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, { clock: () => Date.now() });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = d.createSource('admin-a', { name: 'Kubernetes', stale_seconds: 86400 }); for (const b of [audit, rbac, trivy]) d.ingest('admin-a', src.id, b);
  const count = rule => s.get('SELECT COUNT(*) n FROM alerts WHERE rule_id=?', rule).n;
  assert.equal(count('CG-K8S-AUDIT-105'), 5); assert.equal(count('CG-K8S-RBAC-105'), 2, 'critical and high RBAC findings alert'); assert.equal(count('CG-CONTAINER-VULN-105'), 1);
  const v = d.kubernetesSecurity(), c = v.clusters[0]; assert.equal(c.cluster_ref, 'prod-eu'); assert.deepEqual([c.sources.audit_log, c.sources.rbac_snapshot, c.sources.image_scans], [true, true, 1]); assert.deepEqual(c.rbac.without_enforcement, ['shop', 'default']); assert.ok(v.claim_ar.includes('EKS'));
});
