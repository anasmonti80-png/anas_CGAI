// CG-105 Kubernetes and container evidence from read-only exports.
//   node scripts/k8s-to-telemetry.js audit --input <audit.log (JSON lines)> --cluster-ref <ref> --output <out.json>
//   node scripts/k8s-to-telemetry.js rbac --cluster-ref <ref> --output <out.json> --clusterrolebindings <json> [--rolebindings <json>] [--clusterroles <json>] [--namespaces <json>]
//        (each from: kubectl get <kind> -A -o json)
//   node scripts/k8s-to-telemetry.js trivy --input <trivy image -f json report> --cluster-ref <ref> --output <out.json>
// Only risky audit events are kept in detail (with counts for the rest); request and response bodies are never copied.
import fs from 'node:fs';
import { auditRisk, rbacFindings, trivySummary } from '../lib/kubernetes.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; }, [mode] = args;
const cluster = flag('--cluster-ref'), output = flag('--output'), json = n => flag(n) ? JSON.parse(fs.readFileSync(flag(n), 'utf8')).items || [] : [];
if (!['audit', 'rbac', 'trivy'].includes(mode) || !cluster || !output) { console.error('usage: k8s-to-telemetry.js audit|rbac|trivy --cluster-ref <ref> --output <out.json> ...'); process.exit(2); }
if (fs.existsSync(output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(2); }
const at = new Date().toISOString(), asset = { external_id: `k8s:${cluster}`, hostname: cluster, os_family: 'linux', device_type: 'container', addresses: [] };
let kind, details;
if (mode === 'audit') {
  const lines = fs.readFileSync(flag('--input'), 'utf8').split(/\r?\n/).filter(Boolean), risky = [], verbs = {}; let total = 0, skipped = 0;
  for (const l of lines) { let e; try { e = JSON.parse(l); } catch { skipped++; continue; } if (e.kind !== 'Event' || !String(e.apiVersion || '').startsWith('audit.k8s.io/')) { skipped++; continue; } if (e.stage && e.stage !== 'ResponseComplete') continue; total++; verbs[e.verb] = (verbs[e.verb] || 0) + 1;
    const f = auditRisk(e); if (f && risky.length < 500) risky.push({ audit_id: e.auditID, time: e.stageTimestamp || e.requestReceivedTimestamp, verb: e.verb, user: e.user?.username || null, source_ip: (e.sourceIPs || [])[0] || null, resource: e.objectRef?.resource || null, subresource: e.objectRef?.subresource || null, namespace: e.objectRef?.namespace || null, name: e.objectRef?.name || null, ...f }); }
  kind = 'k8s.audit_batch'; details = { cluster_ref: cluster, events_total: total, skipped_lines: skipped, by_verb: verbs, risky };
} else if (mode === 'rbac') { kind = 'k8s.rbac_snapshot'; const r = rbacFindings({ clusterRoleBindings: json('--clusterrolebindings'), roleBindings: json('--rolebindings'), clusterRoles: json('--clusterroles'), namespaces: json('--namespaces') }); details = { cluster_ref: cluster, ...r, findings: r.findings.slice(0, 500) }; }
else { kind = 'container.image_scan'; details = { cluster_ref: cluster, scanner: 'trivy', ...trivySummary(JSON.parse(fs.readFileSync(flag('--input'), 'utf8'))) }; }
fs.writeFileSync(output, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [{ event_id: `${kind}:${cluster}:${at}`, kind, observed_at: at, asset, details }] }, null, 2), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ mode, cluster, output, ...(kind === 'k8s.audit_batch' ? { events: details.events_total, risky: details.risky.length } : kind === 'k8s.rbac_snapshot' ? { findings: details.findings.length } : { critical: details.critical, fixable_critical: details.fixable_critical.length }) }));
