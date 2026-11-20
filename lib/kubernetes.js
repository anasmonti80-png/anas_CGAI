// CG-105 Kubernetes and container security from read-only sources: the Kubernetes audit log (audit.k8s.io/v1),
// RBAC and namespace snapshots (kubectl get ... -o json), Trivy image scans (trivy image -f json) and Falco runtime
// events (falco-json, CG-094). Works with any conformant cluster; managed EKS/AKS/GKE audit delivery is a later step.
const SYSTEM = /^system:(serviceaccount:kube-system:|kube-|node:|apiserver|kube-controller-manager|kube-scheduler)/;
export function auditRisk(e) {
  const r = e.objectRef || {}, u = e.user?.username || '', code = e.responseStatus?.code ?? 0, ok = code < 400, ro = e.requestObject || {};
  if (!ok) return null;
  // Anonymous access to the public discovery endpoints (/version, /healthz, /livez, /readyz) is a cluster default.
  if (u === 'system:anonymous' && r.resource && !/^\/(version|healthz|livez|readyz)(\/|\?|$)/.test(e.requestURI || '')) return { id: 'anonymous-access', severity: 'high', title: `Anonymous request allowed: ${e.verb} ${r.resource || e.requestURI}`, title_ar: `طلب مجهول الهوية مسموح: ${e.verb} ${r.resource || e.requestURI}` };
  if (r.resource === 'pods' && ['exec', 'attach'].includes(r.subresource) && ['create', 'get'].includes(e.verb)) return { id: 'pod-exec', severity: 'medium', title: `${u} opened a shell in pod ${r.namespace}/${r.name}`, title_ar: `${u} فتح طرفية داخل الحاوية ${r.namespace}/${r.name}` };
  if (r.resource === 'secrets' && ['get', 'list', 'watch'].includes(e.verb) && !SYSTEM.test(u)) return { id: 'secret-read', severity: r.name ? 'medium' : 'high', title: `${u} read ${r.name ? `secret ${r.namespace}/${r.name}` : `all secrets in ${r.namespace || 'every namespace'}`}`, title_ar: `${u} قرأ ${r.name ? `السر ${r.namespace}/${r.name}` : `كل الأسرار في ${r.namespace || 'كل النطاقات'}`}` };
  if (['clusterrolebindings', 'rolebindings'].includes(r.resource) && ['create', 'update', 'patch'].includes(e.verb) && ro.roleRef?.name === 'cluster-admin') return { id: 'cluster-admin-granted', severity: 'critical', title: `${u} bound cluster-admin (${r.name})`, title_ar: `${u} منح صلاحية cluster-admin (${r.name})` };
  const spec = r.resource === 'pods' && e.verb === 'create' ? ro.spec : ['deployments', 'daemonsets', 'statefulsets'].includes(r.resource) && e.verb === 'create' ? ro.spec?.template?.spec : null;
  if (spec && ((spec.containers || []).some(c => c.securityContext?.privileged) || spec.hostPID || spec.hostNetwork)) return { id: 'privileged-workload', severity: 'high', title: `${u} created a privileged workload ${r.namespace}/${r.name || ro.metadata?.name || ''}`, title_ar: `${u} أنشأ حمل عمل بصلاحيات مرتفعة ${r.namespace}/${r.name || ro.metadata?.name || ''}` };
  return null;
}
export function rbacFindings({ clusterRoleBindings = [], roleBindings = [], clusterRoles = [], namespaces = [] }) {
  const f = [], add = (id, severity, en, ar) => f.push({ id, severity, title: en, title_ar: ar }), broadGroups = ['system:anonymous', 'system:unauthenticated', 'system:authenticated'];
  for (const b of [...clusterRoleBindings, ...roleBindings]) { const subs = b.subjects || [], name = b.metadata?.name, scope = b.metadata?.namespace ? `${b.metadata.namespace}/${name}` : name;
    for (const s of subs.filter(s => broadGroups.includes(s.name))) add(`broad-subject:${scope}:${s.name}`, 'critical', `Binding ${scope} grants ${b.roleRef?.name} to ${s.name}`, `الربط ${scope} يمنح ${b.roleRef?.name} لـ${s.name}`);
    // The built-in cluster-admin binding to the system:masters group exists in every cluster and is not reported.
    if (b.roleRef?.name === 'cluster-admin' && !(name || '').startsWith('system:')) for (const s of subs.filter(s => !(s.kind === 'Group' && s.name === 'system:masters'))) add(`cluster-admin:${scope}:${s.kind}:${s.name}`, 'high', `${s.kind} ${s.namespace ? `${s.namespace}/` : ''}${s.name} has cluster-admin through ${scope}`, `${s.kind} ${s.name} لديه cluster-admin عبر ${scope}`); }
  for (const r of clusterRoles.filter(r => !(r.metadata?.name || '').startsWith('system:') && r.metadata?.name !== 'cluster-admin')) if ((r.rules || []).some(x => (x.verbs || []).includes('*') && (x.resources || []).includes('*'))) add(`wildcard-role:${r.metadata.name}`, 'medium', `ClusterRole ${r.metadata.name} allows every verb on every resource`, `الدور ${r.metadata.name} يسمح بكل الأفعال على كل الموارد`);
  const userNs = namespaces.filter(n => !/^kube-/.test(n.metadata?.name || ''));
  const psa = userNs.map(n => ({ name: n.metadata?.name, enforce: n.metadata?.labels?.['pod-security.kubernetes.io/enforce'] || null }));
  for (const n of psa.filter(n => !n.enforce || n.enforce === 'privileged')) add(`psa-missing:${n.name}`, 'medium', `Namespace ${n.name} has no Pod Security Admission enforce level (or privileged)`, `النطاق ${n.name} بلا مستوى فرض لأمان الحاويات (أو privileged)`);
  return { findings: f, pod_security: psa };
}
export function trivySummary(report) {
  const vulns = (report.Results || []).flatMap(r => (r.Vulnerabilities || []).map(v => ({ id: v.VulnerabilityID, pkg: v.PkgName, installed: v.InstalledVersion, fixed: v.FixedVersion || null, severity: String(v.Severity || 'UNKNOWN').toLowerCase(), target: r.Target })));
  const by = s => vulns.filter(v => v.severity === s).length;
  return { image: report.ArtifactName || null, os: report.Metadata?.OS ? `${report.Metadata.OS.Family} ${report.Metadata.OS.Name}` : null, critical: by('critical'), high: by('high'), medium: by('medium'), low: by('low'), fixable_critical: vulns.filter(v => v.severity === 'critical' && v.fixed).slice(0, 50).map(v => ({ id: v.id, pkg: v.pkg, installed: v.installed, fixed: v.fixed })) };
}
