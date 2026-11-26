// CG-151 Service-to-service zero trust (NIST SP 800-207A, September 2023): access between APIs and microservices
// should rest on workload identities (SPIFFE) and identity-tier policies over mTLS, not only on network location.
// Inputs are read-only exports by the owner: Istio PeerAuthentication and AuthorizationPolicy objects and namespaces
// (kubectl get ... -o json), workload certificates (X.509-SVIDs, PEM) and a declared inventory of service-to-service
// credentials. Where no service mesh exists the mesh checks are "not applicable", not failures, and the declared
// inventory still reviews lifetime, secrets and rotation.
import { X509Certificate } from 'node:crypto';
import { fail } from './common.js';

export const METHODS = ['mtls-workload-identity', 'mtls-static-certificate', 'oauth-client-credentials', 'jwt', 'api-key', 'shared-secret', 'none'];
export const METHOD_CLASS = { 'mtls-workload-identity': 'identity', 'mtls-static-certificate': 'static-credential', 'oauth-client-credentials': 'static-credential', jwt: 'token', 'api-key': 'static-credential', 'shared-secret': 'static-credential', none: 'none' };
export const REFERENCES = [
  { id: 'NIST SP 800-207A', url: 'https://csrc.nist.gov/pubs/sp/800/207/a/final', note: 'A Zero Trust Architecture Model for Access Control in Cloud-Native Applications in Multi-Cloud Environments (September 2023)' },
  { id: 'SPIFFE concepts', url: 'https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/', note: 'SPIFFE IDs spiffe://trust-domain/workload; short-lived keys rotated automatically' },
  { id: 'SPIRE server', url: 'https://spiffe.io/docs/latest/deploying/spire_server/', note: 'default_x509_svid_ttl 1h, default_jwt_svid_ttl 5m' },
  { id: 'Istio PeerAuthentication', url: 'https://istio.io/latest/docs/reference/config/security/peer_authentication/', note: 'UNSET without a parent is treated as PERMISSIVE' },
  { id: 'Istio AuthorizationPolicy', url: 'https://istio.io/latest/docs/reference/config/security/authorization-policy/', note: 'An ALLOW policy with an empty spec allows nothing; source.principals requires mTLS' },
];
const DAY = 86400000;

function k8sItems(json, name) { const items = (typeof json === 'string' ? JSON.parse(json) : json)?.items; fail(Array.isArray(items), 400, `not_kubectl_${name}_list`); return items; }

// Effective mTLS per namespace: namespace-wide policy, else mesh-wide policy in the root namespace, else PERMISSIVE.
export function assessMesh({ namespaces, peerAuth = [], authz = [], rootNamespace = 'istio-system' }) {
  const pa = peerAuth.filter(p => p.kind === 'PeerAuthentication'), ap = authz.filter(p => p.kind === 'AuthorizationPolicy');
  if (!pa.length && !ap.length) return { mesh: false, namespaces: [] };
  const wide = ns => pa.find(p => p.metadata?.namespace === ns && !p.spec?.selector);
  const mode = p => String(p?.spec?.mtls?.mode || 'UNSET').toUpperCase();
  const meshMode = mode(wide(rootNamespace)), mesh = meshMode === 'UNSET' ? 'PERMISSIVE' : meshMode;
  return { mesh: true, mesh_mode: mesh, namespaces: namespaces.filter(n => n !== rootNamespace && !/^kube-/.test(n)).map(ns => {
    const own = wide(ns), m = own && mode(own) !== 'UNSET' ? mode(own) : mesh;
    const overrides = pa.filter(p => p.metadata?.namespace === ns && p.spec?.selector).map(p => ({ name: p.metadata.name, mode: mode(p), ports: Object.entries(p.spec?.portLevelMtls || {}).filter(([, v]) => String(v?.mode).toUpperCase() !== 'STRICT').map(([k]) => k) })).filter(o => o.mode === 'DISABLE' || o.mode === 'PERMISSIVE' || o.ports.length);
    const pols = ap.filter(p => p.metadata?.namespace === ns || p.metadata?.namespace === rootNamespace);
    const allow = pols.filter(p => !p.spec?.action || p.spec.action === 'ALLOW'), denyAll = allow.some(p => !p.spec || (!p.spec.rules && !p.spec.selector && !p.spec.action));
    const froms = pols.flatMap(p => (p.spec?.rules || []).flatMap(r => (r.from || []).map(f => f.source || {})));
    const identity = froms.some(s => (s.principals || []).length || (s.requestPrincipals || []).length), network = froms.some(s => (s.ipBlocks || []).length || (s.remoteIpBlocks || []).length || (s.namespaces || []).length);
    const allowAll = !pols.length || allow.some(p => (p.spec?.rules || []).some(r => !r.from && !r.to && !r.when));
    const authzTier = allowAll && !denyAll ? 'allow-all' : identity ? 'identity-tier' : network ? 'network-tier-only' : denyAll ? 'deny-by-default' : 'allow-all';
    const findings = [];
    if (m !== 'STRICT') findings.push({ id: 'mtls-not-strict', severity: m === 'DISABLE' ? 'high' : 'medium', detail: `mTLS is ${m}: plaintext service traffic is accepted`, detail_ar: `وضع mTLS هو ${m}: تُقبل حركة الخدمات غير المشفرة` });
    if (overrides.length) findings.push({ id: 'workload-mtls-exception', severity: 'medium', detail: `Workload exceptions: ${overrides.map(o => o.name).join(', ')}`, detail_ar: `استثناءات على مستوى الحمل: ${overrides.map(o => o.name).join('، ')}` });
    if (authzTier === 'allow-all') findings.push({ id: 'no-authorization', severity: 'medium', detail: 'No authorization policy restricts which services may call this namespace', detail_ar: 'لا سياسة تفويض تقيّد الخدمات التي يمكنها استدعاء هذه المساحة' });
    if (authzTier === 'network-tier-only') findings.push({ id: 'network-tier-only', severity: 'low', detail: 'Authorization uses network attributes only (IP blocks or namespaces), not service identities', detail_ar: 'التفويض يعتمد على خصائص الشبكة فقط (عناوين أو مساحات أسماء) لا على هويات الخدمات' });
    if (identity && m !== 'STRICT') findings.push({ id: 'identity-policy-without-strict-mtls', severity: 'high', detail: 'Principal-based rules need mTLS; plaintext callers bypass identity checks', detail_ar: 'قواعد الهوية تتطلب mTLS؛ والمتصل غير المشفر يتجاوز فحص الهوية' });
    return { namespace: ns, mtls: m, mtls_source: own && mode(own) !== 'UNSET' ? 'namespace' : 'mesh', overrides, authz: authzTier, policies: pols.length, findings };
  }) };
}

export function parseCertificates(pems, { maxLifetimeHours = 24, now = Date.now() } = {}) {
  return pems.map(({ name, pem }) => { let c; try { c = new X509Certificate(pem); } catch { return { name, error: 'not a PEM certificate' }; }
    const from = Date.parse(c.validFrom), to = Date.parse(c.validTo), life = Math.round((to - from) / 3600000), san = String(c.subjectAltName || '');
    const spiffe = (san.match(/URI:(spiffe:\/\/[^,\s]+)/) || [])[1] || null;
    return { name, spiffe_id: spiffe, trust_domain: spiffe ? spiffe.split('/')[2] : null, valid_to: new Date(to).toISOString(), lifetime_hours: life, expired: to < now, long_lived: life > maxLifetimeHours, fingerprint: c.fingerprint256 }; });
}

export function assessCredentials(inventory, now = Date.now()) {
  fail(Array.isArray(inventory) && inventory.length <= 2000, 400, 'invalid_s2s_inventory');
  return inventory.map((x, i) => { fail(x && x.from && x.to && METHODS.includes(x.method), 400, `invalid_s2s_entry_${i}`);
    const cls = METHOD_CLASS[x.method], rotated = x.last_rotated ? Date.parse(x.last_rotated) : null, every = Number(x.rotation_days) || null, findings = [];
    if (cls === 'none') findings.push('no-authentication');
    if (cls === 'static-credential' && !rotated) findings.push('rotation-unknown');
    if (cls === 'static-credential' && rotated && every && now - rotated > every * DAY) findings.push('rotation-overdue');
    if (cls === 'static-credential' && !every) findings.push('no-rotation-period');
    if (x.expires && Date.parse(x.expires) < now) findings.push('expired');
    return { from: String(x.from).slice(0, 120), to: String(x.to).slice(0, 120), method: x.method, class: cls, credential_store: x.credential_store ? String(x.credential_store).slice(0, 80) : null, last_rotated: x.last_rotated || null, rotation_days: every, findings }; });
}

export function s2sView(store) {
  const latest = new Map();
  for (const r of store.all("SELECT observed_at,payload FROM events WHERE kind='network.service_zero_trust' ORDER BY observed_at,received_at")) { const d = JSON.parse(r.payload).details; latest.set(d.environment_ref, { ...d, observed_at: r.observed_at }); }
  return { environments: [...latest.values()], references: REFERENCES,
    claim: 'Following NIST SP 800-207A, service-to-service access is judged by workload identity and identity-tier policies over strict mTLS, not by network location alone. Without a service mesh the mesh checks are not applicable; the declared credential inventory still reviews secrets, lifetime and rotation.',
    claim_ar: 'وفق NIST SP 800-207A، يُقيَّم الوصول بين الخدمات بهوية الحمل وسياسات طبقة الهوية فوق mTLS صارم، لا بموقع الشبكة وحده. ودون شبكة خدمات (service mesh) تكون فحوصها «غير منطبقة»، ويبقى جرد بيانات الاعتماد المعلن يراجع الأسرار والعمر والتجديد.' };
}
