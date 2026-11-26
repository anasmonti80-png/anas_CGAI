// CG-158 Signed artifact admission. One integrity register for what CyberGuard runs and deploys:
//  - the application and its collector/agent scripts: the Ed25519 release manifest (CG-128) covers lib, public,
//    scripts, server.js and package.json, so a changed or added file breaks verification;
//  - detection rules: every approved version is signed with the installation key (CG-066) and the running version is
//    re-verified;
//  - container images: Sigstore cosign verification results and the Kubernetes policy-controller configuration,
//    imported read-only from the owner. Namespaces are enforced only when labelled policy.sigstore.dev/include=true;
//    a ClusterImagePolicy in warn mode does not block admission; images matching no policy are rejected unless
//    no-match-policy says otherwise. Images referenced by tag rather than digest are flagged.
import { fail } from './common.js';

export const REFERENCES = [
  { id: 'Sigstore policy-controller', url: 'https://docs.sigstore.dev/policy-controller/overview/' },
  { id: 'cosign verify', url: 'https://docs.sigstore.dev/cosign/verifying/verify/' },
];
const globToRe = g => new RegExp(`^${String(g).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\u0000/g, '.*')}$`);
const normalise = img => { let s = String(img).split('@')[0]; if (!/^[^/]+\.[^/]+\//.test(s) && !/^localhost/.test(s)) s = `index.docker.io/${s.includes('/') ? s : `library/${s}`}`; return s.replace(/:[^/:]+$/, ''); };

export function parseAdmission({ namespaces, policies, config, pods, cosign = [] }) {
  const items = (j, n) => { const v = j?.items; fail(Array.isArray(v), 400, `not_kubectl_${n}_list`); return v; };
  const ns = items(namespaces, 'namespace').map(n => ({ name: String(n.metadata?.name), opted_in: n.metadata?.labels?.['policy.sigstore.dev/include'] === 'true' }));
  const cips = items(policies, 'clusterimagepolicy').map(p => ({ name: String(p.metadata?.name), globs: (p.spec?.images || []).map(i => String(i.glob)), mode: p.spec?.mode === 'warn' ? 'warn' : 'enforce',
    authorities: (p.spec?.authorities || []).map(a => a.key ? 'key' : a.keyless ? 'keyless' : a.static ? `static-${a.static.action}` : 'other') }));
  const noMatch = ['warn', 'allow', 'deny'].includes(config?.data?.['no-match-policy']) ? config.data['no-match-policy'] : 'deny';
  const images = []; for (const p of items(pods, 'pod')) { const n = p.metadata?.namespace; for (const c of [...(p.spec?.containers || []), ...(p.spec?.initContainers || [])]) { const st = (p.status?.containerStatuses || []).find(x => x.name === c.name), digest = (String(st?.imageID || '').match(/sha256:[a-f0-9]{64}/) || String(c.image).match(/sha256:[a-f0-9]{64}/) || [])[0] || null;
    images.push({ namespace: String(n), pod: String(p.metadata?.name), image: String(c.image), by_digest: /@sha256:[a-f0-9]{64}$/.test(String(c.image)), digest }); } }
  const verified = cosign.map(c => ({ image: String(c.image), digest: c.digest || null, verified: c.verified === true, method: c.method || null }));
  return { namespaces: ns, policies: cips, no_match_policy: noMatch, images: images.slice(0, 20000), cosign: verified };
}

export function assessAdmission(d) {
  const rows = d.images.map(i => {
    const ns = d.namespaces.find(n => n.name === i.namespace), matching = d.policies.filter(p => p.globs.some(g => globToRe(g).test(normalise(i.image)) || globToRe(g).test(i.image)));
    const enforced = !!ns?.opted_in && (matching.some(p => p.mode === 'enforce') || (!matching.length && d.no_match_policy === 'deny'));
    const sig = d.cosign.find(c => (i.digest && c.digest === i.digest) || c.image === i.image), findings = [];
    if (!ns?.opted_in) findings.push('namespace-not-opted-in');
    if (ns?.opted_in && matching.length && matching.every(p => p.mode === 'warn')) findings.push('warn-mode-only');
    if (ns?.opted_in && !matching.length && d.no_match_policy !== 'deny') findings.push(`no-policy-${d.no_match_policy}`);
    if (!i.by_digest) findings.push('referenced-by-tag');
    if (!sig) findings.push('no-signature-evidence'); else if (!sig.verified) findings.push('signature-failed');
    return { ...i, policies: matching.map(p => p.name), admission: enforced ? 'enforced' : ns?.opted_in ? 'not-enforced' : 'not-covered', signature: sig ? (sig.verified ? 'verified' : 'failed') : 'unknown', method: sig?.method || null, findings };
  });
  const uniq = [...new Map(rows.map(r => [`${r.namespace}|${r.image}`, r])).values()];
  return { images: uniq, summary: { images: uniq.length, enforced: uniq.filter(r => r.admission === 'enforced').length, verified: uniq.filter(r => r.signature === 'verified').length, failed: uniq.filter(r => r.signature === 'failed').length, by_tag: uniq.filter(r => !r.by_digest).length },
    namespaces: d.namespaces.filter(n => !/^kube-|^cosign-system$/.test(n.name)), policies: d.policies, no_match_policy: d.no_match_policy };
}

export class ArtifactAdmission {
  constructor(store, { selfDefense, signer } = {}) { Object.assign(this, { s: store, selfDefense, signer }); }
  rules() { if (!this.signer) return { state: 'unknown', total: 0, verified: 0 };
    const rows = this.s.all('SELECT h.id,h.active_version,v.content,v.signature FROM detection_hypotheses h JOIN hypothesis_versions v ON v.hypothesis_id=h.id AND v.version=h.active_version WHERE h.active_version IS NOT NULL');
    const ok = rows.filter(r => { try { return this.signer.verify(JSON.parse(r.content), r.signature); } catch { return false; } }).length;
    return { state: rows.length === ok ? 'verified' : 'tampered', total: rows.length, verified: ok }; }
  view() {
    const rel = this.selfDefense ? this.selfDefense.release() : { state: 'unknown' }, rules = this.rules();
    const latest = this.s.all("SELECT observed_at,payload FROM events WHERE kind='k8s.image_admission' ORDER BY observed_at DESC,received_at DESC LIMIT 1").map(r => ({ ...JSON.parse(r.payload).details, observed_at: r.observed_at }))[0] || null;
    const adm = latest ? assessAdmission(latest) : null;
    const register = [
      { artifact: 'application', title: 'CyberGuard application', title_ar: 'تطبيق CyberGuard', mechanism: 'Ed25519 signed release manifest (CG-128) over lib, public, scripts, server.js and package.json', mechanism_ar: 'بيان إصدار موقّع Ed25519 ‏(CG-128) يغطي lib وpublic وscripts وserver.js وpackage.json', state: rel.state, detail: rel.state === 'verified' ? null : rel.state === 'unsigned' ? 'Development build: no signed manifest or no pinned public key.' : `${(rel.changed || []).length} changed, ${(rel.added || []).length} added, ${(rel.missing || []).length} missing files`, detail_ar: rel.state === 'verified' ? null : rel.state === 'unsigned' ? 'بناء تطوير: لا بيان موقّع أو لا مفتاح عام مثبّت.' : `${(rel.changed || []).length} ملف معدّل، و${(rel.added || []).length} مضاف، و${(rel.missing || []).length} مفقود` },
      { artifact: 'agent', title: 'Collectors and agent scripts', title_ar: 'المجمّعات وسكربتات الوكيل', mechanism: 'Covered by the same release manifest (scripts/)', mechanism_ar: 'يغطيها بيان الإصدار نفسه (scripts/)', state: rel.state, detail: null },
      { artifact: 'rules', title: 'Detection rules', title_ar: 'قواعد الكشف', mechanism: 'Every approved version signed with the installation Ed25519 key (CG-066); the running version is re-verified', mechanism_ar: 'كل نسخة معتمدة موقعة بمفتاح Ed25519 الخاص بالتثبيت (CG-066)، ويُعاد التحقق من النسخة العاملة', state: rules.total ? rules.state : 'none', detail: `${rules.verified} / ${rules.total} running rule versions verify`, detail_ar: `${rules.verified} / ${rules.total} نسخة قاعدة عاملة يتحقق توقيعها` },
      { artifact: 'images', title: 'Container images', title_ar: 'صور الحاويات', mechanism: 'Sigstore cosign signatures enforced by the Kubernetes policy-controller', mechanism_ar: 'توقيعات Sigstore cosign يفرضها policy-controller في Kubernetes', state: !adm ? 'not-imported' : adm.summary.failed ? 'failed' : adm.summary.verified === adm.summary.images && adm.summary.enforced === adm.summary.images ? 'verified' : 'partial', detail: adm ? `${adm.summary.verified} / ${adm.summary.images} signed and verified, ${adm.summary.enforced} enforced at admission` : 'No Kubernetes export imported (not applicable without Kubernetes).', detail_ar: adm ? `${adm.summary.verified} / ${adm.summary.images} موقّعة ومتحقق منها، و${adm.summary.enforced} مفروضة عند القبول` : 'لا تصدير من Kubernetes (لا ينطبق دون Kubernetes).' },
    ];
    return { register, admission: adm, observed_at: latest?.observed_at || null, references: REFERENCES,
      claim: 'Integrity of what CyberGuard runs is shown from signatures that verify now, not from a claim: the signed release manifest for the application and its collectors, signed rule versions, and cosign signatures enforced at Kubernetes admission where Kubernetes is used.',
      claim_ar: 'تُعرض سلامة ما يشغّله CyberGuard من توقيعات تُتحقق الآن لا من ادعاء: بيان الإصدار الموقّع للتطبيق ومجمّعاته، ونسخ القواعد الموقعة، وتوقيعات cosign المفروضة عند القبول في Kubernetes حيث يُستخدم.' };
  }
}
