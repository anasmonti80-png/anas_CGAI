// CG-106 Software supply chain: SBOM (CycloneDX or SPDX JSON) matched against OSV advisories, CI/CD pipeline review
// (unpinned third-party actions, secrets echoed or committed, risky triggers, broad token permissions), and artifact
// verification (SHA-256 against a published checksum list, detached signature with a trusted public key, and SLSA
// in-toto provenance subject digest and builder). Everything is offline and read-only.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, createPublicKey, verify } from 'node:crypto';

export function parseSbom(doc) {
  if (doc.bomFormat === 'CycloneDX') return { format: `CycloneDX ${doc.specVersion || ''}`.trim(), components: (doc.components || []).map(c => ({ name: c.name, version: c.version || null, purl: c.purl || null, sha256: (c.hashes || []).find(h => /SHA-?256/i.test(h.alg))?.content || null, license: c.licenses?.[0]?.license?.id || c.licenses?.[0]?.expression || null })) };
  if (doc.spdxVersion) return { format: doc.spdxVersion, components: (doc.packages || []).filter(p => p.SPDXID !== doc.documentDescribes?.[0]).map(p => ({ name: p.name, version: p.versionInfo || null, purl: (p.externalRefs || []).find(r => r.referenceType === 'purl')?.referenceLocator || null, sha256: (p.checksums || []).find(c => c.algorithm === 'SHA256')?.checksumValue || null, license: p.licenseConcluded && p.licenseConcluded !== 'NOASSERTION' ? p.licenseConcluded : null })) };
  throw new Error('unsupported SBOM: expected CycloneDX or SPDX JSON');
}
const ECO = { npm: 'npm', pypi: 'PyPI', maven: 'Maven', golang: 'Go', nuget: 'NuGet', gem: 'RubyGems', cargo: 'crates.io', deb: 'Debian', composer: 'Packagist' };
export function purlKey(purl) { const m = /^pkg:([a-z]+)\/(.+?)@([^?#]+)/.exec(purl || ''); return m ? { ecosystem: ECO[m[1]] || m[1], name: decodeURIComponent(m[2]), version: decodeURIComponent(m[3]) } : null; }
const cmp = (a, b) => { const x = String(a).split(/[.+-]/), y = String(b).split(/[.+-]/); for (let i = 0; i < Math.max(x.length, y.length); i++) { const p = x[i] ?? '0', q = y[i] ?? '0', n = /^\d+$/.test(p) && /^\d+$/.test(q) ? Number(p) - Number(q) : p.localeCompare(q); if (n) return Math.sign(n); } return 0; };
export function affected(osv, eco, name, version) {
  return (osv.affected || []).some(a => a.package?.ecosystem === eco && a.package?.name === name && ((a.versions || []).includes(version) || (a.ranges || []).some(r => { let introduced = null, inRange = false; for (const e of r.events || []) { if (e.introduced !== undefined) introduced = e.introduced; if (e.fixed !== undefined && introduced !== null) { if ((introduced === '0' || cmp(version, introduced) >= 0) && cmp(version, e.fixed) < 0) inRange = true; introduced = null; } } if (introduced !== null && (introduced === '0' || cmp(version, introduced) >= 0)) inRange = true; return inRange; })));
}
const fixedIn = (osv, eco, name) => (osv.affected || []).filter(a => a.package?.ecosystem === eco && a.package?.name === name).flatMap(a => (a.ranges || []).flatMap(r => (r.events || []).filter(e => e.fixed).map(e => e.fixed)))[0] || null;
export function matchSbom(sbom, advisories) {
  return sbom.components.flatMap(c => { const k = purlKey(c.purl); if (!k) return []; return advisories.filter(o => affected(o, k.ecosystem, k.name, k.version)).map(o => ({ component: `${k.name}@${k.version}`, ecosystem: k.ecosystem, id: o.id, aliases: (o.aliases || []).slice(0, 5), summary: String(o.summary || '').slice(0, 200), severity: /critical/i.test(JSON.stringify(o.database_specific || {})) ? 'critical' : /high/i.test(JSON.stringify(o.database_specific || {})) ? 'high' : 'medium', fixed: fixedIn(o, k.ecosystem, k.name) })); });
}
// Committed secrets: provider token shapes and private keys (values are never stored, only file, line and type).
const SECRET_PATTERNS = [['aws-access-key', /\bAKIA[0-9A-Z]{16}\b/], ['github-token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/], ['slack-token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/], ['private-key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/], ['google-api-key', /\bAIza[0-9A-Za-z_-]{35}\b/], ['stripe-live-key', /\bsk_live_[0-9a-zA-Z]{24,}\b/]];
export function reviewRepository(root, { maxFiles = 5000 } = {}) {
  const findings = [], add = (id, severity, file, line, en, ar) => findings.push({ id, severity, file, line, title: en, title_ar: ar }), files = [];
  const walk = d => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { if (files.length >= maxFiles) return; if (['.git', 'node_modules', 'data', 'tenants'].includes(e.name)) continue; const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (fs.statSync(p).size < 1024 * 1024) files.push(p); } };
  walk(root);
  for (const f of files) {
    const rel = path.relative(root, f).replace(/\\/g, '/'); let text; try { text = fs.readFileSync(f, 'utf8'); } catch { continue; } if (text.includes('\u0000')) continue;
    const lines = text.split(/\r?\n/), workflow = /^\.github\/workflows\/.+\.ya?ml$/.test(rel) || /(^|\/)\.gitlab-ci\.ya?ml$/.test(rel);
    lines.forEach((l, i) => { for (const [type, re] of SECRET_PATTERNS) if (re.test(l)) add(`committed-secret:${type}`, /(^|\/)(tests?|fixtures?|examples?)\//i.test(rel) ? 'low' : 'critical', rel, i + 1, `Possible ${type} committed in ${rel}:${i + 1}`, `احتمال وجود ${type} محفوظ في ${rel}:${i + 1}`); });
    if (!workflow) continue;
    if (/^on:[\s\S]*?pull_request_target/m.test(text) && /ref:\s*\$\{\{\s*github\.event\.pull_request\.head/.test(text)) add('pr-target-checkout', 'high', rel, null, 'pull_request_target checks out untrusted pull request code with repository secrets', 'pull_request_target يجلب شيفرة طلب دمج غير موثوقة مع أسرار المستودع');
    if (!/^permissions:/m.test(text)) add('default-token-permissions', 'medium', rel, null, 'Workflow does not restrict GITHUB_TOKEN permissions', 'سير العمل لا يقيّد صلاحيات GITHUB_TOKEN');
    if (/^permissions:\s*write-all/m.test(text)) add('write-all-permissions', 'high', rel, null, 'Workflow grants write-all token permissions', 'سير العمل يمنح صلاحيات كتابة كاملة للرمز');
    lines.forEach((l, i) => { const m = /uses:\s*([^@\s]+)@([^\s#]+)/.exec(l); if (m && !m[1].startsWith('./') && !/^[0-9a-f]{40}$/.test(m[2])) add(`unpinned-action:${m[1]}`, 'medium', rel, i + 1, `Third-party action ${m[1]}@${m[2]} is not pinned to a commit SHA`, `الإجراء الخارجي ${m[1]}@${m[2]} غير مثبت على بصمة commit`);
      if (/(echo|printf|cat)\b.*\$\{\{\s*secrets\./.test(l)) add('secret-echoed', 'high', rel, i + 1, `A secret is printed in ${rel}:${i + 1}`, `سر يُطبع في ${rel}:${i + 1}`); });
  }
  return { files_scanned: files.length, findings };
}
export function verifyArtifact({ artifact, checksums = null, signature = null, publicKey = null, provenance = null, trustedBuilders = [] }) {
  const buf = fs.readFileSync(artifact), sha256 = createHash('sha256').update(buf).digest('hex'), name = path.basename(artifact), checks = [];
  if (checksums) { const line = checksums.split(/\r?\n/).map(l => l.trim().split(/\s+\*?/)).find(([, f]) => f === name); checks.push({ check: 'checksum', ok: Boolean(line && line[0].toLowerCase() === sha256), detail: line ? (line[0].toLowerCase() === sha256 ? 'matches the published SHA-256' : 'does not match the published SHA-256') : 'artifact is not listed in the checksum file' }); }
  if (signature && publicKey) { let ok = false; try { const key = createPublicKey(publicKey); ok = verify(key.asymmetricKeyType === 'ed25519' ? null : 'sha256', buf, key, Buffer.from(signature.trim(), /^[A-Za-z0-9+/=\s]+$/.test(signature.trim()) ? 'base64' : 'hex')); } catch { ok = false; } checks.push({ check: 'signature', ok, detail: ok ? 'detached signature verifies with the trusted key' : 'signature does not verify with the trusted key' }); }
  if (provenance) { const subj = (provenance.subject || []).find(s => s.digest?.sha256 === sha256), builder = provenance.predicate?.runDetails?.builder?.id || provenance.predicate?.builder?.id || null, slsa = /slsa\.dev\/provenance/.test(provenance.predicateType || '');
    checks.push({ check: 'provenance-subject', ok: Boolean(slsa && subj), detail: !slsa ? 'not a SLSA provenance statement' : subj ? 'provenance subject digest matches the artifact' : 'artifact digest is not a provenance subject' });
    checks.push({ check: 'provenance-builder', ok: Boolean(builder && trustedBuilders.includes(builder)), detail: builder ? `builder ${builder}${trustedBuilders.includes(builder) ? ' is trusted' : ' is not in the trusted list'}` : 'no builder identity' }); }
  return { artifact: name, sha256, size: buf.length, checks, verified: checks.length > 0 && checks.every(c => c.ok) };
}
