// CG-179 Crypto-agility inventory. The owner imports what TLS, SSH and VPN endpoints actually negotiate (scanner or
// configuration export): protocol versions, key exchanges, certificate or host-key algorithm and size, ciphers, the
// product and whether it supports post-quantum algorithms. CyberGuard reports, per endpoint:
//  - legacy cryptography: SSL/TLS 1.0/1.1, SSH protocol 1, IKEv1, RC4/3DES/DES/NULL/EXPORT ciphers, MD5/SHA-1 signatures,
//    RSA or finite-field DH below 2048 bits (alerted);
//  - reliance on quantum-vulnerable public-key algorithms (RSA, DH, ECDH/ECDSA, X25519/Ed25519) unless a post-quantum or
//    hybrid key exchange (ML-KEM, FIPS 203) is negotiated; signatures move to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205);
//  - readiness: migrate only where the product supports it; where it does not, nothing is forced — the plan waits for
//    the vendor. CyberGuard never changes a device's algorithms.
export const REFERENCES = [
  { id: 'FIPS 203 ML-KEM', url: 'https://csrc.nist.gov/pubs/fips/203/final' },
  { id: 'FIPS 204 ML-DSA', url: 'https://csrc.nist.gov/pubs/fips/204/final' },
  { id: 'FIPS 205 SLH-DSA', url: 'https://csrc.nist.gov/pubs/fips/205/final' },
  { id: 'NIST IR 8547 Transition to PQC Standards', url: 'https://csrc.nist.gov/pubs/ir/8547/final' },
];
export const PROTOCOLS = ['tls', 'ssh', 'ipsec', 'openvpn', 'wireguard'];
const LEGACY_VERSIONS = /^(ssl\d|tls1\.0|tls1\.1|ssh1|ikev1)$/i, LEGACY_CIPHERS = /(rc4|3des|des-cbc|^des|null|export)/i, LEGACY_SIG = /(md5|sha1)/i;
const PQ_KEX = /(mlkem|ml-kem|kyber|sntrup)/i, PQ_SIG = /^(ml-dsa|slh-dsa)$/i;
const READINESS = { supported: 'ready-to-migrate', 'vendor-roadmap': 'wait-for-vendor', 'not-supported': 'do-not-force', unknown: 'confirm-with-vendor' };

export function assessEndpoint(i) {
  const legacy = [];
  for (const v of i.versions) if (LEGACY_VERSIONS.test(v)) legacy.push(`version:${v}`);
  for (const c of i.ciphers) if (LEGACY_CIPHERS.test(c)) legacy.push(`cipher:${c}`);
  if (i.signature_hash && LEGACY_SIG.test(i.signature_hash)) legacy.push(`signature-hash:${i.signature_hash}`);
  if (i.key?.algorithm === 'rsa' && i.key.bits < 2048) legacy.push(`rsa-key:${i.key.bits}`);
  for (const k of i.key_exchange) { const m = String(k).match(/^(dh|ffdhe|dh-group)[-_]?(\d+)$/i); if (m && Number(m[2]) < 2048 && Number(m[2]) > 64) legacy.push(`dh:${m[2]}`); if (/group(1|2|5)$/i.test(k)) legacy.push(`dh:${k}`); }
  const pqKex = i.key_exchange.some(k => PQ_KEX.test(k)), pqSig = PQ_SIG.test(i.key?.algorithm || '');
  const vulnerable = [...(pqKex ? [] : i.key_exchange.filter(k => !PQ_KEX.test(k)).length ? ['key-exchange'] : []), ...(pqSig || !i.key ? [] : ['signature'])];
  const readiness = pqKex && (pqSig || !i.key) ? 'migrated' : READINESS[i.pqc_support];
  const recommendation = readiness === 'migrated' ? 'Post-quantum algorithms negotiated; keep classical fallbacks under review.'
    : readiness === 'ready-to-migrate' ? `The product supports post-quantum algorithms: plan ${pqKex ? '' : 'a hybrid ML-KEM (FIPS 203) key exchange'}${!pqKex && !pqSig ? ' and ' : ''}${pqSig ? '' : 'ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) certificates'} in a test window first.`
    : readiness === 'wait-for-vendor' ? 'Vendor roadmap only: do not change algorithms on this device; track the vendor release.'
    : readiness === 'do-not-force' ? 'The product does not support post-quantum algorithms: nothing is forced on it; plan replacement or a supported version.'
    : 'Confirm post-quantum support with the vendor before planning any change.';
  return { legacy, quantum_vulnerable: vulnerable, readiness, recommendation, recommendation_ar: { migrated: 'تُستخدم خوارزميات ما بعد الكم؛ تُراجع البدائل التقليدية.', 'ready-to-migrate': 'المنتج يدعم خوارزميات ما بعد الكم: خطط للترحيل (ML-KEM للتبادل، وML-DSA أو SLH-DSA للشهادات) في نافذة اختبار أولًا.', 'wait-for-vendor': 'خارطة طريق المورد فقط: لا تغيير على هذا الجهاز؛ تُتابع إصدارات المورد.', 'do-not-force': 'المنتج لا يدعم خوارزميات ما بعد الكم: لا يُفرض عليه شيء؛ يُخطط لاستبداله أو لإصدار مدعوم.', 'confirm-with-vendor': 'أكّد دعم ما بعد الكم مع المورد قبل أي تخطيط.' }[readiness] };
}

export function cryptoView(store) {
  const latest = new Map();
  for (const r of store.all("SELECT observed_at,payload FROM events WHERE kind='crypto.inventory' ORDER BY observed_at,received_at")) for (const i of JSON.parse(r.payload).details.items) latest.set(`${i.protocol}|${i.endpoint}`, { ...i, observed_at: r.observed_at });
  const items = [...latest.values()].map(i => ({ ...i, ...assessEndpoint(i) })), count = f => items.filter(f).length;
  return { items, summary: { endpoints: items.length, legacy: count(i => i.legacy.length), quantum_vulnerable: count(i => i.quantum_vulnerable.length), ready_to_migrate: count(i => i.readiness === 'ready-to-migrate'), do_not_force: count(i => i.readiness === 'do-not-force'), migrated: count(i => i.readiness === 'migrated') }, references: REFERENCES,
    claim: 'Crypto-agility inventory from what endpoints actually negotiate: legacy protocols, ciphers and key sizes, reliance on quantum-vulnerable RSA, DH and elliptic-curve algorithms, and readiness for ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205). Migration is planned only where the product supports it; nothing is forced on a device that does not, and CyberGuard never changes algorithms itself.',
    claim_ar: 'جرد المرونة التشفيرية مما تتفاوض عليه نقاط الاتصال فعلًا: البروتوكولات والشفرات وأطوال المفاتيح القديمة، والاعتماد على خوارزميات RSA وDH والمنحنيات الإهليلجية المعرضة لحوسبة الكم، والجاهزية لـ ML-KEM ‏(FIPS 203) وML-DSA ‏(FIPS 204) وSLH-DSA ‏(FIPS 205). ولا يُخطط للترحيل إلا حيث يدعمه المنتج؛ ولا يُفرض شيء على جهاز لا يدعمه، ولا يغيّر CyberGuard الخوارزميات بنفسه.' };
}
