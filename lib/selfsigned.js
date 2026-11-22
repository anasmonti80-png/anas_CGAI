// CG-052 Dependency-free self-signed X.509 v3 certificate for local HTTPS (RSA 2048, SHA-256, SAN localhost/127.0.0.1/::1).
// The key is generated on the machine that serves CyberGuard and stays in its data directory; it is never committed.
import { generateKeyPairSync, randomBytes, sign, X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';

const len = n => (n < 128 ? Buffer.from([n]) : (b => Buffer.concat([Buffer.from([0x80 | b.length]), b]))(Buffer.from(n.toString(16).padStart(n.toString(16).length + (n.toString(16).length % 2), '0'), 'hex')));
const tlv = (tag, body) => Buffer.concat([Buffer.from([tag]), len(body.length), body]);
const seq = (...parts) => tlv(0x30, Buffer.concat(parts));
const int = buf => tlv(0x02, buf[0] & 0x80 ? Buffer.concat([Buffer.from([0]), buf]) : buf);
const oid = dotted => { const p = dotted.split('.').map(Number), out = [40 * p[0] + p[1]]; for (const n of p.slice(2)) { const b = [n & 0x7f]; let v = n >>> 7; while (v) { b.unshift(0x80 | (v & 0x7f)); v >>>= 7; } out.push(...b); } return tlv(0x06, Buffer.from(out)); };
const utf8 = s => tlv(0x0c, Buffer.from(s, 'utf8'));
const time = d => { const iso = d.toISOString(); return d.getUTCFullYear() < 2050 ? tlv(0x17, Buffer.from(`${iso.slice(2, 4)}${iso.slice(5, 7)}${iso.slice(8, 10)}${iso.slice(11, 13)}${iso.slice(14, 16)}${iso.slice(17, 19)}Z`)) : tlv(0x18, Buffer.from(`${iso.slice(0, 4)}${iso.slice(5, 7)}${iso.slice(8, 10)}${iso.slice(11, 13)}${iso.slice(14, 16)}${iso.slice(17, 19)}Z`)); };
const ipBytes = ip => (isIP(ip) === 4 ? Buffer.from(ip.split('.').map(Number)) : Buffer.from(ip === '::1' ? '00000000000000000000000000000001' : ip.split(':').map(h => h.padStart(4, '0')).join(''), 'hex'));
const pem = (label, der) => `-----BEGIN ${label}-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;

// usage: 'server' (default), 'client' (device certificate for mutual TLS, CG-053) or 'ca' (an organisation CA that
// issues device certificates). With `issuer` ({cert, key, commonName}) the certificate is signed by that CA.
export function selfSignedCertificate({ commonName = 'CyberGuard local', hosts = ['localhost', '127.0.0.1', '::1'], days = 397, now = new Date(), usage = 'server', issuer = null } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const sha256Rsa = seq(oid('1.2.840.113549.1.1.11'), Buffer.from([0x05, 0x00])), nameOf = cn => seq(tlv(0x31, seq(oid('2.5.4.3'), utf8(cn)))), name = nameOf(commonName);
  const notBefore = new Date(now.getTime() - 60000), notAfter = new Date(now.getTime() + days * 86400000);
  const san = seq(...hosts.map(h => (isIP(h) ? tlv(0x87, ipBytes(h)) : tlv(0x82, Buffer.from(h, 'ascii')))));
  const ext = usage === 'ca'
    ? [seq(oid('2.5.29.19'), tlv(0x01, Buffer.from([0xff])), tlv(0x04, seq(tlv(0x01, Buffer.from([0xff]))))), seq(oid('2.5.29.15'), tlv(0x01, Buffer.from([0xff])), tlv(0x04, tlv(0x03, Buffer.from([0x01, 0x06]))))]
    : [seq(oid('2.5.29.19'), tlv(0x01, Buffer.from([0xff])), tlv(0x04, seq())), seq(oid('2.5.29.15'), tlv(0x01, Buffer.from([0xff])), tlv(0x04, tlv(0x03, Buffer.from([0x05, 0xa0])))), seq(oid('2.5.29.37'), tlv(0x04, seq(oid(usage === 'client' ? '1.3.6.1.5.5.7.3.2' : '1.3.6.1.5.5.7.3.1')))), ...(usage === 'server' ? [seq(oid('2.5.29.17'), tlv(0x04, san))] : [])];
  const extensions = tlv(0xa3, seq(...ext));
  // Positive and minimally encoded: a zero first byte would make the DER INTEGER illegally padded (about 1 in 512 certificates).
  const serial = randomBytes(16); serial[0] = (serial[0] & 0x7f) | 0x01;
  const signer = issuer ? { key: issuer.key, name: nameOf(issuer.commonName) } : { key: privateKey, name };
  const tbs = seq(tlv(0xa0, int(Buffer.from([2]))), int(serial), sha256Rsa, signer.name, seq(time(notBefore), time(notAfter)), name, publicKey.export({ type: 'spki', format: 'der' }), extensions);
  const der = seq(tbs, sha256Rsa, tlv(0x03, Buffer.concat([Buffer.from([0]), sign('sha256', tbs, signer.key)])));
  const cert = pem('CERTIFICATE', der), x509 = new X509Certificate(cert);
  if (!x509.verify(issuer ? new X509Certificate(issuer.cert).publicKey : publicKey)) throw new Error('certificate did not verify');
  return { cert, key: privateKey.export({ type: 'pkcs8', format: 'pem' }), commonName, fingerprint256: x509.fingerprint256, valid_to: new Date(x509.validTo).toISOString() };
}
