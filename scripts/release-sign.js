// CG-128 Signed release manifest for CyberGuard's own code.
//   node scripts/release-sign.js keygen --private <path outside the repository> --public deploy/release-signing-public.pem
//   node scripts/release-sign.js sign --private <path> --version 1.4.0      (writes release-manifest.json)
//   node scripts/release-sign.js verify                                       (exit 1 when the code differs)
// The private key never belongs in the repository; the public key is what installations pin.
import fs from 'node:fs';
import path from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { signRelease, verifyRelease } from '../lib/self-defense.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; }, [mode] = args;
const pubFile = path.resolve(flag('--public') || path.join(ROOT, 'deploy', 'release-signing-public.pem')), manifestFile = path.resolve(flag('--manifest') || path.join(ROOT, 'release-manifest.json'));
const die = m => { console.error(m); process.exit(2); };
if (mode === 'keygen') {
  const priv = path.resolve(flag('--private') || die('--private <path outside the repository> required'));
  if (priv.startsWith(path.resolve(ROOT) + path.sep)) die('The private key must be stored outside the repository.');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519'); fs.writeFileSync(priv, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
  fs.mkdirSync(path.dirname(pubFile), { recursive: true }); fs.writeFileSync(pubFile, publicKey.export({ type: 'spki', format: 'pem' })); console.log(JSON.stringify({ private_key: priv, public_key: pubFile }));
} else if (mode === 'sign') {
  const priv = flag('--private') || die('--private <path> required'), version = flag('--version') || die('--version required');
  const m = signRelease(ROOT, fs.readFileSync(path.resolve(priv), 'utf8'), version); fs.writeFileSync(manifestFile, JSON.stringify(m, null, 2) + '\n'); console.log(JSON.stringify({ manifest: manifestFile, files: Object.keys(m.files).length, signer: m.signer_fingerprint }));
} else if (mode === 'verify') {
  if (!fs.existsSync(manifestFile) || !fs.existsSync(pubFile)) die('No release manifest or public key: this is an unsigned development build.');
  const r = verifyRelease(ROOT, JSON.parse(fs.readFileSync(manifestFile, 'utf8')), fs.readFileSync(pubFile, 'utf8')); console.log(JSON.stringify(r, null, 2)); process.exit(r.state === 'verified' ? 0 : 1);
} else die('usage: release-sign.js keygen | sign | verify');
