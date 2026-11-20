import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseSbom, matchSbom, reviewRepository, verifyArtifact, affected } from '../lib/supply-chain.js';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const cyclonedx = { bomFormat: 'CycloneDX', specVersion: '1.5', components: [
  { type: 'library', name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20', hashes: [{ alg: 'SHA-256', content: 'a'.repeat(64) }], licenses: [{ license: { id: 'MIT' } }] },
  { type: 'library', name: 'minimist', version: '1.2.6', purl: 'pkg:npm/minimist@1.2.6', licenses: [{ license: { id: 'MIT' } }] },
  { type: 'library', name: 'internal-lib', version: '0.1.0' }] };
// Shapes of the real OSV records GHSA-35jh-r3h4-6jhm (lodash command injection) and GHSA-xvch-5gv4-984h (minimist prototype pollution).
const osv = [{ id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], summary: 'Command Injection in lodash', database_specific: { severity: 'HIGH' }, affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] },
  { id: 'GHSA-xvch-5gv4-984h', aliases: ['CVE-2021-44906'], summary: 'Prototype Pollution in minimist', database_specific: { severity: 'CRITICAL' }, affected: [{ package: { ecosystem: 'npm', name: 'minimist' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.2.4' }, { introduced: '1.0.0' }, { fixed: '1.2.6' }] }] }] }];

test('SBOM components are matched to OSV ranges and gaps in identifiers, hashes and licences are counted (CG-106)', () => {
  const sbom = parseSbom(cyclonedx); assert.equal(sbom.format, 'CycloneDX 1.5'); assert.equal(sbom.components.length, 3);
  assert.deepEqual(matchSbom(sbom, osv).map(v => [v.component, v.id, v.severity, v.fixed]), [['lodash@4.17.20', 'GHSA-35jh-r3h4-6jhm', 'high', '4.17.21']], 'minimist 1.2.6 is the fixed version and is not reported');
  assert.equal(affected(osv[1], 'npm', 'minimist', '1.2.5'), true); assert.equal(affected(osv[1], 'npm', 'minimist', '0.2.4'), false);
  const spdx = parseSbom({ spdxVersion: 'SPDX-2.3', documentDescribes: ['SPDXRef-root'], packages: [{ SPDXID: 'SPDXRef-root', name: 'app' }, { SPDXID: 'SPDXRef-1', name: 'minimist', versionInfo: '1.2.5', licenseConcluded: 'MIT', externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:npm/minimist@1.2.5' }], checksums: [{ algorithm: 'SHA256', checksumValue: 'b'.repeat(64) }] }] });
  assert.deepEqual(matchSbom(spdx, osv).map(v => v.id), ['GHSA-xvch-5gv4-984h']); assert.throws(() => parseSbom({}), /unsupported SBOM/);
});

test('CI/CD review finds unpinned actions, risky triggers, broad permissions, printed and committed secrets; this repository is clean (CG-106)', t => {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'cg106-repo-')); t.after(() => fs.rmSync(repo, { recursive: true, force: true }));
  fs.mkdirSync(path.join(repo, '.github/workflows'), { recursive: true }); fs.mkdirSync(path.join(repo, 'config'));
  fs.writeFileSync(path.join(repo, '.github/workflows/build.yml'), 'on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - uses: ./local-action\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n');
  fs.writeFileSync(path.join(repo, '.github/workflows/release.yml'), 'permissions: write-all\non: push\njobs:\n  r:\n    steps:\n      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020\n');
  fs.writeFileSync(path.join(repo, 'config/aws.env'), `AWS_ACCESS_KEY_ID=${'AKIA'}IOSFODNN7EXAMPLE\n`);
  const r = reviewRepository(repo), ids = r.findings.map(f => [f.id, f.severity]).sort();
  assert.deepEqual(ids, [['committed-secret:aws-access-key', 'critical'], ['default-token-permissions', 'medium'], ['pr-target-checkout', 'high'], ['secret-echoed', 'high'], ['unpinned-action:actions/checkout', 'medium'], ['write-all-permissions', 'high']]);
  assert.ok(!JSON.stringify(r).includes('IOSFODNN7EXAMPLE'), 'the secret value is never stored');
  const own = reviewRepository(ROOT); assert.ok(own.files_scanned > 100); assert.deepEqual(own.findings.filter(f => f.severity !== 'low'), [], 'CyberGuard pins its actions, limits token permissions and commits no credentials');
});

test('artifacts are verified by checksum, signature and SLSA provenance, and the evidence alerts on failures (CG-106)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg106-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const art = path.join(dir, 'agent-1.4.2.tar.gz'); fs.writeFileSync(art, 'synthetic release bytes'); const sha = createHash('sha256').update('synthetic release bytes').digest('hex');
  const { publicKey, privateKey } = generateKeyPairSync('ed25519'), pub = publicKey.export({ type: 'spki', format: 'pem' }), sig = sign(null, fs.readFileSync(art), privateKey).toString('base64');
  const prov = { _type: 'https://in-toto.io/Statement/v1', subject: [{ name: 'agent-1.4.2.tar.gz', digest: { sha256: sha } }], predicateType: 'https://slsa.dev/provenance/v1', predicate: { runDetails: { builder: { id: 'https://github.com/actions/runner/github-hosted' } } } };
  const ok = verifyArtifact({ artifact: art, checksums: `${sha}  agent-1.4.2.tar.gz\n`, signature: sig, publicKey: pub, provenance: prov, trustedBuilders: ['https://github.com/actions/runner/github-hosted'] });
  assert.equal(ok.verified, true); assert.deepEqual(ok.checks.map(c => c.check), ['checksum', 'signature', 'provenance-subject', 'provenance-builder']);
  const other = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  const bad = verifyArtifact({ artifact: art, checksums: `${'0'.repeat(64)}  agent-1.4.2.tar.gz\n`, signature: sig, publicKey: other, provenance: prov, trustedBuilders: [] });
  assert.deepEqual(bad.checks.map(c => c.ok), [false, false, true, false]);
  for (const [f, v] of [['sig', sig], ['pub.pem', other], ['SHA256SUMS', `${sha}  agent-1.4.2.tar.gz\n`], ['prov.json', JSON.stringify(prov)]]) fs.writeFileSync(path.join(dir, f), v);
  const out = path.join(dir, 'v.json'), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/supply-chain.js'), 'verify', '--artifact', art, '--project', 'edge-agent', '--output', out, '--checksums', path.join(dir, 'SHA256SUMS'), '--signature', path.join(dir, 'sig'), '--public-key', path.join(dir, 'pub.pem')], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr); assert.equal(JSON.parse(r.stdout).verified, false, 'signature by an untrusted key fails');
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, { clock: () => Date.now() });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = d.createSource('admin-a', { name: 'Build pipeline', stale_seconds: 86400 }); d.ingest('admin-a', src.id, JSON.parse(fs.readFileSync(out, 'utf8')));
  const sb = path.join(dir, 'sbom.json'), ov = path.join(dir, 'osv.json'), out2 = path.join(dir, 's.json'); fs.writeFileSync(sb, JSON.stringify(cyclonedx)); fs.writeFileSync(ov, JSON.stringify(osv));
  assert.equal(spawnSync(process.execPath, [path.join(ROOT, 'scripts/supply-chain.js'), 'sbom', '--input', sb, '--osv', ov, '--project', 'edge-agent', '--output', out2]).status, 0); d.ingest('admin-a', src.id, JSON.parse(fs.readFileSync(out2, 'utf8')));
  assert.equal(s.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-SUPPLY-106'").n, 2, 'one failed artifact and one fixable dependency');
  const v = d.supplyChain().projects[0]; assert.equal(v.project, 'edge-agent'); assert.equal(v.sbom.without_purl, 1); assert.equal(v.artifacts[0].verified, false); assert.ok(d.supplyChain().claim_ar.includes('SLSA'));
});
