// CG-106 Software supply chain evidence (offline, read-only).
//   node scripts/supply-chain.js sbom --input <CycloneDX or SPDX JSON> --osv <OSV advisories JSON array> --project <name> --output <out.json>
//   node scripts/supply-chain.js ci --repo <path> --project <name> --output <out.json>       (workflows and committed secrets)
//   node scripts/supply-chain.js verify --artifact <file> --project <name> --output <out.json>
//        [--checksums SHA256SUMS] [--signature <file> --public-key <PEM>] [--provenance <in-toto JSON> --trusted-builder <id>]
import fs from 'node:fs';
import { parseSbom, matchSbom, reviewRepository, verifyArtifact } from '../lib/supply-chain.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; }, all = n => args.flatMap((a, i) => a === n ? [args[i + 1]] : []), read = n => flag(n) ? fs.readFileSync(flag(n), 'utf8') : null;
const [mode] = args, project = flag('--project'), output = flag('--output');
if (!['sbom', 'ci', 'verify'].includes(mode) || !project || !output) { console.error('usage: supply-chain.js sbom|ci|verify --project <name> --output <out.json> ...'); process.exit(2); }
if (fs.existsSync(output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(2); }
let kind, details;
try {
  if (mode === 'sbom') { const sbom = parseSbom(JSON.parse(read('--input'))), osv = flag('--osv') ? JSON.parse(read('--osv')) : []; kind = 'supply_chain.sbom'; details = { project, format: sbom.format, components: sbom.components.length, without_purl: sbom.components.filter(c => !c.purl).length, without_hash: sbom.components.filter(c => !c.sha256).length, without_license: sbom.components.filter(c => !c.license).length, advisories_checked: osv.length, vulnerable: matchSbom(sbom, osv).slice(0, 500) }; }
  else if (mode === 'ci') { const r = reviewRepository(flag('--repo') || '.'); kind = 'supply_chain.ci_review'; details = { project, files_scanned: r.files_scanned, findings: r.findings.slice(0, 500) }; }
  else { kind = 'supply_chain.artifact'; details = { project, ...verifyArtifact({ artifact: flag('--artifact'), checksums: read('--checksums'), signature: read('--signature'), publicKey: read('--public-key'), provenance: flag('--provenance') ? JSON.parse(read('--provenance')) : null, trustedBuilders: all('--trusted-builder') }) }; }
} catch (e) { console.error(`Refused: ${e.message}`); process.exit(1); }
const at = new Date().toISOString();
fs.writeFileSync(output, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [{ event_id: `${kind}:${project}:${at}`, kind, observed_at: at, asset: { external_id: `project:${project}`, hostname: project, os_family: 'unknown', device_type: 'unknown', addresses: [] }, details }] }, null, 2), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ mode, project, output, ...(kind === 'supply_chain.sbom' ? { components: details.components, vulnerable: details.vulnerable.length } : kind === 'supply_chain.ci_review' ? { files: details.files_scanned, findings: details.findings.length } : { verified: details.verified }) }));
