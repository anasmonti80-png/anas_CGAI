// Convert a public vulnerability feed file into a cg.telemetry/1 file (read only; no download, no upload).
// Usage: node scripts/vuln-feed-to-telemetry.js <kev|epss|nvd|nvd-catalog> <input> <output> [--cves <file-or-list>] [--id <name>]
//   kev          CISA Known Exploited Vulnerabilities JSON (known_exploited_vulnerabilities.json)
//   epss         FIRST EPSS daily CSV (epss_scores-YYYY-MM-DD.csv, decompressed) or an api.first.org/data/v1/epss JSON response
//   nvd          NVD CVE API 2.0 JSON response: CVSS score, vector, attack vector and CWE per CVE
//   nvd-catalog  The same NVD response turned into a version-range vulnerability catalog from its application CPE matches
// --cves keeps only CVE IDs found in the given file (any text, e.g. an exported catalog) or comma list.
import fs from 'node:fs';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { parseKev, parseEpss, parseNvd, nvdCatalogEntries } from '../lib/vulnerability-intel.js';

const args = process.argv.slice(2), flag = name => { const i = args.indexOf(name); return i >= 0 ? args.splice(i, 2)[1] : null; };
const cvesArg = flag('--cves'), idArg = flag('--id');
const [mode, input, output] = args;
if (!['kev', 'epss', 'nvd', 'nvd-catalog'].includes(mode) || !input || !output) { console.error('Usage: node scripts/vuln-feed-to-telemetry.js <kev|epss|nvd|nvd-catalog> <input> <output> [--cves <file-or-list>] [--id <name>]'); process.exit(2); }
if (fs.existsSync(output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(1); }
const raw = fs.readFileSync(input, 'utf8').replace(/^﻿/, '');
const wanted = cvesArg ? new Set((fs.existsSync(cvesArg) ? fs.readFileSync(cvesArg, 'utf8') : cvesArg).match(/CVE-\d{4}-\d{4,8}/g) || []) : null;
const keep = list => (wanted ? list.filter(x => wanted.has(x.cve_id || x.vuln_id)) : list);
const asset = { external_id: `vuln-intel-${os.hostname().toLowerCase()}`, hostname: os.hostname(), os_family: { win32: 'windows', linux: 'linux', darwin: 'macos' }[process.platform] || 'unknown', device_type: 'server', addresses: [] };
const now = new Date().toISOString(), events = [];
if (mode === 'nvd-catalog') {
  const { entries, skipped } = nvdCatalogEntries(raw), kept = keep(entries);
  if (!kept.length) { console.error(`No application CPE version ranges found (${skipped.length} skipped).`); process.exit(1); }
  for (let i = 0; i < kept.length; i += 5000) events.push({ event_id: `catalog-${randomUUID()}`, kind: 'vulnerability.catalog', observed_at: now, asset, details: { catalog_id: `${idArg || 'NVD'}${kept.length > 5000 ? `-${i / 5000 + 1}` : ''}`, source: 'NIST NVD CVE API 2.0 (application CPE ranges)', published_at: now, entries: kept.slice(i, i + 5000) } });
  console.log(`Catalog: ${kept.length} product ranges from ${new Set(kept.map(e => e.vuln_id)).size} CVEs; skipped ${skipped.length} (${[...new Set(skipped.map(s => s.reason))].join(', ') || 'none'}).`);
} else {
  const feed = { kev: parseKev, epss: parseEpss, nvd: parseNvd }[mode](raw), kept = keep(feed.entries);
  if (!kept.length) { console.error('No matching CVE entries.'); process.exit(1); }
  if (!feed.published_at) { console.error('Feed has no publication date.'); process.exit(1); }
  for (let i = 0; i < kept.length; i += 5000) events.push({ event_id: `intel-${randomUUID()}`, kind: 'vulnerability.intel', observed_at: now, asset, details: { intel_id: `${idArg || feed.feed}${kept.length > 5000 ? `-${i / 5000 + 1}` : ''}`, feed: feed.feed, feed_version: feed.feed_version, published_at: feed.published_at, entries: kept.slice(i, i + 5000) } });
  console.log(`${feed.feed} ${feed.feed_version} published ${feed.published_at}: kept ${kept.length} of ${feed.entries.length} CVEs.`);
}
fs.writeFileSync(output, JSON.stringify({ schema_version: 'cg.telemetry/1', events }));
console.log(`Wrote ${events.length} event(s) to the requested private file. No upload performed.`);
