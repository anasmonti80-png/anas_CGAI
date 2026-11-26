import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { evaluateToolShell, attackCasesView } from '../lib/attack-cases.js';
import { normalizeLogLines } from '../lib/log-normalizer.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const iisLines = day => fs.readFileSync(path.join(ROOT, 'tests/fixtures/toolshell/iis-u_ex251119.log'), 'utf8').split('{{DATE}}').join(day).split(/\r?\n/);
function fixture(t) {
  const s = new Store(':memory:'); t.after(() => s.close()); const now = Date.now(), d = new Domain(s, { clock: () => now }), at = h => new Date(now - h * 3600000).toISOString();
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', at(0)); const src = d.createSource('a', { name: 'Sensors', stale_seconds: 86400 });
  const sp = { external_id: 'sp-01', hostname: 'SP-01', os_family: 'windows', device_type: 'server', addresses: ['10.30.0.20'] };
  const put = (id, kind, details, asset = sp, h = 1) => d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: id, kind, observed_at: at(h), asset, details }] });
  put('cat', 'vulnerability.catalog', { catalog_id: 'MS-2025-07', source: 'Synthetic copy of the July 2025 SharePoint advisory', published_at: at(48), entries: [{ vuln_id: 'CVE-2025-53770', vendor: 'Microsoft', product: 'Microsoft SharePoint Server 2019', affected: { min_version: '16.0', max_version_exclusive: '16.0.10417.20027' }, fixed_version: '16.0.10417.20027', fixed_by_update: null, cvss: 9.8, kev: true, summary: 'SharePoint deserialization of untrusted data (ToolShell)' }] }, { external_id: 'catalogs', hostname: 'CATALOGS', os_family: 'unknown', device_type: 'server', addresses: [] });
  const inv = version => put(`inv-${version}`, 'software.inventory', { inventory_id: 'INV-SP-01', os: { name: 'Microsoft Windows Server 2019', version: '10.0.17763', build: '17763' }, software: [{ name: 'Microsoft SharePoint Server 2019', vendor: 'Microsoft Corporation', version, install_date: null, source: 'uninstall-registry' }], updates: [], evidence_ref: 'SYNTHETIC-INV-SP' });
  const iis = () => put('iis', 'log.batch', { batch_id: 'IIS-SP-01', source_name: 'iis', format: 'iis-w3c', lines: iisLines(at(2).slice(0, 10)) });
  const proc = () => put('proc', 'endpoint.process_causality', { causality_id: 'C-SP', collector: { type: 'sysmon', name: 'Synthetic Sysmon', trust: 'high', evidence_ref: 'SYN' }, window: { starts_at: at(3), ends_at: at(1) }, processes: [
    { process_id: 'w', parent_process_id: null, image_path: 'C:\\Windows\\System32\\inetsrv\\w3wp.exe', command_line: 'w3wp.exe -ap SharePoint', user_ref: 'svc-sp', started_at: at(3), signer: { status: 'signed', publisher: 'Microsoft' }, integrity: 'medium', evidence_ref: 'edr:1' },
    { process_id: 'p', parent_process_id: 'w', image_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', command_line: 'powershell.exe -EncodedCommand SQBFAFgA', user_ref: 'svc-sp', started_at: at(2), signer: { status: 'signed', publisher: 'Microsoft' }, integrity: 'medium', evidence_ref: 'edr:2' }],
    service_changes: [], scheduled_task_changes: [{ change_id: 't', process_id: 'p', task_name: '\\SyntheticUpdater', action: 'created', command: 'C:\\ProgramData\\u.exe', occurred_at: at(1.5), evidence_ref: 'edr:3' }], connections: [] });
  const tamper = (type, name, action, id) => put(id, 'endpoint.defense_tamper', { tamper_id: id, control: { type, name }, change: { action, occurred_at: at(1.2), actor_ref: 'svc-sp', process_ref: 'synthetic', method: 'service-control', previous_value: 'on', new_value: 'off', time_skew_seconds: null }, context: { authorization_ref: null, change_ticket_ref: null, maintenance_window: false, preceding_errors: 0, recovered_at: null, recovery_evidence_ref: null }, evidence_ref: id });
  return { s, d, put, inv, iis, proc, tamper, now, sp };
}
const state = (d, now) => evaluateToolShell(d, { assetRef: 'sp-01', now })[0];

test('IIS W3C logs are parsed with the field header, query strings are dropped and only the referrer path is kept (CG-139)', () => {
  const r = normalizeLogLines('iis-w3c', iisLines('2026-11-20')); assert.equal(r.rejected.length, 0); assert.equal(r.records.length, 4);
  const post = r.records[2]; assert.deepEqual([post.action, post.query, post.src_ip, post.outcome, post.signature, post.category], ['POST', '/_layouts/15/ToolPane.aspx', '198.51.100.77', '200', '/_layouts/SignOut.aspx', 'web']);
  assert.ok(!JSON.stringify(r.records).includes('DisplayMode'), 'the query string is not stored');
  assert.equal(normalizeLogLines('iis-w3c', ['2026-11-20 08:00:00 10.0.0.1 GET / - 80']).rejected.length, 1, 'a data line before the #Fields header is not guessed');
});

test('signals are joined per SharePoint server and a single file signature is never proof of compromise (CG-139)', t => {
  const { s, d, put, inv, iis, proc, now } = fixture(t);
  inv('16.0.10417.20018'); let c = state(d, now); assert.equal(c.state, 'vulnerable-not-seen-exposed'); assert.deepEqual(c.identified_by, ['software-inventory']);
  put('finding', 'security.finding', { title: 'Web shell signature spinstall0.aspx detected', severity: 'high', description: 'Antivirus signature match' });
  c = state(d, now); assert.equal(c.state, 'suspected'); assert.match(c.note, /single web-shell file or signature is not proof/); assert.equal(c.confirmed, false);
  iis(); c = state(d, now); assert.deepEqual(c.kinds.sort(), ['exposure', 'file-signature', 'toolpane-post', 'vulnerable']); assert.equal(c.state, 'suspected', 'web activity without host behaviour stays suspected');
  proc(); c = state(d, now); assert.equal(c.state, 'probable-compromise'); assert.deepEqual(c.host_behaviour.sort(), ['scheduled-task', 'w3wp-shell']); assert.match(c.signals.find(x => x.signal === 'w3wp-shell').detail, /encoded command/);
  assert.match(c.note, /analyst must confirm/); assert.equal(c.confirmed, false);
  const alerts = s.all("SELECT dedup_key,severity FROM alerts WHERE rule_id='CG-TOOLSHELL-139' ORDER BY dedup_key").map(a => [a.dedup_key, a.severity]);
  assert.deepEqual(alerts, [['CG-TOOLSHELL-139:sp-01:probable-compromise', 'critical'], ['CG-TOOLSHELL-139:sp-01:suspected', 'high'], ['CG-TOOLSHELL-139:sp-01:vulnerable-not-seen-exposed', 'medium']]);
});

test('protection and GPO changes count as host behaviour, a patched build is not vulnerable, and missing visibility is stated (CG-139)', t => {
  const { d, inv, iis, tamper, put, now } = fixture(t);
  inv('16.0.10417.20027'); assert.equal(state(d, now).state, 'no-evidence', 'the fixed build is not vulnerable'); assert.deepEqual(state(d, now).missing_visibility.sort(), ['process', 'web_logs']);
  iis(); assert.equal(state(d, now).state, 'suspected');
  tamper('policy', 'Default Domain Policy (GPO)', 'policy-changed', 'GPO-1'); let c = state(d, now); assert.equal(c.state, 'probable-compromise'); assert.ok(c.kinds.includes('policy-change'));
  tamper('antivirus', 'Defender Antivirus', 'disabled', 'AV-1'); c = state(d, now); assert.ok(c.kinds.includes('protection-change'));
  put('ctx', 'asset.context', { owner: { owner_id: 'it', display_name: 'IT', contact: null }, business_service: 'Intranet SharePoint', service_name: null, site: 'HQ', data_sensitivity: 'internal', maintenance_windows: [], service_criticality: 'high' }, { external_id: 'sp-02', hostname: 'SP-02', os_family: 'windows', device_type: 'server', addresses: ['10.30.0.21'] });
  const v = attackCasesView(d), sp2 = v.cases[0].servers.find(x => x.asset_ref === 'sp-02'); assert.equal(sp2.state, 'no-evidence'); assert.match(sp2.note, /not proof the server is safe/);
  assert.ok(v.cases[0].steps.some(([en]) => /machine keys/.test(en))); assert.ok(v.cases[0].references[0].url.startsWith('https://www.microsoft.com/'));
});
