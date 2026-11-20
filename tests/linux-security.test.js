import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { normalizeLogLines } from '../lib/log-normalizer.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), SCRIPT = path.join(ROOT, 'scripts', 'agent', 'linux-security.sh');
const h = c => c.repeat(64);
const posture = over => ({ enrolled_by: 'it-ops', collected_as_root: true, kernel: '6.8.0-49-generic', auditd: { state: 'running', rules: 12 }, journald: 'readable', ebpf: { state: 'supported', btf: true, unprivileged_bpf_disabled: '2', reason: 'kernel 6.8.0-49-generic with BTF' }, falco: { state: 'running', unit: 'falco-modern-bpf' },
  sudo: { sudoers: [{ path: '/etc/sudoers', sha256: h('a') }], no_prompt_rules: 0, full_all_grants: 1, groups: [{ group: 'sudo', members: ['ops'] }], use_source: 'journald', use_24h: [{ user: 'ops', as: 'root', command: 'apt', count: 3 }] },
  cron: [{ path: '/etc/crontab', sha256: h('b') }], systemd_units: [{ path: '/etc/systemd/system/app.service', sha256: h('c') }], ...over });

test('Linux posture covers auditd, journald, eBPF and Falco and alerts on new persistence, sudoers changes and NOPASSWD (CG-094)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.now(); const d = new Domain(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString());
  const src = d.createSource('admin-a', { name: 'Linux agents', stale_seconds: 86400 }), asset = { external_id: 'managed-web01', hostname: 'web01', os_family: 'linux', device_type: 'server', addresses: [] };
  let n = 0; const send = details => d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: `lp-${n++}`, kind: 'linux.security_posture', observed_at: new Date(now).toISOString(), asset, details }] });
  send(posture({}));
  let v = d.linuxSecurity().items[0]; assert.equal(v.baseline, true); assert.deepEqual(v.coverage, { auditd: 'running', audit_rules: 12, journald: 'readable', ebpf: 'supported', ebpf_reason: 'kernel 6.8.0-49-generic with BTF', falco: 'running' });
  assert.equal(s.get("SELECT COUNT(*) n FROM alerts WHERE rule_id LIKE 'CG-LINUX-%'").n, 0, 'a clean first snapshot is the baseline');
  // Second snapshot: a new cron job, a modified service unit, a changed sudoers file with NOPASSWD.
  now += 3600000; send(posture({ cron: [{ path: '/etc/crontab', sha256: h('b') }, { path: '/etc/cron.d/update-check', sha256: h('d') }], systemd_units: [{ path: '/etc/systemd/system/app.service', sha256: h('e') }], sudo: { ...posture({}).sudo, sudoers: [{ path: '/etc/sudoers', sha256: h('a') }, { path: '/etc/sudoers.d/90-tmp', sha256: h('f') }], no_prompt_rules: 1 } }));
  v = d.linuxSecurity().items[0]; assert.equal(v.baseline, false);
  assert.deepEqual(v.changes.persistence, [{ path: '/etc/cron.d/update-check', change: 'added' }, { path: '/etc/systemd/system/app.service', change: 'modified' }]); assert.deepEqual(v.changes.sudoers, [{ path: '/etc/sudoers.d/90-tmp', change: 'added' }]);
  const alerts = s.all("SELECT rule_id,severity,title FROM alerts WHERE rule_id LIKE 'CG-LINUX-%' ORDER BY rule_id,severity");
  assert.deepEqual(alerts.map(a => [a.rule_id, a.severity]), [['CG-LINUX-PERSIST-094', 'high'], ['CG-LINUX-SUDO-094', 'high'], ['CG-LINUX-SUDO-094', 'medium']]); assert.match(alerts[0].title, /added \/etc\/cron\.d\/update-check/);
  // A host where the kernel or permissions do not allow full telemetry: reasons are shown, never assumed.
  const old = { ...asset, external_id: 'managed-legacy', hostname: 'legacy01' };
  d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'lp-old', kind: 'linux.security_posture', observed_at: new Date(now).toISOString(), asset: old, details: posture({ collected_as_root: false, kernel: '4.15.0-213-generic', auditd: { state: 'stopped', rules: null }, journald: 'access-denied', ebpf: { state: 'not-supported', btf: false, unprivileged_bpf_disabled: 'unknown', reason: 'kernel 4.15.0-213-generic is older than 5.8; modern eBPF probes are not available' }, falco: { state: 'not-installed', unit: null }, sudo: { ...posture({}).sudo, sudoers: [{ path: '/etc/sudoers', sha256: null }], no_prompt_rules: null, full_all_grants: null, use_source: 'not-readable', use_24h: [] } }) }] });
  const legacy = d.linuxSecurity().items.find(x => x.hostname === 'legacy01'); assert.equal(legacy.coverage.ebpf, 'not-supported'); assert.match(legacy.coverage.ebpf_reason, /older than 5\.8/); assert.equal(legacy.files.unreadable, 1);
  assert.equal(s.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-LINUX-VISIBILITY-094'").n, 1);
  assert.throws(() => send(posture({ sudo: { ...posture({}).sudo, sudoers: [{ path: '/etc/sudoers', sha256: 'not-a-hash' }] } })), /invalid_linux_sudoers_sha256_0/);
  assert.ok(d.linuxSecurity().claim_ar.includes('لا يُجمع محتوى الملفات'));
});

test('Falco JSON runtime alerts are normalized with priority as severity (CG-094)', () => {
  const lines = ['{"hostname":"web01","output":"Shell spawned in container","priority":"Critical","rule":"Terminal shell in container","source":"syscall","time":"2026-11-20T08:00:00.123456789Z","output_fields":{"proc.name":"bash","user.name":"root","container.id":"3ad7b26ded6d"}}', '{"priority":"Notice","rule":"Read sensitive file untrusted","time":"2026-11-20T08:01:00Z","output_fields":{"proc.name":"cat","container.id":"host"}}', 'not json'];
  const r = normalizeLogLines('falco-json', lines);
  assert.deepEqual(r.records.map(x => [x.category, x.signature, x.severity, x.outcome]), [['ids', 'Falco: Terminal shell in container', 1, 'proc bash, user root, container 3ad7b26ded6d'], ['ids', 'Falco: Read sensitive file untrusted', 4, 'proc cat']]); assert.equal(r.rejected.length, 1);
});

test('the Linux collector script runs read-only on Linux and produces valid evidence (CG-094)', { skip: process.platform !== 'linux' && 'runs on Linux hosts' }, t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg094-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true })); const out = path.join(dir, 'p.json');
  execFileSync('bash', [SCRIPT, out, 'ci-test'], { encoding: 'utf8' }); const batch = JSON.parse(fs.readFileSync(out, 'utf8'));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, { clock: () => Date.now() });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  assert.equal(d.ingest('admin-a', d.createSource('admin-a', { name: 'Linux', stale_seconds: 3600 }).id, batch).accepted, 1); assert.equal(d.linuxSecurity().items.length, 1);
});
