import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { blastRadius } from '../lib/blast-radius.js';

test('stop service, switch port, disable user and security group changes get a specific blast radius from visible relationships, and unknown when none is visible (CG-171)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {}), now = new Date().toISOString();
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin', 'admin', 'fixture-not-a-password-hash', 'admin', now);
  const src = d.createSource('admin', { name: 'Lab', stale_seconds: 86400 }), put = (...events) => d.ingest('admin', src.id, { schema_version: 'cg.telemetry/1', events });
  const app = { external_id: 'app-01', hostname: 'APP-01', os_family: 'linux', device_type: 'server', addresses: ['192.0.2.10'] }, lonely = { external_id: 'lonely-01', hostname: 'LONELY-01', os_family: 'linux', device_type: 'server', addresses: ['192.0.2.99'] };
  put({ event_id: 'a1', kind: 'asset.observed', observed_at: now, asset: app, details: {} }, { event_id: 'a2', kind: 'asset.observed', observed_at: now, asset: lonely, details: {} });
  // Flow logs: three clients talk to app-01.
  const lines = ['192.0.2.21', '192.0.2.22', '192.0.2.23'].map(src => `2 123456789012 eni-1 ${src} 192.0.2.10 51000 443 6 10 840 1700000000 1700000060 ACCEPT OK`);
  put({ event_id: 'f1', kind: 'log.batch', observed_at: now, asset: app, details: { batch_id: 'flows', source_name: 'vpc', format: 'aws-vpc-flow', lines } });
  let r = blastRadius(s, d, { change_type: 'stop-service', asset_ref: 'app-01', target: { service_ref: 'nginx' } });
  assert.deepEqual([r.impact, r.affected.clients.length, r.based_on, r.requires_human_review], ['limited', 3, ['flow-logs-7d'], false]);
  r = blastRadius(s, d, { change_type: 'stop-service', asset_ref: 'lonely-01', target: { service_ref: 'cron' } });
  assert.deepEqual([r.impact, r.requires_human_review, r.based_on], ['unknown', true, []], 'no visible relationship is unknown, never "no impact"');
  assert.match(r.warnings[0].en, /needs human review/);
  // Disable user: sign-ins, a remote session and a SaaS service identity.
  put({ event_id: 's1', kind: 'identity.signin_activity', observed_at: now, asset: app, details: { batch_id: 'b', directory_ref: 'lab', window: { starts_at: now, ends_at: now }, signins: [{ signin_id: 'x1', principal_ref: 'svc-report@lab.example', at: now, result: 'success', failure_reason: null, source_ip: '192.0.2.40', country: 'SA', client_app: 'Reporting', mfa: 'not-required' }] } },
    { event_id: 'r1', kind: 'remote.authenticated', observed_at: now, asset: app, details: { session_id: 'rs1', protocol: 'ssh', source_a: { hostname: null, ip: '192.0.2.40', account: null }, target_b: { hostname: 'APP-01', ip: '192.0.2.10', account: 'svc-report' }, relay: false, evidence_type: 'authentication_log' } });
  r = blastRadius(s, d, { change_type: 'disable-user', target: { account: 'svc-report' } });
  assert.deepEqual([r.impact, r.sign_ins, r.affected.hosts, r.affected.applications], ['limited', 1, ['APP-01'], ['Reporting']]);
  assert.equal(blastRadius(s, d, { change_type: 'disable-user', target: { account: 'nobody-here' } }).impact, 'unknown');
  // Security group: resources that reference it in the cloud inventory.
  put({ event_id: 'c1', kind: 'cloud.resource_inventory', observed_at: now, asset: app, details: { inventory_id: 'inv', provider: 'aws', source: 'aws-resource-explorer', resources: [
    { resource_id: 'i-0001', name: 'web-1', account_id: '123456789012', region: 'me-central-1', type: 'ec2:instance', category: 'compute', tags: {}, public: true, security_groups: ['sg-web'] },
    { resource_id: 'i-0002', name: 'web-2', account_id: '123456789012', region: 'me-central-1', type: 'ec2:instance', category: 'compute', tags: {}, public: false, security_groups: ['sg-web', 'sg-mgmt'] }] } });
  r = blastRadius(s, d, { change_type: 'security-group-change', target: { group_id: 'sg-web' } });
  assert.deepEqual([r.impact, r.affected.resources, r.affected.public_resources], ['limited', ['i-0001', 'i-0002'], ['i-0001']]); assert.ok(r.warnings.some(w => /public/.test(w.en)));
  assert.equal(blastRadius(s, d, { change_type: 'security-group-change', target: { group_id: 'sg-unknown' } }).impact, 'unknown');
  // Switch port without a port map: unknown.
  assert.equal(blastRadius(s, d, { change_type: 'switch-port-shutdown', asset_ref: 'app-01', target: { interface_ref: 'Gi1/0/5', device_ref: 'app-01' } }).impact, 'unknown');
  assert.throws(() => blastRadius(s, d, { change_type: 'reboot', target: {} }), /blast_change_type/);
});
