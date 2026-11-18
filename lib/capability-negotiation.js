// CG-044 capability negotiation: what each device actually supports, from a probe of the device itself,
// checked against the probed version and licence. Nothing is assumed from the vendor name alone.
import { compareVersions } from './device-config.js';

export const capabilityNames = Object.freeze(['read', 'logs', 'config', 'policy', 'isolation', 'port-shutdown', 'undo']);
// Minimum versions documented by the vendors for the read APIs our connectors use.
export const knownMinimums = Object.freeze({
  'cisco-iosxe:config': { min_version: '16.6', basis: 'IOS XE RESTCONF is available from 16.6' },
  'palo-alto:policy': { min_version: '9.0', basis: 'PAN-OS REST API is available from 9.0' },
  'mikrotik:policy': { min_version: '7.1', basis: 'RouterOS REST API is available from 7.1' },
});
// Which capability a governed response action needs on the target device.
export const actionCapability = Object.freeze({
  'network.block-ip': 'policy', 'network.block-port': 'policy', 'endpoint.block-app': 'policy', 'dns.block-domain': 'policy',
  'network.allow-ip': 'undo', 'network.allow-port': 'undo', 'endpoint.allow-app': 'undo', 'dns.allow-domain': 'undo',
  'endpoint.isolate-device': 'isolation', 'endpoint.reconnect-device': 'undo', 'network.nac-quarantine-endpoint': 'isolation', 'network.nac-release-endpoint': 'undo',
  'network.switch-port-admin-down': 'port-shutdown', 'network.switch-port-admin-up': 'undo',
  'endpoint.stop-service': 'config', 'endpoint.disable-service': 'config', 'endpoint.quarantine-file': 'isolation', 'endpoint.shutdown-host': 'config',
});

// Effective availability of each capability for one probe.
export function negotiate(probe, now = Date.now()) {
  const ageDays = (now - Date.parse(probe.probed_at)) / 86400000, license = probe.license || {};
  return capabilityNames.map(name => {
    const c = probe.capabilities.find(x => x.capability === name), reasons = [];
    if (!c) return { capability: name, available: false, state: 'not-probed', reasons: ['not-probed'], method: null, evidence: null };
    const min = c.min_version || knownMinimums[`${probe.vendor}:${name}`]?.min_version || null;
    if (c.status !== 'supported') reasons.push(c.status === 'unsupported' ? 'probe-unsupported' : 'probe-inconclusive');
    if (min && (!probe.version || compareVersions(probe.version, min) < 0)) reasons.push(probe.version ? 'version-too-old' : 'version-unknown');
    if (c.license_feature) {
      const feature = (license.features || []).find(f => f.name === c.license_feature);
      if (!feature) reasons.push('license-missing');
      else if (feature.expires_at && Date.parse(feature.expires_at) < now) reasons.push('license-expired');
    }
    if (ageDays > 30) reasons.push('probe-stale');
    return { capability: name, available: reasons.length === 0, state: reasons.length ? 'unavailable' : 'available', reasons, method: c.method || null, evidence: c.evidence || null, min_version: min, license_feature: c.license_feature || null };
  });
}
