// CG-095 macOS, iOS/Android and BYOD coverage through MDM/MAM/EDR. Converts a Microsoft Graph managedDevices export
// (Intune; Jamf and other MDMs map to the same fields) into coverage evidence. What each platform lets CyberGuard see
// is stated per platform and management type, and personal (BYOD) devices are minimised for privacy: no user name,
// serial number, phone number, IMEI or location is kept, only a pseudonymous reference and the security posture.
import { createHash } from 'node:crypto';

export const platformCapabilities = {
  macos: { mdm: ['inventory', 'os-version', 'encryption (FileVault)', 'compliance', 'configuration profiles'], edr: ['process telemetry', 'file events', 'network connections'], not_visible: ['process telemetry without an EDR system extension'] },
  ios: { mdm: ['inventory', 'os-version', 'passcode and encryption state', 'jailbreak signal', 'compliance'], mam: ['managed app data protection only'], edr: ['phishing and network threat signals (Mobile Threat Defense)'], not_visible: ['other apps', 'processes', 'files', 'personal data'] },
  android: { mdm: ['inventory', 'os-version', 'encryption', 'root signal (Play Integrity)', 'compliance'], mam: ['managed app data protection only'], edr: ['malicious app and network threat signals (Mobile Threat Defense)'], not_visible: ['personal profile apps and data on BYOD work-profile devices', 'processes'] },
  windows: { mdm: ['inventory', 'os-version', 'BitLocker', 'compliance'], edr: ['full endpoint telemetry with an EDR'], not_visible: [] },
};
const platformOf = os => { const v = String(os || '').toLowerCase(); return v.includes('mac') ? 'macos' : v.includes('ios') || v.includes('ipad') ? 'ios' : v.includes('android') ? 'android' : v.includes('windows') ? 'windows' : 'other'; };
const pseudo = (salt, v) => createHash('sha256').update(`${salt}|${v}`).digest('hex').slice(0, 16);

export function managedDevices(graph, { salt, now = Date.now() } = {}) {
  if (!salt || salt.length < 16) throw new Error('a private salt of at least 16 characters is required to pseudonymise devices');
  const list = Array.isArray(graph) ? graph : graph?.value; if (!Array.isArray(list)) throw new Error('expected a Graph managedDevices export with a value array');
  return list.map(d => {
    const platform = platformOf(d.operatingSystem), personal = String(d.managedDeviceOwnerType || d.ownerType || '').toLowerCase() === 'personal';
    const agent = String(d.managementAgent || '').toLowerCase(), management = agent.includes('mdm') || agent.includes('eas') || agent === 'intune' || agent.includes('jamf') ? 'mdm' : agent.includes('mam') ? 'mam' : agent ? 'other' : 'unknown';
    const last = d.lastSyncDateTime ? new Date(d.lastSyncDateTime).toISOString() : null;
    return { device_ref: pseudo(salt, d.id || d.serialNumber || d.deviceName), platform, os_version: String(d.osVersion || '').slice(0, 40) || null, ownership: personal ? 'personal' : String(d.managedDeviceOwnerType || '').toLowerCase() === 'company' ? 'corporate' : 'unknown', management,
      compliance: ['compliant', 'noncompliant', 'conflict', 'error', 'ingraceperiod', 'configmanager', 'unknown'].includes(String(d.complianceState || '').toLowerCase()) ? String(d.complianceState).toLowerCase() : 'unknown',
      encrypted: typeof d.isEncrypted === 'boolean' ? d.isEncrypted : null, jailbroken: d.jailBroken === 'True' || d.jailBroken === true ? true : d.jailBroken === 'False' || d.jailBroken === false ? false : null,
      supervised: typeof d.isSupervised === 'boolean' ? d.isSupervised : null, mtd_enabled: d.partnerReportedThreatState ? String(d.partnerReportedThreatState).toLowerCase() : null, last_sync: last, stale: last ? now - Date.parse(last) > 7 * 86400000 : true,
      // Corporate devices keep the device name for operations; personal devices keep nothing that identifies the owner.
      display_name: personal ? null : String(d.deviceName || '').slice(0, 100) || null };
  });
}
export function toTelemetry(devices, { source = 'intune-graph', now = Date.now() } = {}) {
  const at = new Date(now).toISOString();
  return { schema_version: 'cg.telemetry/1', events: devices.map(d => ({ event_id: `mdm:${d.device_ref}:${at}`, kind: 'mdm.device_posture', observed_at: at, asset: { external_id: `mdm:${d.device_ref}`, hostname: d.display_name || `byod-${d.device_ref.slice(0, 8)}`, os_family: d.platform === 'macos' ? 'macos' : d.platform === 'windows' ? 'windows' : 'unknown', device_type: d.platform === 'ios' || d.platform === 'android' ? 'phone' : 'workstation', addresses: [] }, details: { ...d, source } })) };
}
