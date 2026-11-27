// CG-176 Network policy simulation coverage. Every firewall what-if (CG-020) now states what it covers and whether its
// result is qualified for use on the device it describes:
//  - scope: one device's L3/L4 filter rules in first-match or deny-overrides order, IPv4 CIDR containment, exact IPv6
//    prefixes, TCP/UDP/ICMP/any, port ranges, application names as exact labels;
//  - not modelled: NAT, routing and the path through other devices, return traffic and session state, schedules, user
//    and identity rules, URL/content and L7 inspection, vendor implicit rules missing from the export, rules whose
//    named objects could not be resolved;
//  - reachability output: before/after decisions for one sampled flow per rule edge, not an exhaustive search; a path
//    reachability engine such as Batfish analyses whole networks (multi-vendor configurations, traceroute and
//    reachability across devices) and is the reference for anything beyond one device.
// A simulation is qualified only when nothing in the ruleset or change falls outside that scope. Network response
// actions on a sensitive production device (asset criticality or business service marked critical) need a qualified
// simulation of that device from the last 24 hours; an unqualified result is never applied there.
import { randomUUID } from 'node:crypto';
import { fail, text } from './common.js';

export const SUPPORTED_VENDORS = ['windows-firewall', 'iptables', 'nftables', 'pfsense', 'palo-alto', 'fortigate', 'cisco-asa', 'cisco-fmc', 'juniper-srx', 'mikrotik', 'opnsense', 'aws-security-group', 'azure-nsg', 'azure-firewall', 'gcp-vpc-firewall'];
export const PROTOCOLS = ['tcp', 'udp', 'icmp', 'any'];
export const NOT_MODELLED = ['nat', 'routing-and-path', 'return-traffic-and-state', 'schedules', 'user-identity-rules', 'url-and-l7-inspection', 'vendor-implicit-rules', 'unresolved-named-objects'];
export const COVERAGE = { scope: 'single-device-l3-l4-filters', evaluation: ['first-match', 'deny-overrides'], protocols: PROTOCOLS, vendors: SUPPORTED_VENDORS, not_modelled: NOT_MODELLED,
  reachability: 'before/after decision for one sampled flow per rule edge on this device; not exhaustive and not end-to-end',
  reference: { id: 'Batfish supported devices and forwarding analysis', url: 'https://batfish.readthedocs.io/en/latest/supported_devices.html' } };
const SENSITIVE_ACTIONS = ['network.block-ip', 'network.allow-ip', 'network.block-port', 'network.allow-port'];

export function qualify(ruleset, change) {
  const reasons = [], rules = [...ruleset.rules, ...(change?.rule ? [change.rule] : [])];
  if (!SUPPORTED_VENDORS.includes(ruleset.vendor)) reasons.push(`vendor-not-modelled:${ruleset.vendor}`);
  const unreadable = ruleset.rules.filter(r => r.filters_readable === false).length; if (unreadable) reasons.push(`unresolved-named-objects:${unreadable}`);
  const protos = [...new Set(rules.map(r => r.protocol).filter(p => p && !PROTOCOLS.includes(p)))]; if (protos.length) reasons.push(`protocol-not-modelled:${protos.join(',')}`);
  if (rules.some(r => r.application)) reasons.push('application-rules-as-labels-only');
  if (rules.some(r => (r.scope_constraints || []).length)) reasons.push('scope-constraints-not-modelled');
  if (rules.some(r => [...(r.src || []), ...(r.dst || [])].some(a => String(a).includes(':')))) reasons.push('ipv6-prefixes-compared-exactly');
  return { qualified: reasons.length === 0, reasons };
}

export class SimulationCoverage {
  constructor(store, { clock } = {}) { Object.assign(this, { s: store, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  record(actor, deviceRef, ruleset, change, result) {
    const q = qualify(ruleset, change), id = randomUUID();
    this.s.run('INSERT INTO simulations(id,device_ref,ruleset_id,change_json,qualified,reasons,opened,closed,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)', id, deviceRef, ruleset.ruleset_id, JSON.stringify(change), q.qualified ? 1 : 0, JSON.stringify(q.reasons), result.opened ?? 0, result.closed ?? 0, actor || 'system', this.now());
    return { simulation_id: id, ...q, coverage: COVERAGE };
  }
  // The simulation describes a filtering device's ruleset, so the gate applies to firewalls and routers, or to any device
  // CyberGuard holds a ruleset for, when that device is critical or serves a critical business service.
  filtering(asset) { return ['firewall', 'router'].includes(asset.device_type) || !!this.s.get("SELECT 1 x FROM events WHERE kind='firewall.ruleset' AND json_extract(payload,'$.details.device_ref')=? LIMIT 1", asset.external_id); }
  sensitive(asset, context) { return this.filtering(asset) && (asset.criticality === 'critical' || context?.service_criticality === 'critical'); }
  // Called by the governed preview for network filter actions.
  require(asset, type, simulationId, context) {
    if (!SENSITIVE_ACTIONS.includes(type) || !this.sensitive(asset, context)) return null;
    fail(simulationId, 409, 'qualified_simulation_required_for_sensitive_production');
    const sim = this.s.get('SELECT * FROM simulations WHERE id=?', text(simulationId, 'simulation_id', 64)); fail(sim && sim.device_ref === asset.external_id, 409, 'simulation_not_for_this_device');
    fail(Date.parse(sim.created_at) >= this.clock() - 86400000, 409, 'simulation_older_than_24_hours');
    fail(sim.qualified === 1, 409, `simulation_not_qualified:${JSON.parse(sim.reasons).join(',')}`);
    return sim;
  }
  view() {
    return { coverage: COVERAGE, simulations: this.s.all('SELECT * FROM simulations ORDER BY created_at DESC LIMIT 100').map(r => ({ ...r, qualified: !!r.qualified, reasons: JSON.parse(r.reasons), change: JSON.parse(r.change_json) })),
      claim: 'Each firewall simulation states its scope (one device, L3/L4 filters, the vendors and protocols modelled), what it does not model (NAT, routing and path, state, schedules, identity, L7) and what its reachability output means. Only a qualified simulation from the last 24 hours lets a network filter action run on a sensitive production device.',
      claim_ar: 'تعلن كل محاكاة جدار ناري نطاقها (جهاز واحد، ومرشحات الطبقتين الثالثة والرابعة، والموردون والبروتوكولات المنمذجة)، وما لا تنمذجه (الترجمة NAT، والتوجيه والمسار، والحالة، والجداول الزمنية، والهوية، والطبقة السابعة)، ومعنى مخرجات الوصول فيها. ولا يُنفذ إجراء مرشح شبكي على جهاز إنتاج حساس إلا بمحاكاة مؤهلة من آخر 24 ساعة.' };
  }
}
