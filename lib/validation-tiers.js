// CG-026 testing tiers. CyberGuard governs and records validation work; it does not run attacks itself.
// Each tier names the techniques it may contain and the safeguards an approved plan must carry.
export const tiers = {
  passive: {
    techniques: ['telemetry-review', 'log-analysis', 'inventory-correlation', 'config-export-review'],
    environments: ['production', 'staging', 'lab'],
    max_window_days: 90,
    requires: [],
    description: 'Analysis of evidence already collected. No packets or commands reach the targets.',
  },
  'low-impact-validation': {
    techniques: ['version-banner-check', 'credentialed-config-check', 'credentialed-patch-check', 'tls-configuration-check', 'safe-port-reachability', 'registry-policy-check'],
    environments: ['production', 'staging', 'lab'],
    max_window_days: 14,
    requires: ['authorization_ref', 'approved_by', 'rate_limit_per_minute', 'stop_conditions'],
    max_rate_per_minute: 60,
    description: 'Read-only or single-request checks under written authorization, a time window, a rate limit and stop conditions. No exploitation, no writes, no credential attacks.',
  },
  'adversary-emulation': {
    techniques: 'mitre-attack',
    environments: ['lab'],
    max_window_days: 30,
    requires: ['authorization_ref', 'approved_by', 'second_approver', 'isolation_evidence_ref', 'rollback'],
    description: 'MITRE ATT&CK technique emulation only in an isolated, authorized lab, approved by two different people, with isolation evidence and a cleanup plan.',
  },
};
export const attackTechnique = /^T\d{4}(\.\d{3})?$/;
export function techniqueAllowed(tier, id) {
  const allowed = tiers[tier]?.techniques;
  return allowed === 'mitre-attack' ? attackTechnique.test(id) : Array.isArray(allowed) && allowed.includes(id);
}
