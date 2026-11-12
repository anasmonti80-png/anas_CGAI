# Codex instructions — CyberGuard AI (CG AI) V3.0

This repository contains **product research and implementation requirements**, not a finished cybersecurity application.

## Mandatory reading order
1. `00_START_HERE/README_AR.md`
2. `00_START_HERE/Manifest_V3.0.json`
3. `00_START_HERE/CyberGuard_AI_V3.0_EXECUTION_PROMPT_ONLY.md`
4. `00_START_HERE/CyberGuard_AI_V3.0_MASTER_PROMPT_COMPLETE.md`
5. `01_SOURCE/Research_and_Requirements_v2.9.md`
6. `01_SOURCE/Gap_Closure_Audit_v2.9.md`
7. `02_REQUIREMENTS/CG_Requirements_1440.jsonl`
8. All 12 files in `02_REQUIREMENTS/CHUNKS/`; consult `03_HISTORY/` to preserve legacy intent.

## Requirements and traceability
- The verified registered range is **CG-001..CG-1440**, not 1,470 or 1,500.
- Preserve every ID and verbatim requirement, including repetitions, while classifying overlaps and superseded scope decisions.
- Keep a machine-readable traceability matrix: ID, status, owner, implementation location, test ID, evidence, restrictions.
- "Implemented" requires passing tests on the actual supported platform; do not invent demos, sensors, deployments, or test results.
- Preserve historical source records; newer explicit scope decisions and the final CyberGuard AI naming take precedence.
- Implement in dependency-ordered phases, not one speculative giant code change.

## Product scope
CyberGuard: defensive cybersecurity, authorized validation/AI Red Team, adaptive device protection, AI-assisted detection/response, DevSecOps, cyber resilience, and auditable remote-access session security telemetry.
NCC: operational network management / switch-port or device configuration. Connect only through scoped, approved API requests.
IT Twin: digital twin. Tickets: IT service management. Do not duplicate either subsystem.

## Safety and privacy
- Default to offline/local processing when feasible. No secrets in logs, prompts, source control, or third-party API payloads.
- Do not perform live intrusion, password guessing, production scanning, containment, firewall changes, SSH execution, device isolation, or credential operations without explicit authorized scope and documented approval.
- AI may reason and propose; a separate policy/approval gateway must authorize actions.
- Prioritize read-only discovery and simulation; support dry runs, impact analysis, rollback and evidence of remediation.
- Do not claim cross-platform support without Windows/macOS/Linux support matrix and actual tests.
- The repository may be public. Never add customer data, personal information, private network inventories or production credentials.

## First engineering deliverable
Create an architecture decision record (ADRs), requirements coverage report, a support matrix, implementation milestones, test strategy and identified blockers before attempting high-risk functionality.

## Cross-agent GitHub handoff
- GitHub is the shared handoff point for Codex, Claude, and any other authorized coding agent. Conversation memory is not shared.
- Before editing, inspect `AI_CLOUD_HANDOFF.md` and `PROGRESS.md`, fetch the working branch, and preserve newer work. Do not force-push, reset, or overwrite another agent's changes.
- Work on a named branch. After each coherent, verified checkpoint, update `PROGRESS.md`, commit with an agent prefix such as `[Codex]` or `[Claude]`, and push the branch when authorized.
- Before an agent's context or usage limit ends, it must make a best-effort checkpoint: save safe work, update `PROGRESS.md` with the exact next step and verification state, and commit it. Unverified work must be labelled as unverified.
- A handoff is complete only when the receiver can identify the branch, latest commit, changed files, validation level, remaining work, and any blocked external dependency from repository files alone.
- GitHub is a relay, not a live conversation channel. Never store tokens, setup codes, cookies, customer data, or private telemetry in commits or handoff files.
