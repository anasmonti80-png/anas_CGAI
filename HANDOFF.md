# HANDOFF — shared state between Claude Code and Codex

Either agent may stop at any time (usage limit). The next agent resumes from this file.
Rules, scope and safety live in `AGENTS.md`; do not duplicate them here.

## Protocol
1. On start: read this file, then `git log -10 --oneline` and `git status`.
2. Work in small phases; commit after each logical step with a clear message.
3. Keep this file current: update "Current state" and "Next steps" at every commit.
4. Record decisions in ADRs (when created), not only in chat.
5. Never claim "implemented" without passing tests (see AGENTS.md).
6. Do not put secrets, customer data or private inventories in this file.

## Current state
- Last agent: Codex
- Branch: codex/cg001-600
- Last updated: 2026-11-12
- Completed: Documentation and runnable platform merged; CG-001..CG-600 triaged; CG-001..CG-005, CG-007, CG-008, CG-016, CG-022, CG-032, CG-054, CG-056, CG-057, CG-061, CG-068..CG-071, CG-073 and CG-075..CG-078 are acceptance-verified. The UI has the requested SOC design, bilingual responsive navigation, evidence readiness, discovery, typed interfaces/services, remote access, operating modes, actions, source health, NIST mapping, versioned environment threat models, an institutional risk register, asset lifecycle/support plans, a legacy compatibility matrix, compensating-control and backup-security registries, a visibility-gap registry, evidence-linked asset context and the Achievements ledger. 64/64 tests pass.
- In progress: Sequential authenticated discovery for CG-006; external connectors remain gated by authorized labs.
- Blockers: Vendor EDR/cloud/macOS/Linux/network integrations require authorized accounts, licenses, and real lab environments before they can be labelled working. GitHub push also requires a working credential on this host; the non-interactive push after `2f8d54b` was rejected.

## Task for Codex (from Claude Code)
Read AGENTS.md mandatory reading order first, then start the first engineering deliverable:
1. `docs/adr/ADR-0001-architecture.md` (+ ADR template).
2. `docs/requirements_coverage.md` (CG-001..CG-1440 coverage, no invented results).
3. `docs/support_matrix.md` (Windows/macOS/Linux, status = untested unless tested).
4. `docs/milestones.md`, `docs/test_strategy.md`, `docs/blockers.md`.
Docs only, no high-risk functionality. Commit per file, update this file, push to the same branch.
Reply in this file under "Log" when done or when your usage limit is near.

## Next steps (ordered)
1. Continue actual implementation from CG-005. Use `docs/engineering/ACCEPTANCE_001_600.json` only for requirements with current full acceptance evidence.
2. Run `node scripts/verify.js`, then `node scripts/requirements.js`, then verify again before committing a promoted requirement.
3. Keep `artifacts/browser-qa.json` and the browser report current when UI acceptance changes.

## Log (newest first)
| Date | Agent | Summary | Commit |
|------|-------|---------|--------|
| 2026-11-12 | Codex | Added evidence-gated backup security with multiple separated copies, platform immutability support, modification/deletion monitoring and permission review; 64/64 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-12 | Codex | Added evidence-gated legacy compensating controls for segmentation, jump hosts, Internet restriction, MFA, backup/restore, monitoring and owned migration; 62/62 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-12 | Codex | Added the per-asset legacy compatibility matrix with explicit support, agent, read-only/access, isolation, tested-capability, performance, licensing and evidence-basis fields; 60/60 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-12 | Codex | Added versioned product/OS lifecycle, support and security-update end dates, extended-support enrollment and owned upgrade/replacement plans to central assets; 58/58 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-12 | Codex | Added a versioned institutional risk register with coverage, resolved evidence, ownership, remediation deadlines, exceptions and time-bounded acceptance reviews; 56/56 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-12 | Codex | Added a versioned threat model per registered environment with valuable assets, trust boundaries, attack scenarios, outage/disclosure impacts and central-asset links; 54/54 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-12 | Codex | Linked the central asset to versioned owner, business-service, site, sensitivity, maintenance-window and service-criticality evidence; 52/52 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-12 | Codex | Added a known-scope visibility-gap registry for systems, networks, accounts and source outages with reasons, last sighting, recommendations and resolution; 50/50 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-12 | Codex | Added a live NIST CSF 2.0 map for all six functions with actual evidence counts, bounded references and explicit gaps; 48/48 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-12 | Codex | Separated remote-application presence from connection phases and required evidence for authorized/suspicious assessments; 46/46 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-12 | Codex | Added typed managed-agent/log-forwarder health, coverage statistics and distinct loss/delivery-failure alerts; 44/44 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-12 | Codex | Completed the current-catalog action lifecycle with dry run, impact, independent approval, execute, verify, audit and guarded rollback evidence; 42/42 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-12 | Codex | Added PC Local, Enterprise Collectors and authorized validation-lab modes with truthful PC blind spots and SPAN/TAP, flow-log and agent evidence paths; 41/41 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-12 | Codex | Added authorized passive discovery, change/outage evidence, and strict physical-interface versus TCP/UDP service types; 38/38 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-12 | Codex | Added evidence-readiness scoring, enforced/tested local-only exposure, and established the dependency/license/privacy release gate; 35/35 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-12 | Codex | Added acceptance-gated Achievements ledger and browser-verified CG-001..CG-004; 34/34 Unit Tested. | f479438 |
| 2026-11-12 | Codex | Merged the runnable SOC/evidence implementation; 29/29 Unit Tested. | 6dbf824 |
| 2026-11-12 | Codex | Extended semantic scope/delivery triage through CG-600; 30/30 Unit Tested. | e8356d4 |
| 2026-11-12 | Codex | Added downloadable deterministic case evidence packs and traceability for CG-321..324 subsets. | cff7419 |
| 2026-11-12 | Codex | Added ADR template and evidence-first local architecture decision. | 8e39fda |
| 2026-11-12 | Codex | Added coverage report, support matrix, milestones, test strategy, and blocker register. | 08f22ca, 0938b27, 17acd34, 798e821, 554f683 |
| 2026-11-12 | Codex | Documentation verification passed (1,440 IDs); GitHub push blocked by missing Git credential. | 54d3855 |
