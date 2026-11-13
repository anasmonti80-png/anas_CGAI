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
7. `HANDOFF.md` is the single canonical coordination notebook for Codex and Claude. Record the active owner, exact CG range, validation result, commit and push state here; do not create agent-specific handoff files.
8. After every verified checkpoint, commit with an agent prefix (`[Codex]` or `[Claude]`) and push `codex/cg001-600`. The next agent pulls this branch and resumes the first unfinished item without duplicating completed work.

## Current state
- Last agent: Codex
- Branch: codex/cg001-600
- Last updated: 2026-11-13
- Completed: Documentation and runnable platform merged; CG-001..CG-600 triaged; CG-001..CG-005, CG-007, CG-008, CG-016, CG-022, CG-032, CG-054, CG-056, CG-057, CG-061, CG-068..CG-071, CG-073 and CG-075..CG-086 are acceptance-verified. The UI includes the requested SOC design and evidence registries through SaaS/OAuth/service-identity inventory, PAM, directory audit, Windows LAPS and AD CS/Kerberos/NTLM posture. 80/80 tests pass.
- In progress: no unpublished requirement checkpoint after CG-086. CG-087 is the next sequential requirement; sequential authenticated discovery for CG-006 also remains open. External connectors remain gated by authorized labs.
- GitHub handoff: active. `codex/cg001-600` is published and tracks `origin/codex/cg001-600`. The newest `[Codex]` checkpoint in the Log is the source of truth available to Claude.
- Blockers: Vendor EDR/cloud/macOS/Linux/network integrations require authorized accounts, licenses, and real lab environments before they can be labelled working.

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
| 2026-11-13 | Codex | Added a read-only SaaS/OAuth/service-identity inventory with explicit application and identity owners, credential rotation metadata, permissions, observed activities and rejection of credential values; 80/80 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-13 | Codex | Added PAM evidence for bounded JIT/PIM, MFA, compliant dedicated PAW, temporary recorded administrative sessions and independent high-sensitivity authorization without executing privilege grants; 78/78 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-13 | Codex | Added source-reported AD CS/Kerberos/NTLM posture for certificate services, templates and issuance, delegation, legacy authentication and access-decided authentication changes while rejecting private-key material; 76/76 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-13 | Codex | Added per-device Windows LAPS posture for policy and rotation interval, local-administrator management, rotation failures and audited access metadata while rejecting password fields and collecting no LAPS secrets; 74/74 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-13 | Codex | Added a read-only AD/Entra/hybrid directory audit for Tier 0/control-plane principals, Domain Admin changes, service-account sign-in/rotation, trusts and sign-in policies without secrets; 72/72 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-13 | Codex | Activated the shared GitHub branch and made this file the single canonical Codex/Claude coordination notebook. | current checkpoint |
| 2026-11-13 | Codex | Added evidence-gated network/SOC resilience controls for separated configuration backups, tested out-of-band and alternate management, an exercised SOC outage playbook and an expiring automatic temporary-policy fail-safe; 70/70 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-13 | Codex | Added ordered incident recovery with containment, identity/configuration/device restore, zero-finding threat clearance and approved reconnection gates; 68/68 Unit Tested and Chromium checked. | current checkpoint |
| 2026-11-13 | Codex | Added per-service restore readiness with periodic documented tests, measured RPO/RTO, integrity evidence and explicit separation from backup presence; 66/66 Unit Tested and Chromium checked. | current checkpoint |
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
