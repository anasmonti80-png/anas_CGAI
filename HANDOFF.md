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
- Completed: Documentation and runnable platform merged; CG-001..CG-600 triaged; CG-001..CG-005, CG-007, CG-008, CG-022, CG-032, CG-054, CG-056, CG-057 and CG-061 are acceptance-verified. The live UI has the requested SOC design, bilingual responsive navigation, explicit unknown states, evidence readiness, authorized discovery observations, typed switch interfaces/services, operating modes, an evidence-visible action lifecycle, typed source-health monitoring and the shared Achievements ledger. 44/44 tests pass.
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
