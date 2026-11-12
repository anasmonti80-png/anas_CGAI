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
- Completed: Documentation and runnable platform merged; CG-001..CG-600 triaged; CG-001..CG-004 are acceptance-verified. The live UI has the requested SOC design, the fourteen requested navigation destinations, Arabic/English RTL/LTR, tested 390/760/desktop layouts, explicit unknown/unverified posture, and a shared Achievements ledger. 34/34 tests pass.
- In progress: Authorized discovery/visibility foundations starting at CG-005; external connectors remain gated by authorized labs.
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
| 2026-11-12 | Codex | Added acceptance-gated Achievements ledger and browser-verified CG-001..CG-004; 34/34 Unit Tested. | f479438 |
| 2026-11-12 | Codex | Merged the runnable SOC/evidence implementation; 29/29 Unit Tested. | 6dbf824 |
| 2026-11-12 | Codex | Extended semantic scope/delivery triage through CG-600; 30/30 Unit Tested. | e8356d4 |
| 2026-11-12 | Codex | Added downloadable deterministic case evidence packs and traceability for CG-321..324 subsets. | cff7419 |
| 2026-11-12 | Codex | Added ADR template and evidence-first local architecture decision. | 8e39fda |
| 2026-11-12 | Codex | Added coverage report, support matrix, milestones, test strategy, and blocker register. | 08f22ca, 0938b27, 17acd34, 798e821, 554f683 |
| 2026-11-12 | Codex | Documentation verification passed (1,440 IDs); GitHub push blocked by missing Git credential. | 54d3855 |
