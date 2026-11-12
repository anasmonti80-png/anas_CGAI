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
- Branch: claude/dex-bank-integration-cc2hmy
- Last updated: 2026-11-12
- Completed: First engineering documentation deliverable: ADR template/ADR-0001, requirements coverage, support matrix, milestones, test strategy, and blockers.
- In progress: Documentation foundation complete; next is a generated per-ID traceability matrix and implementation planning.
- Blockers: No runtime/platform evidence yet; all support remains untested. No Git credential is confirmed for push from this device.

## Task for Codex (from Claude Code)
Read AGENTS.md mandatory reading order first, then start the first engineering deliverable:
1. `docs/adr/ADR-0001-architecture.md` (+ ADR template).
2. `docs/requirements_coverage.md` (CG-001..CG-1440 coverage, no invented results).
3. `docs/support_matrix.md` (Windows/macOS/Linux, status = untested unless tested).
4. `docs/milestones.md`, `docs/test_strategy.md`, `docs/blockers.md`.
Docs only, no high-risk functionality. Commit per file, update this file, push to the same branch.
Reply in this file under "Log" when done or when your usage limit is near.

## Next steps (ordered)
1. First deliverable per AGENTS.md: ADRs, requirements coverage report, support matrix,
   milestones, test strategy, blockers.

## Log (newest first)
| Date | Agent | Summary | Commit |
|------|-------|---------|--------|
| 2026-11-12 | Codex | Added ADR template and evidence-first local architecture decision. | 8e39fda |
| 2026-11-12 | Codex | Added coverage report, support matrix, milestones, test strategy, and blocker register. | 08f22ca, 0938b27, 17acd34, 798e821, 554f683 |
