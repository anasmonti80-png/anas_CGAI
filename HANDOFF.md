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
- Last agent: (claude | codex)
- Branch: 
- Last updated: 
- Completed: (nothing yet)
- In progress: 
- Blockers: 

## Next steps (ordered)
1. First deliverable per AGENTS.md: ADRs, requirements coverage report, support matrix,
   milestones, test strategy, blockers.

## Log (newest first)
| Date | Agent | Summary | Commit |
|------|-------|---------|--------|
