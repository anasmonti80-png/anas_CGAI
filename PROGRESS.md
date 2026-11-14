# CyberGuard AI — Cross-Agent Progress

## Handoff protocol

Read this file and `AI_CLOUD_HANDOFF.md` before modifying the project. Treat the Git commit history as authoritative when this file and the branch disagree. Update this file in the same commit as each completed checkpoint.

## Current checkpoint

- **Branch:** `codex/cg001-600`
- **Latest verified implementation checkpoint:** current CG-026 phase (Claude) completes CG-026 validation tiers; CG-025 completes vulnerability risk ranking.
- **Latest requirements checkpoint:** CG-001..CG-600 have semantic scope/delivery triage. CG-001..CG-026, CG-032, CG-054, CG-056, CG-057, CG-061, CG-068..CG-071, CG-073 and CG-075..CG-091 have current requirement-specific acceptance evidence and are the only rows labelled `acceptance-verified`.
- **Validation:** Unit Tested — Codex independently reproduced `node scripts/verify.js` at 138/138 tests on Windows x64, Node 24.21.0, SQLite 3.53.4 after pulling Claude's checkpoints. Traceability regeneration reports 1,440 tracked, 50 accepted, source integrity passing, and CG-024 as the first unaccepted ID. UI checks passed in local Chromium, including help-desk abuse controls, identity attack correlation, the SaaS/OAuth/service-identity inventory, PAM and all previously listed application views. No live connector lab or Production Validated claim.
- **Current integration:** the live UI includes every required CG-002 sidebar destination, a shared Achievements ledger for CG-001..CG-600, a central asset record with evidence-linked governance context, an evidence-readiness score, a Discover view for authorized observations, and a Settings view that states actual PC/collector/lab visibility boundaries. Unsupported integrations render an explicit evidence/visibility status instead of a simulated result.
- **Running preview:** `http://127.0.0.1:4313` from this worktree; first-run setup is required. QA data stays in an ignored, isolated data directory.
- **Published state:** `codex/cg001-600` is published on `origin` and is the shared Codex/Claude handoff branch. `HANDOFF.md` is the single canonical coordination notebook.

## Safe next work

1. Continue CG-006 with sequential authenticated connector contracts; do not execute active network scanning outside an approved scope.
2. Promote only requirements whose complete acceptance boundary has current code, test and platform evidence.
3. Keep the Achievements ledger and Claude handoff current after every implementation phase.

## Handoff checklist

1. Fetch the target branch and inspect `git log`, `git status`, `AI_CLOUD_HANDOFF.md`, and this file.
2. Make a focused change and run `node scripts/requirements.js` and `node scripts/verify.js` when applicable.
3. Record the actual result, validation level, exact remaining task, and any external blocker here.
4. Commit the code, evidence, and this file together. Push only with authorization and never include secrets.
