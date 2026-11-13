# CyberGuard AI — Cross-Agent Progress

## Handoff protocol

Read this file and `AI_CLOUD_HANDOFF.md` before modifying the project. Treat the Git commit history as authoritative when this file and the branch disagree. Update this file in the same commit as each completed checkpoint.

## Current checkpoint

- **Branch:** `codex/cg001-600`
- **Latest verified implementation checkpoint:** current CG-012 phase (Claude) completes CG-012 with six versioned detection rules raising evidence-linked alerts; CG-011 completes sensitive change monitoring.
- **Latest requirements checkpoint:** CG-001..CG-600 have semantic scope/delivery triage. CG-001..CG-012, CG-016, CG-022, CG-032, CG-054, CG-056, CG-057, CG-061, CG-068..CG-071, CG-073 and CG-075..CG-091 have current requirement-specific acceptance evidence and are the only rows labelled `acceptance-verified`.
- **Validation:** Unit Tested — `node scripts/verify.js` passed 101/101 tests on Windows x64, Node 24.21.0, SQLite 3.53.4. UI checks passed in local Chromium, including help-desk abuse controls, identity attack correlation, the SaaS/OAuth/service-identity inventory, PAM and all previously listed application views. No live connector lab or Production Validated claim.
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
