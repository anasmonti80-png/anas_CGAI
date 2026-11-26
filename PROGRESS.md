# CyberGuard AI — Cross-Agent Progress

## Handoff protocol

Read this file and `AI_CLOUD_HANDOFF.md` before modifying the project. Treat the Git commit history as authoritative when this file and the branch disagree. Update this file in the same commit as each completed checkpoint.

## Current checkpoint

- **Branch:** `codex/cg001-600`
- **Latest verified implementation checkpoint:** current CG-130 phase (Claude) completes CG-130 research evidence register; CG-129 completes the budget and capacity model.
- **Latest requirements checkpoint:** CG-001..CG-600 have semantic scope/delivery triage. CG-001..CG-130 have current requirement-specific acceptance evidence and are the only rows labelled `acceptance-verified`.
- **Validation:** Unit Tested — verification passes 344, fails 0 and skips 1 environment-gated test across 345 tests on Windows x64, Node 24.21.0 and SQLite 3.53.4. The CG-113 panel was inspected in Arabic and English using an isolated local Chromium instance with synthetic data. No vendor endpoint, identity, network or cloud integration is Production Validated without its required authorized account or lab.
- **Current integration:** the live UI includes every required CG-002 sidebar destination, a shared Achievements ledger for CG-001..CG-600, a central asset record with evidence-linked governance context, an evidence-readiness score, a Discover view for authorized observations, and a Settings view that states actual PC/collector/lab visibility boundaries. Unsupported integrations render an explicit evidence/visibility status instead of a simulated result.
- **Running preview:** `http://127.0.0.1:4313` from this worktree; first-run setup is required. QA data stays in an ignored, isolated data directory.
- **Published state:** `codex/cg001-600` is published on `origin` and is the shared Codex/Claude handoff branch. `HANDOFF.md` is the single canonical coordination notebook.

## Safe next work

1. Continue CG-114, the lowest unaccepted requirement; do not skip it for a higher CG number.
2. Promote only requirements whose complete acceptance boundary has current code, test and platform evidence.
3. Keep the Achievements ledger and Claude handoff current after every implementation phase.

## Handoff checklist

1. Fetch the target branch and inspect `git log`, `git status`, `AI_CLOUD_HANDOFF.md`, and this file.
2. Make a focused change and run `node scripts/requirements.js` and `node scripts/verify.js` when applicable.
3. Record the actual result, validation level, exact remaining task, and any external blocker here.
4. Commit the code, evidence, and this file together. Push only with authorization and never include secrets.
