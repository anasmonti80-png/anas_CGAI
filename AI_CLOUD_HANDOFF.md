# CyberGuard AI — AI Cloud Handoff

## Read this first

This repository is an **engineering preview**, not a production cybersecurity platform. Preserve the 1,440 historical requirements verbatim and do not claim they are fully complete. Current full-acceptance count is **0**; implemented components only have the evidence stated below.

## Current branch and checkpoints

- Working branch: `codex/cyberguard-foundation`
- Foundation: `40e5466` — requirements, architecture and milestones
- Local evidence API: `b163ba7` — RBAC, event evidence, alerts, cases, guarded local approvals
- Current implementation: `293b75b` — SOC UI, Windows Security JSON adapter, browser QA and traceability subset
- First semantic review batch: pending current commit — CG-001..CG-300 triaged in 44 requirement families; this is scope/delivery review, not full acceptance.

The local working tree should be clean after the current handoff commit. Do not reset or overwrite a newer branch state.

## What is runnable

```text
node scripts/launch.js
```

The app is loopback-only at `http://127.0.0.1:4310`. First setup requires the private token written to `data/setup-token`; no default password exists. `data/` is ignored and must never be committed.

```text
node scripts/verify.js
node scripts/requirements.js
```

Latest local result: **29 passed, 0 failed**, Windows x64 / Node 24.21.0 / SQLite 3.53.4. This is **Unit Tested** using temporary databases, synthetic records and loopback HTTP. It is not Lab Tested or Production Validated.

## Product state

- Local accounts: admin, analyst and viewer roles; session, CSRF, Host/Origin checks.
- Evidence ingestion: strict `cg.telemetry/1`, atomic/idempotent ingest, redaction and hash-linked audit records.
- Windows adapter: accepts manual `cg.windows-export/1` JSON files for Security events 4624/4625/4634. It is synthetic-test only; the PowerShell exporter was syntax-checked, not run against a live security log.
- SOC dashboard: follows the supplied visual reference in `04_REFERENCE/SOC_Dashboard_User_Reference.png`; metrics come from available local data. Security score, scanner data, detection time and prevention remain explicit Unknown/unmeasured when no evidence exists.
- Investigation workflow: alerts, acknowledgement, cases, local asset-criticality preview → independent admin approval → local DB verification → rollback. There is no endpoint, firewall, NCC or network action executor.

## Safety and ownership boundaries

- Never perform live scans, intrusion attempts, containment, port shutdown, device isolation, AD/GPO/SCCM writes, or network-device configuration without explicit authorized scope and an approved change flow.
- NCC owns network configuration and execution. IT Twin owns full what-if simulation. Tickets owns ITSM; CyberGuard stores security cases only.
- Do not add secrets, production telemetry, private inventory, cookies, tokens, databases, setup tokens or customer data to source control.
- Do not turn a source-reported protection state into an independent prevention claim.

## Required reading before changes

1. `AGENTS.md`
2. `docs/engineering/ARCHITECTURE_AR.md`
3. `docs/engineering/MILESTONES_AR.md`
4. `docs/engineering/VALIDATION_AR.md`
5. `docs/engineering/REVIEWED_SUBSETS.json`
6. `docs/engineering/REVIEW_BATCH_001_300.json`
7. `docs/engineering/BROWSER_QA_AR.md`
7. `docs/OPERATIONS_AR.md` and `docs/TELEMETRY_AR.md`

Read `00_START_HERE/` and the 12 requirement chunks before expanding a domain. Preserve `TRACEABILITY.jsonl`, regenerate it with `node scripts/requirements.js`, and distinguish partial component evidence from full requirement acceptance.

## Suggested next work

1. Conduct manual semantic review of the remaining requirements in small, evidence-backed batches; preserve every original record.
2. Build authorized, read-only lab contracts for Windows/Defender/Sysmon before any live connector claim.
3. Add capability contracts and disabled-safe UI states for later EDR, identity, cloud and NCC integrations.
4. Add accessibility checks and cross-browser/device verification for the SOC reference UI.
5. Do not begin AI/LLM or SOAR execution until grounding, tool typing, approval gateway, egress policy and authorized lab tests are designed.

## Suggested prompt for the cloud agent

> Continue CyberGuard AI from `AI_CLOUD_HANDOFF.md`. Work only on `codex/cyberguard-foundation` or a new child branch. Read the required files, preserve all 1,440 verbatim requirements, run `node scripts/verify.js` before and after material changes, label evidence honestly, and never add production scans, device actions or network configuration.
