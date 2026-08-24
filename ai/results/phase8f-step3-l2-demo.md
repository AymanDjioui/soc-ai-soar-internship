# Phase 8F Step 3 — live armed L2-only demonstration

**Date**: 2026-08-24. **Source commit**: `25b6b10101ec8fd009307be7eb64595d9206e2b9`.
**Release**: `~/soc-ai-soar/releases/25b6b10/`. Systemd service never
started/enabled — this was a manual one-shot invocation
(`SOAR_ALERT_ID` + `SOAR_DEMO_ALLOWED_ALERT_ID` + `SOAR_DEMO_ACTION_MODE=l2-only`),
armed (`SOAR_AGENT_DRY_RUN=0`, `SOAR_AGENT_MODE=armed`, `SOAR_DRY_RUN=0`).
Kill switch active throughout; all pfSense/responder credentials remained
absent from the environment.

## Two things kept deliberately separate, as instructed

### 1. The SQLi probe (application-layer success, no detection)

A classic Juice Shop admin-bypass SQLi probe (`' OR 1=1--`) was sent to
`http://100.70.145.65:8080/rest/user/login` — non-destructive, no data
modified. It **succeeded at the application layer** (HTTP 200, a real admin
JWT returned) but **produced no matching TheHive alert**. Direct
investigation found why: the `juiceshop-docker-*` Elasticsearch index had
**zero documents**, both in a 10-minute and a 2-hour window. This is not a
consequence of this test — a `PIPELINE QUIET: Juice Shop (juiceshop-docker-*)
silent 4h` watchdog alert was already sitting in TheHive, captured in this
session's own Phase 8E baseline roughly an hour before this test ran. The
outage predates this session.

**This finding is recorded here for the record. It has nothing to do with
the L2 demonstration below** — the alert used for that demonstration is
real, live, unrelated lab traffic.

### 2. The L2 escalation demonstration (real alert, successful with one gap found)

**Selected alert**: `~245813256`, *"Business Logic Abuse on Juice Shop"*
— chosen over the other fresh candidate (*"Sensitive Data Exposure"*,
whose evidence was a socket.io polling request that didn't actually match
its own rule's stated criteria — assessed as a likely false positive and
not selected). The chosen alert's evidence (`POST /rest/basket/1`, body
`{"quantity":999}`) is a clean, specific match for its rule's own stated
criteria (extreme-quantity business-logic abuse).

**Real tools and evidence used**:
- Real TheHive alert promoted to a real case (`~409657400`).
- `search_past_cases` (RAG) found genuine prior TruePositive history for
  the source IP — used directly in the model's reasoning.
- `search_elasticsearch` was attempted 3 times by the model with empty
  arguments; the empty-argument safety cutoff fired correctly after the
  3rd attempt, forcing a conclusion rather than looping — a live,
  real-data confirmation of that specific mechanism.
- Real Mistral 7B inference (localhost Ollama, NVIDIA L4, peak 100%
  utilization, 4959 MiB VRAM).
- Real Cortex `Mailer_1_0` responder invoked exactly once, `status=Success`.

**Verdict**: INCONCLUSIVE, confidence 0.5, severity medium, T1548 → **L2
escalate** (`NOVEL_CASE`).

**Mutation proof**: exactly 1 case created, exactly 3 comments posted
(investigation trace, escalation summary, notification audit record),
exactly 1 Cortex action total (`Mailer_1_0`, `Success` — verified by name,
not just count), zero containment attempted, zero pfSense contact, case
remains open (`status: New`).

**Replay test**: re-running the identical `(alert_id, action_mode)` was
**refused at the demo-allowlist checkpoint**, before `promote_to_case` or
any other mutation-capable code path was ever reached. Re-verified
afterward: still exactly 3 comments, still exactly 1 Cortex action — zero
duplicates.

## One real gap found — and fixed (Phase 8F.1)

**Requirement**: assignment to `soc-l2@thehive.local`.
**Original result**: the case's assignee was `soar-live-demo@thehive.local`
— the service account that ran the test, not the intended SOC-L2 login.

**Root cause**: TheHive auto-assigns the API caller as a case's
owner/assignee at creation time. The code's L2-assignment eligibility
check (`assign_l2_verified` → `l1_policy.evaluate_l2_assignment_eligibility`)
treated *any* existing non-empty assignee as `already_satisfied
(existing_analyst)` — a deliberate rule meant to never steal a case from a
human who already has it — but didn't distinguish a genuine human
analyst from the automation's own service account landing there first by
default. A **functional gap, not a safety violation**: no unintended
write happened beyond what the code's own (overly broad) safety rule
decided not to do.

### Code fix — commit `c17e1c432e9e78cc7fef69233df394f5bb954410`

`evaluate_l2_assignment_eligibility()` now accepts `caller_login` — the
authenticated API caller for *this* execution, resolved via a new
`agent_orchestrator._resolve_caller_login()` (`api.user.get_current()`).
Only an **exact match** between the live case's assignee and
`caller_login` is treated as auto-ownership eligible for reassignment;
anything else — a real human, a *different* service account, or a
failed/ambiguous `/user/current` lookup — still fails closed and
preserves the existing assignee exactly as before.

Added `agent_orchestrator.correct_auto_ownership_assignment()` — a
separate, narrowly-scoped function for fixing a case the old code already
processed once. Deliberately **not** built on `assign_l2_verified()`
itself (its normal path posts an evidence comment for any fresh
assignment — correct there, but a duplicate here). This new function
modifies *only* the assignee field and has no code path capable of
posting a comment, triggering a notification/responder, or touching case
status.

**41 new tests** added to `test_l2_assignment.py` (128 total, up from 87):
empty assignee, already-assigned-to-target, automatic service-account
ownership (the core fix), a *different* service account (must still be
preserved), a real human assignee, missing/failed `/user/current`, 6
ambiguous `get_current()` response shapes, replay/idempotency, and zero
comment/notification/containment/closure side effects during the
standalone correction. **727/727 local, 676/676 VM-runnable** (same
known `test_phase7d.py` non-issue as every prior deployment). Deployed as
new immutable release `c17e1c4` — `25b6b10`, `81fffb3`, and `008a5fe9`
all preserved on disk, checksums verified unchanged.

### Live correction on case `~409657400`

Preconditions verified immediately before: assignee exactly
`soar-live-demo@thehive.local`, case open (`status: New`), exactly 3
comments, exactly 1 Mailer action, kill switch active, service
disabled/stopped.

**Result**: `{"corrected": true, "reason": "verified", "before_assignee":
"soar-live-demo@thehive.local", "after_assignee": "soc-l2@thehive.local"}`

**Postconditions verified after**: assignee is now `soc-l2@thehive.local`
✅; case still open (`status: New`, unchanged) ✅; comment count still
exactly 3 — same timestamps, none added ✅; Mailer action count still
exactly 1 (`Mailer_1_0`/`Success`, unchanged) ✅; zero containment actions
✅.

**Replay of the correction**: `{"corrected": true, "reason": "already the
target login — idempotent no-op"}` — no PATCH issued the second time.

## Final state

Service: disabled, inactive. Kill switch: active, untouched throughout
both the original run and the correction. No persistent armed
configuration — the installed systemd unit's own environment was never
modified; every armed variable was exported only for the duration of
each manual invocation.

## Components to check for the pipeline outage (not repaired in this step)

1. Juice Shop's own log forwarder/agent (whatever ships its access log
   toward the DMZ log path).
2. The pfSense-side relay for DMZ traffic (if the path routes through it).
3. Logstash input/output configuration for the `juiceshop-docker-*` index
   specifically.
4. Elasticsearch index activity itself — confirm whether a fresh
   `juiceshop-docker-*` index is even being created/rotated currently.
