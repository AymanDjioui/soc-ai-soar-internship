# Phase 8G Parts A–D — Linux/Windows validation and permanent L2 activation

**Date**: 2026-08-24. **Release**: `17e9f35` (unchanged from Parts 1–3 —
no code changes were needed for Parts A–C). **Production watermark**:
`2026-08-24T15:08:48+00:00`.

## Part A — Linux and Windows validation

**Infrastructure finding, reported accurately per instruction, not
fabricated**: both `linux-lan-logs-*` and `windows-logs-*` Elasticsearch
indices showed **zero documents across a full 24-hour window** at test
time — both live pipelines are down, extending the same class of gap
already found for `juiceshop-docker-*` in Phase 8F Step 3. This predates
and is independent of this session's testing.

Per the task's own fallback, **existing real alerts** were used instead
of generating undetectable fresh traffic:

| | Alert | Case (existing) | Verdict | Tools used | Latency | GPU peak |
|---|---|---|---|---|---|---|
| Windows | `~409743416` "Suspicious PowerShell Execution Detected" (real `elastalert2` detection, `New`, no case) | — | inconclusive, 0.3, N/A | `search_past_cases` (real hostname `DESKTOP-FK7RO72`) | 15.14s | 100%, 4959 MiB |
| Linux | `~286793928` "Direct Root SSH Login Detected" (real `elastalert2` detection, already had a case) | `~123019408` | inconclusive, 0.5, N/A | `search_elasticsearch` (real IP `192.168.10.1`, 1 hit), `run_analyzer` (correctly degraded to `not_wired`, no live Cortex job) | 17.29s | 100%, 4961 MiB |

Both run through the proven shadow one-shot path (`SOAR_AGENT_DRY_RUN=1`,
`SOAR_AGENT_MODE=shadow`, `SOAR_DRY_RUN=1`). **Zero mutations on
either**: before/after comparison confirmed identical status, case
linkage, assignee, and (for the Linux alert, which already had a case)
identical comment/action counts.

## Part B — permanent-activation preflight (all passed)

1. `soar-agent-l2-worker.service`: disabled, inactive (confirmed before any change).
2. Kill switch: active, mtime unchanged since Phase 8D.
3. No `PFSENSE_*`/`RESPONDER_NAME` anywhere reachable by the worker (credential file and unit file both checked by name).
4. `l2-only` confirmed hardcoded in *code*, not config: `env["SOAR_DEMO_ACTION_MODE"] = "l2-only"` is an unconditional Python assignment in the deployed `l2_worker.py`, not read from any environment variable — no credential file or config change could ever override it.
5. Circuit-breaker trip evidence preserved (see Phase 8G Part 3 doc, and again below): `{"tripped_at": "2026-08-24T14:32:07Z", "cases_last_hour": 3, "emails_last_hour": 3}`.
6. Manual reset performed (`rm CIRCUIT_BREAKER_TRIPPED`).
7. New production watermark recorded: `2026-08-24T15:08:48+00:00`.
8. Full current-alert baseline captured before enabling: 15 alerts, all `createdAt` before the new watermark, all otherwise fully eligible (`New`/`elastalert2`/no case) — including the entire hour of ambient traffic that accumulated during the soak test window. This is the concrete exclusion-proof set.
9. Claim state for the 3 soak-test alerts re-verified: still `completed` after the breaker reset and watermark change.
10. Credential file: `root:root`, `600`, unchanged (names only checked, no value read).
11. **Documented here**: `soar-live-demo` (Analyst profile) is being used as the permanent worker's service identity for this initial controlled activation. This is temporary — before any extended unattended operation, it should be replaced with (or renamed to) a dedicated production service identity, distinct from the manual demo/test account it originated as.

## Part C — permanent enablement

`sudo systemctl enable --now soar-agent-l2-worker.service` — executed
exactly as explicitly approved.

**Immediate post-enable state**: `enabled: enabled`, `active: active`,
correct immutable release (`17e9f35`), correct new watermark
(`15:08:48Z` — confirmed via the `ExecStartPre` precheck log line), kill
switch active, no containment variables present, state directory
writable, shadow service (`soar-agent-shadow.service`) still
disabled/inactive throughout.

**A second circuit-breaker trip occurred immediately on the first poll
— correct behavior, not a malfunction.** The breaker counts real audit
events over a *rolling* 1-hour window, not a resettable counter: the 3
cases from the soak test (14:27–14:31) were still inside the trailing
hour from the new activation time (15:09), so the very first evaluation
re-tripped on the same real evidence. Deleting the marker file clears
the *alarm*, not the underlying history — by design, since the
alternative (a marker-only reset that ignores recent real activity)
would be a weaker safety property, not a stronger one.

**Correction to an earlier statement in this session**: I initially told
the operator the breaker would "clear naturally around 15:31" once the
3 soak-test cases aged out of the rolling window. Re-reading
`check_circuit_breaker()`'s actual implementation shows that prediction
was wrong: once the trip marker file exists, the function returns
`tripped=True` immediately and **never recomputes the underlying counts
again** — it is intentionally sticky, matching requirement #14's literal
text ("require manual reset") more faithfully than a self-clearing
rolling window would have. It cannot clear on its own, ever, regardless
of how much time passes.

**Confirmed by direct evidence, not inference**: every one of 28+
consecutive poll cycles from activation (15:09:28) through the end of
this observation window (15:38:29) produced exactly one audit event —
`l2_worker_circuit_breaker_tripped` — and nothing else. Zero
`l2_worker_claimed`, zero `agent_case_created`, zero
`agent_notification_mailer_accepted` events appear anywhere after
activation. This is airtight, log-verified proof of:
- **Zero backlog processing** — the breaker check runs before the alert
  fetch, so no backlog alert (or any alert at all) was ever evaluated
  against eligibility.
- **Zero new-alert processing** — same reason; no alert created after
  the watermark has been touched either.
- **Zero containment, zero duplicates** — trivially true, since nothing
  was processed at all.

Checkpoint state re-verified unchanged: the 3 soak-test claims
(`~409882824`, `~245891208`, `~245915880`) all still show `status:
completed` with their original `completed_at` timestamps, untouched by
the permanent activation. Service PID unchanged (`4349`) since start —
no crash, no restart, continuously healthy and correctly self-gating for
the full 29-minute observation window. Kill switch active and untouched
throughout.

**Current state, as left**: `soar-agent-l2-worker.service` remains
**enabled and active**, correctly blocked by its own circuit breaker.
Whether/when to issue the manual reset is an operator decision, not
something this session performed — per explicit instruction, the
breaker's state was inspected only, never modified.
