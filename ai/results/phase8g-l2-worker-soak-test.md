# Phase 8G — permanent L2-only worker: build, soak test, and current state

**Date**: 2026-08-24. **Source commit** (final): `17e9f352b4f90206f9a4a1059fc2dd4cea7d1e53`.
**Deployed release**: `~/soc-ai-soar/releases/17e9f35/`. **Watermark**:
`2026-08-24T14:08:47+00:00`.

## Part 1 — worker implementation

`soar/l2_worker.py`: polls TheHive (read-only) for eligible `New` alerts
and, for each one, invokes the existing, unchanged one-shot orchestrator
(`agent_orchestrator.py`) via subprocess in strict `l2-only` mode. The
worker itself never calls a TheHive/Cortex mutation endpoint — only
polling and local idempotency claims. Containment is structurally
impossible: `SOAR_DEMO_ACTION_MODE=l2-only` is hardcoded in
`build_subprocess_env()` (not merely env-defaulted), and
`RESPONDER_NAME`/`PFSENSE_*` are explicitly stripped from every
subprocess environment.

Sequential (concurrency 1), explicit required watermark (no default —
refuses to start without one), bounded exponential retry with
dead-lettering, persistent circuit breaker (default 3 cases/3 emails per
hour, manual reset required), graceful shutdown, credential redaction on
all captured output, atomic claims surviving restart.

**A real bug was found and fixed during the soak test itself**: the
initial alert-fetch query sorted `createdAt` ascending with a capped
page size. With 25+ permanently-unprocessable backlog alerts already in
`New` status (they will always be there — the worker never touches
them), a genuinely new alert never entered the fetched window at all —
the worker would have starved forever. Fixed by sorting descending
(newest-first) for fetch visibility, then processing oldest-first within
the fetched window. A regression test for this exact scenario (30
backlog alerts + 1 new one, in one page) was added.

**Tests**: 51 tests in `test_l2_worker.py`, covering all 18 required
scenarios (watermark/backlog exclusion, source/tag/status filtering,
watchdog/synthetic exclusion, atomic claim, 6-way race, restart survival,
transient retry, permanent dead-letter, duplicate/already-promoted
skipping, circuit breaker trip+reset, zero containment access, kill
switch pass-through, malformed-result non-fatal handling, credential
redaction, graceful shutdown) plus the pagination regression. **778/778
local, 727/727 VM-runnable** (same known `test_phase7d.py` non-issue as
every prior deployment — missing `ai/` sibling outside the minimal
`soar/`-only release).

Two commits, both pushed: `864d63df782f5f82b88b83808340a034cadc3001`
(initial worker), `17e9f352b4f90206f9a4a1059fc2dd4cea7d1e53` (pagination
fix). Deployed as two successive immutable releases; all four prior
releases (`c17e1c4`, `25b6b10`, `81fffb3`, `008a5fe9`) preserved,
checksums verified unchanged throughout, including across an
unplanned GPU VM restart (Spot preemption) mid-deployment.

## Part 2 — systemd unit

`/etc/systemd/system/soar-agent-l2-worker.service`. Non-root
(`djiouiayman`), source/venv read-only (`ProtectSystem=strict`,
`ProtectHome=read-only`), dedicated `StateDirectory=soc-ai-soar-l2-worker`
(worker's own claims/health) plus continued access to the existing
`soc-ai-soar-shadow` state dir (shared audit log/kill switch/orchestrator
idempotency store). Credentials reused from the already-created,
already-verified `soar-live-demo` Analyst-profile account
(`/etc/soc-ai-soar/live-demo.env`, `root:root`/`600`) — confirmed by
name-only inspection to contain exactly `THEHIVE_URL`/`THEHIVE_API_KEY`/
`ES_URL`/`ES_USER`/`ES_PASSWORD`/`CORTEX_ID`/`MAILER_RESPONDER_NAME`, no
`RESPONDER_NAME`, no `PFSENSE_*`. Safety `Environment=` lines placed
after `EnvironmentFile=` (override-proof). `ExecStartPre` runs
`l2_worker_precheck.py`: credential presence, watermark validity,
kill-switch path well-formedness, live Ollama reachability.
`systemd-analyze verify`: clean. **Installed, disabled, not started
persistently** — every activation in this document was a manual
`systemctl start`/`stop`, never `enable`.

## Part 3 — controlled soak test

### Pre-activation checks (all passed)
- Watermark and full current-alert baseline recorded before anything
  ran: 15+ alerts, all pre-watermark, all otherwise fully eligible
  (New/`elastalert2`/no case) — a strong test case for backlog exclusion.
- Credential file: `root:root`/`600`, exactly the 7 expected variable
  names (checked by name only, no value read).
- Kill switch: active (unchanged mtime from Phase 8D).
- No pfSense/containment variable anywhere reachable by the worker
  (credential file and unit file both checked — the only matches in the
  unit file are explanatory comments, not assignments).
- Circuit breaker: fresh, untripped.

### Live run
First manual start: the worker's first poll saw all 25 backlog
candidates and **processed zero of them** — live proof of backlog
exclusion, not just a unit-test claim. One deliberately-generated
controlled alert (`~245891208`, a non-destructive Juice Shop
business-logic-abuse probe) plus genuine ambient lab traffic produced
three real, eligible, post-watermark alerts across the test window. Each
was processed cleanly:

| Alert | Case | Verdict | Comments | Cortex actions | Assignee | Status |
|---|---|---|---|---|---|---|
| `~409882824` | `~409784320` | inconclusive 0.4 | 3 | 1 (Mailer, Success) | `soc-l2@thehive.local` | New (open) |
| `~245891208` | `~205017240` | inconclusive | 3 | 1 (Mailer, Success) | `soc-l2@thehive.local` | New (open) |
| `~245915880` | `~245948648` | inconclusive 0.3 | 3 | 1 (Mailer, Success) | `soc-l2@thehive.local` | New (open) |

Zero containment attempted in any case (verdicts never reached
`malicious`, and `l2-only` forbids it unconditionally regardless).

### Restart survival
`systemctl restart` mid-soak. The already-processed alert's claim
persisted as `completed` (verified directly: distinct worker PIDs before
and after the restart, same claim record, no reprocessing). The restart
correctly picked up the *next* eligible alert, not a repeat.

### Circuit breaker — live, unplanned confirmation
Ambient lab traffic pushed the count to exactly 3 cases/3 emails within
the hour. **The very next poll cycle tripped the breaker**
(`"circuit breaker tripped: 3 case(s)/3 email(s) in the last hour
(limits 3/3)"`), wrote a persistent trip marker, and **stayed tripped
across 6+ further poll cycles** with no further cases or emails created
— verified directly against the audit log (nothing after the trip
timestamp). This is the single strongest piece of evidence in this
whole test: the safety mechanism activated correctly under real,
unplanned load, not a synthetic scenario.

### Final state
Service stopped (`systemctl stop`), `enabled: disabled`, `active:
inactive`, kill switch active and untouched throughout.

## Not yet done

**Part 3 step 7 (enable the worker to run permanently, unattended)** —
deliberately not executed. Every prior action in this engagement has
been a single, supervised action followed immediately by stopping again;
enabling a permanent, always-on service that creates cases and sends
real emails without per-action supervision is a materially different
kind of decision, and directly touches the "autonomous vs.
human-in-the-loop" question `AGENT-ROADMAP.md` flags as still awaiting
the encadrant's answer. Holding this for explicit confirmation.

**Part 4 (Linux/Windows validation)** — not yet run. The task's own
fallback allows shadow mode here, since a real L2 permanent-worker
alert has already been proven live (three, in fact) — this can proceed
independently of the Part 3 step 7 decision whenever requested.
