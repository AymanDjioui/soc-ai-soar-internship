# Phase 8G.1 — circuit breaker redesign, identity rotation, controlled reset

**Date**: 2026-08-24. **Source commit**: `acee67e9eb988a955cc3b357da21f8ffd81b0081`.
**Deployed release**: `~/soc-ai-soar/releases/acee67e/`. **Watermark**:
`2026-08-24T15:08:48+00:00` (unchanged — this is a code/identity migration
of the same production epoch, not a new one). **Identity**:
`soc-l1-ai-agent@thehive.local`.

## Correction from the previous session turn

I told the operator the tripped circuit breaker would "clear naturally
around 15:31." That was wrong. Re-reading `check_circuit_breaker()`
showed it is intentionally sticky — once the trip marker exists, the
function returns `tripped=True` immediately and never recomputes
counts. It cannot self-clear, ever, matching the original requirement's
literal text ("require manual reset") more faithfully than a
self-clearing window would have. Confirmed directly: 28+ consecutive
poll cycles from activation (15:09:28) through 16:10 produced only
`l2_worker_circuit_breaker_tripped` events — zero cases, zero emails,
zero anything else the whole time.

## 1. Circuit breaker redesign

Two real problems, both found through live operation, not speculation:

1. **Epoch bleed** — the counting window was a bare rolling hour with no
   floor at the current activation watermark. A fresh production epoch
   inherited trip-worthy history (3 cases/3 emails) from the *prior*
   soak-test epoch, tripping on the very first poll before any
   production alert was ever evaluated.
2. **Audit noise** — every poll cycle re-announced "tripped" as its own
   event, making a genuine new trip indistinguishable from "still
   tripped, nothing changed."

**Fix**: the counting window is now `max(now - 1h, activation_watermark)`
— it can never reach into a prior epoch. Steady-state long-running
behavior (watermark older than an hour) is unchanged. Exactly one
`l2_worker_circuit_breaker_tripped` event fires on the genuine
untripped→tripped transition; subsequent cycles emit a rate-limited
`l2_worker_circuit_breaker_heartbeat` instead (default 15 min interval,
`SOAR_WORKER_BREAKER_HEARTBEAT_INTERVAL`).

**New administrative interface** (`circuit_breaker_status()`,
`reset_circuit_breaker()`, and companion CLI `l2_worker_admin.py`) is
now the *only* sanctioned way to clear a trip — never delete the marker
file by hand. A reset requires a non-empty `--reason`, is refused if the
epoch-bounded count is still at/above threshold (so it can only ever
confirm genuine improvement, never override an active real trip), and
writes a sanitized audit event on both success and refusal.

**20 new regression tests** (71 total in `test_l2_worker.py`, up from
51): inherited soak-history exclusion (the exact live-found bug),
confirmation a real trip still fires correctly when the epoch does
include it, restart persistence, invalid reset (empty reason), premature
reset (count still high — refused), successful audited reset, reset on
a never-tripped breaker (refused, nothing to do), and audit-event
deduplication with heartbeat timing. **798/798 local, 747/747
VM-runnable** (same known `test_phase7d.py` non-issue as every prior
deployment).

## 2. Identity rotation

The operator created `soc-l1-ai-agent@thehive.local` directly and
rotated the API key in place inside `/etc/soc-ai-soar/live-demo.env`.
Verified via a live, read-only `/user/current` call: the credential now
authenticates as `soc-l1-ai-agent@thehive.local`, org `devoteam-soc`,
same Analyst-shaped profile as before — confirming the rotation
succeeded without ever reading or displaying the key value itself.

Per the architecture requirement (a dedicated permanent file, not
continuing to treat `live-demo.env` as production config), the
credential was copied — server-side, values never touched by this
session — into a new dedicated file:
`/etc/soc-ai-soar/soc-l1-ai-agent.env` (`root:root`, `600`), with a
matching `.example` template. Confirmed by name-only inspection: exactly
`THEHIVE_URL`/`THEHIVE_API_KEY`/`ES_URL`/`ES_USER`/`ES_PASSWORD`/
`CORTEX_ID`/`MAILER_RESPONDER_NAME` — no `RESPONDER_NAME`, no
`PFSENSE_*`. The worker unit's `EnvironmentFile=` now points at this
dedicated file instead of `live-demo.env`.

**Recommendation, not yet acted on**: revoke the temporary
`soar-live-demo` API key now that `soc-l1-ai-agent` is confirmed
active and in use. This was *not* performed — it requires your explicit
approval, same as every other credential action in this project.

## 3–4. Deployment and unit migration

Full suite + secret scan + `py_compile` passed (see above). Committed
(`acee67e9eb988a955cc3b357da21f8ffd81b0081`) and pushed. New immutable
release deployed; all five prior releases (`17e9f35`, `c17e1c4`,
`25b6b10`, `81fffb3`, `008a5fe9`) preserved, checksums verified
unchanged (including a fresh checksum comparison of `17e9f35` against
its own pinned commit, confirming the earlier VM outage/restart caused
no corruption).

Unit reinstalled atomically while the service was **stopped throughout**
(confirmed via a live `systemctl is-active` check immediately before the
swap) — no processing race possible. `systemd-analyze verify`: clean.

## 5–6. Preflight and controlled reset

All required preconditions verified before touching the breaker:

| Check | Result |
|---|---|
| Old rolling-window counts below threshold | **0 cases / 0 emails** in the current epoch (via `circuit_breaker_status`, epoch-aware) |
| Production watermark correct | `2026-08-24T15:08:48+00:00`, unchanged, still valid |
| Backlog remains excluded | Same alert set observed before and after; nothing processed |
| Permanent identity active | `soc-l1-ai-agent@thehive.local`, confirmed live |
| Kill switch active | Confirmed, mtime unchanged since Phase 8D |
| Mode strictly `l2-only` | Confirmed hardcoded in deployed source (`env["SOAR_DEMO_ACTION_MODE"] = "l2-only"`), not read from any config |
| No pfSense/containment credentials present | Confirmed absent by name in both the new credential file and the unit |

**One explicit, audited reset** performed via `l2_worker_admin.py reset
--reason "..."`: succeeded, marker removed programmatically (never
`rm`'d by hand), sanitized audit event recorded with the full reason and
the verified 0/0 counts. Service started immediately after.

## 7–8. Bounded production observation

First post-reset poll: `status: idle`, 50 candidates evaluated, zero
claimed — the entire pre-existing backlog correctly excluded again,
immediately confirming the fix works under real conditions, not just in
tests. A ~4.5-minute bounded observation window followed (20 consecutive
15-second checks): **every single one reported `idle`**. Audit log
confirms zero `agent_case_created`, zero `agent_notification_mailer_accepted`,
zero `l2_worker_claimed` events at any point after the reset.

**No new post-watermark alert arrived during this observation window.**
Per instruction, this is reported honestly as the healthy waiting
state — no alert was fabricated, no attack was launched to force one.
The worker remains enabled, active, and correctly idle, ready to process
the next genuinely eligible alert whenever one arrives.

## Final state

`soar-agent-l2-worker.service`: **enabled, active**, release `acee67e`,
watermark `15:08:48Z`, identity `soc-l1-ai-agent@thehive.local`, circuit
breaker clear (0/0 in window), kill switch active, zero containment
credentials present, zero alerts processed this epoch (none have
qualified yet).

## Remaining blockers

- **`soar-live-demo` key revocation** — recommended, not performed;
  needs your explicit approval.
- **Three infrastructure gaps**, all pre-existing and unrelated to this
  session's changes: `linux-lan-logs-*`, `windows-logs-*`, and
  `juiceshop-docker-*` ingestion all confirmed silent — see the Badr
  handoff checklist (`ai/results/phase8-badr-handoff-and-l1-readiness.md`)
  for the specific components to check.
- **L1 containment** — still blocked on live pfSense access (unchanged
  from the earlier readiness report).
- **No production alert has been processed yet** — the worker is
  correctly healthy and waiting; whether/when a genuinely new,
  eligible alert arrives depends on real detection traffic, which this
  session did not fabricate.
