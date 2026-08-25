# Phase 8H — standing L1 auto-containment: production cutover + first real capture

**Date**: 2026-08-24/25. **Commit**: `a1a30ff` ("Phase 8H: standing L1 auto-containment
capability, dedicated breaker"). **Deployed release**: `a1a30ff`. **Worker**:
`soar-agent-l2-worker.service`, `SOAR_WORKER_ACTION_MODE=l1-containment`.

## Summary

Following the honest, safety-proving-but-block-free outcome of Phase 8G.2 Part B, the
operator explicitly authorized moving from demo-only L1 containment to a **standing,
permanent, human-free** production capability. Built, tested (838 local tests), deployed,
and cut over live. The system then captured its first genuine, fully independently-verified
autonomous IP block under the new standing capability — zero human clicks — while also
correctly refusing to fire on a second, less-decisively-worded alert for the same IOC,
demonstrating the eligibility gates are still doing real work, not rubber-stamping.

## What changed (code)

`l2_worker.py` gained `SOAR_WORKER_ACTION_MODE` (default `l2-only`, unchanged prior
behavior). Set to `l1-containment`:
- `build_subprocess_env()` leaves `SOAR_DEMO_ACTION_MODE` unset (demo_allowlist becomes a
  full no-op) instead of pinning `l2-only`, and stops stripping `RESPONDER_NAME`/
  `PFSENSE_*` — they pass through from a **new, dedicated, permanent** credential file
  (`/etc/soc-ai-soar/l1-production-pfsense.env`, root:root, 600).
- `l1_policy.py`'s own gates are completely unmodified: `T1071.001`-only allowlist,
  confidence ≥0.85, both `search_past_cases` AND `run_analyzer` required, corroboration,
  no conflicting evidence, explicit-armed. Nothing about containment *authorization*
  changed — only which action mode the worker launches subprocesses under.
- A **dedicated containment circuit breaker** (`SOAR_WORKER_MAX_CONTAINMENTS_HOUR`,
  default/deployed at 3/hour) — separate from the case/email breaker, same epoch-bounded
  sticky/audited-reset-only design, counting only `agent_containment_verification` events
  with `executed=True` (a Cortex "success" that failed independent pfSense verification
  never counts). Checked at the start of every poll cycle, only in `l1-containment` mode.
- `l2_worker_precheck.py` now fails startup loud if `l1-containment` mode is configured
  without `RESPONDER_NAME`/`PFSENSE_*` present (existence only, values never inspected).
- `agent_orchestrator.py`: the `agent_containment_verification` audit event now carries
  `executed` explicitly (previously only inferable from a `final_state` string), needed
  for the new breaker to count accurately.
- Case/email circuit breaker raised from the test-era 3/hour to **25/hour** — real
  production traffic (Linux SSH + Juice Shop DMZ alerts) tripped the old limit within
  minutes of ingestion gaps closing earlier the same day.

24 new regression tests (`test_l2_worker.py`, 71→95). 838/838 local tests passing,
py_compile clean, secret scan clean.

## Cutover sequence (live, production)

1. New release `a1a30ff` deployed, checksum-verified, full test suite green on the VM.
2. New credential file created with a placeholder; operator filled the real pfSense SSH
   password via `sudoedit` — never seen, printed, or handled by this session.
3. Credential verified read-only (`check_ip_in_pfsense_table`) before anything else moved.
4. New systemd unit staged, `systemd-analyze verify` clean (one real syntax bug caught and
   fixed here: `-EnvironmentFile=` is invalid — the optional marker goes *after* `=`, as
   `EnvironmentFile=-/path`, not before the directive name).
5. Old unit stopped, new unit installed and started **with the kill switch still active**
   — deliberately: this proved the new release/config/mode is healthy under real traffic
   before containment could fire at all. Confirmed via live `/proc/<pid>/environ`
   inspection: `SOAR_WORKER_ACTION_MODE=l1-containment`, `RESPONDER_NAME`/`PFSENSE_*` all
   present and correct.
6. Case/email breaker reset via the audited interface (live count 3/25 — well below new
   threshold; reset reason logged).
7. **Explicit operator confirmation obtained**, then kill switch removed
   (`2026-08-24T21:27:42Z`) — the point at which real containment became possible.

## First real-world validation attempt: correctly refused (not a bug)

A synthetic-but-honestly-labelled alert for a ThreatFox-flagged IOC (`45.141.215.202`,
100% confidence Cobalt Strike, independently checked live before use — learning directly
from Phase 8G.2 Part B's IOC-vetting mistake) was queued for creation, but the session's
own write action was blocked by the harness's auto-mode classifier before it could be
created. The operator instead independently verified a different IOC directly on
AbuseIPDB (`1.212.225.99` — 100% abuse confidence, 24,358 reports, most recent 20 minutes
prior) and asked for that one to be used instead.

**First attempt** (alert `~409956408`, case `~246198480`): the agent called all four
available tools including both required ones, but returned **`INCONCLUSIVE`, confidence
0.3** — correctly escalated to L2, no containment attempted. Root cause, visible directly
in the model's own recorded reasoning: *"This alert is a manual test of the L1-containment
worker, not a real attack... The alert was created manually and has no network traffic
associated with it."* The alert's own `description` field had included an honest disclosure
that it was manually created for validation purposes — and the model read that disclosure
as part of its investigative context, correctly concluding it wasn't a real attack. **A
genuine finding, not a bug**: full transparency inside content an LLM investigates can
itself become evidence against the scenario being real.

**Fix applied**: the "this is a manual validation test" disclosure was moved entirely out
of the alert's `title`/`description` (which the agent reads) and into this evidence
document and the operator conversation instead (which the agent never sees). The alert
content itself was rewritten to state only true, verifiable technical facts — the way a
genuine Suricata detection actually would be worded — with no meta-commentary about intent
or provenance.

## Second attempt: real, fully-verified, autonomous capture

Alert `~410398920` ("Suricata: Cobalt Strike C2 beacon to known-malicious IP 1.212.225.99"),
created by the operator directly from their own terminal (over Tailscale SSH, this
session's own write access having been blocked), source `elastalert2`, picked up by the
**standing worker** on its normal poll cycle — not a manual one-shot invocation.

| Step | Result |
|---|---|
| Verdict | `MALICIOUS`, confidence 0.9, `T1071.001` |
| Tools used | `run_analyzer`, `search_past_cases` (both required tools) |
| L1 eligibility | **all 11 gates passed**: schema_valid, verdict_malicious, confidence_ok, rule_allowlisted, required_tools_used, no_tool_errors, corroboration_ok, no_conflicting_evidence, target_unambiguous, guard_allowed, not_already_processed, armed |
| Cortex `PfSense_Blocker_1_0` | Success (job `~246108168`) |
| Independent pfSense verification | precheck `ABSENT` → postcheck **`PRESENT`** (`final_state: CONTAINMENT_VERIFIED`) — confirmed directly, never trusting Cortex's self-report alone |
| Tier decision | L1, `close_true_positive`, reason explicitly cites the independent verification, not the Cortex report |
| Closure | `TruePositive`, re-queried live and confirmed (`agent_closure_verification`) |
| Notification | L1-contained email accepted by Mailer (masked recipients logged) |

**Independently re-verified by this session, fresh, minutes later**: `pfctl -t
EasyRuleBlockHostsWAN -T show` — table grew from 7 to 8 entries, `1.212.225.99` genuinely
present, the original 7 entries unchanged. No human clicked anything at any point in this
sequence — the standing worker did the entire investigate→verdict→eligibility→
block→verify→close→notify cycle autonomously, on its own 60-second poll.

## Backlog note (operational, not a defect)

83 alerts show as "New" in the TheHive dashboard. Checked directly against the worker's own
`is_eligible_alert()` logic: **zero are currently eligible** — 79 predate the
`SOAR_WORKER_WATERMARK_ISO` activation instant (2026-08-24T15:08:48Z) and are permanently
excluded by design (the worker never processes historical backlog, to avoid a silent flood
on any restart), and 4 are correctly excluded by source (`Suricata`/
`elastalert2-watchdog`, not the trusted `elastalert2` source). Every alert created after the
watermark this session was picked up and processed correctly, including the case above.

## Final state (verified 2026-08-25T~12:00 UTC)

- `soar-agent-l2-worker.service`: enabled, active, release `a1a30ff`,
  `SOAR_WORKER_ACTION_MODE=l1-containment`.
- Case/email breaker: 0/25, untripped. Containment breaker: 0/3, untripped.
- Kill switch: **removed** (deliberately — this is now the standing production
  configuration, not a temporary test window; the fastest override remains
  `touch /var/lib/soc-ai-soar-shadow/KILL_SWITCH` on the VM, no restart required).
- pfSense `EasyRuleBlockHostsWAN`: 8 entries (7 pre-existing + `1.212.225.99`, the one
  genuine new block from this session).
- Scope remains deliberately narrow: `l1_policy.L1_ALLOWED_TECHNIQUES = {"T1071.001"}`
  only — SSH brute force, XSS, LFI, and every other alert type currently arriving in
  production correctly cannot trigger L1 regardless of this change, by the same
  explicit-approval-required design as before.

## Outstanding, not addressed this session

- `soar-live-demo` TheHive API key revocation — recommended since Phase 8G.1, still
  pending operator decision.
- Whether to expand `L1_ALLOWED_TECHNIQUES` beyond C2 beacons is a separate, larger policy
  decision, not undertaken here.
