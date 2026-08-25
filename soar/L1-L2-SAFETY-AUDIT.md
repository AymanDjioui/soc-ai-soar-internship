# L1/L2 Safety Audit — 2026-08-21

Audit only. No code changed, nothing deployed, nothing activated. Read in full:
`soar/agent_orchestrator.py`, `soar/soc_agent.py`, `soar/agent_tools.py`,
`soar/agent_bench.py`, and the working notes/roadmap docs of the time
(`MY-NOTES.md`, `PROJECT-STATE.md`, `AGENT-ROADMAP.md`, `TOMORROW-TODO.md` —
since consolidated into the local-only `PROJECT-ARCHIVE-LOCAL.md`, see
`docs/SECURITY.md`).

Goal being audited against: **zero observed unsafe auto-closures on the locked
evaluation dataset, adversarial tests, integration tests, and shadow-mode run.**

---

## 1. Walkthrough of the current L1/L2 implementation

`agent_orchestrator.process_alert_agent()` does, in order:

1. Skip operational/watchdog alerts (`orch.is_operational_alert`).
2. **Promote to case immediately** (before investigation) — deliberate, so
   `run_analyzer` has real observable ids.
3. Fetch case observables with retry (`OBSERVABLE_FETCH_ATTEMPTS`).
4. `soc_agent.investigate()` — the ReAct loop, up to 6 iterations, produces a
   `VERDICT_SCHEMA`-constrained verdict, then hands it to the **unchanged**
   `containment_allowed()`/`select_containment_target()` from
   `e2e_soc_orchestrator.py` for an `allowed`/`refused` read (evaluate only).
5. If `malicious` and `allowed` and not dry-run → `_execute_containment()` — real
   Cortex responder call, polls `wait_for_responder_action()` for a terminal status,
   sets `executed=True` only on `"Success"`.
6. `l1_disposition(verdict, containment, alert)` — the ONLY function that decides
   tier. Pure, deterministic, no LLM input beyond reading the verdict fields.
7. Post a comment (`build_agent_comment`) — **unconditional, not gated by dry-run**.
8. If `action.startswith("close_")` → `close_case_l1()` (gated by dry-run + kill
   switch). Else → `trigger_mailer_responder()` — **unconditional, not gated by
   dry-run**.

`l1_disposition()` logic today:

```
benign, conf ≥ 0.85, NOT is_attack_signature(alert)  → L1 close FalsePositive
benign, conf ≥ 0.85, IS is_attack_signature(alert)   → L2 escalate
malicious, containment.executed == True              → L1 close TruePositive
everything else                                       → L2 escalate
```

---

## 2. Protections that already exist — confirmed, with file:line

| # | Protection | Where | Status |
|---|---|---|---|
| 1 | ReAct investigation loop | `soc_agent.py:147-308` | ✅ |
| 2 | 5 investigation tools | `agent_tools.py:389-395` (`TOOLS`) | ✅ |
| 3 | Live RAG over closed cases | `agent_tools.py:114-178` (`search_past_cases`) — live TheHive query, not an offline index | ✅ |
| 4 | Elasticsearch investigation | `agent_tools.py:59-98` | ✅ |
| 5 | MITRE ATT&CK KB | `agent_kb/mitre.json` + `get_mitre_context` | ✅ |
| 6 | Investigation playbooks | `agent_kb/playbooks/*.md` (10 files) + `get_playbook` | ✅ |
| 7 | Live Cortex analyzers | `agent_tools.py:314-385` (`run_analyzer`) — real job submit+poll+taxonomy read | ✅ |
| 8 | Deterministic `policy_guard()` | imported unchanged, `soc_agent.py:42-43`, called `soc_agent.py:291-298` | ✅ |
| 9 | Deterministic L1/L2 tiering | `agent_orchestrator.py:75-124` (`l1_disposition`) | ✅ |
| 10 | `is_attack_signature()` veto | `agent_orchestrator.py:60-72`, applied `:93` | ✅ (see gap notes — real but narrow) |
| 11 | Real L1 malicious capture, verified, auto-close | mechanism at `:104-107` + `:297-339`; **the actual pfSense/case verification done this week was manual (my own SSH `pfctl` check), not a code-enforced step** — see §3 P2 | ⚠️ mechanism exists, independent verification is NOT in code |
| 12 | Dry-run-by-default | `agent_orchestrator.py:47` | ✅ |
| 13 | Separate proven armed orchestrator | `e2e_soc_orchestrator.py`, imported not modified | ✅ |
| 14 | 7-case benchmark | `agent_bench.py` + `ai/testset/*.json` | ✅ exists, but only tests `soc_agent.investigate()` — never exercises `l1_disposition`/`is_attack_signature`/closure at all |

None of these need rebuilding. Confirmed present and functioning as described.

---

## 3. Remaining unsafe paths — exact, by priority

### P1 — Benign FalsePositive auto-close (negative-selection today)
Current gate: `benign AND conf≥0.85 AND NOT is_attack_signature(alert)`. This is
allow-by-default, veto-by-keyword — exactly the shape you flagged as insufficient.
Concretely, today, a case auto-closes as FalsePositive even when:
- The alert's rule type has never been reviewed or allowlisted — there is no
  allowlist, no rule-type concept at all in `l1_disposition()`.
- No tool was ever successfully called. The loop can hit the empty-arg cap (3) or
  duplicate-call cap (2) and go straight to a forced verdict with zero investigation
  data. `l1_disposition()` never inspects `res['trace']` or `tools_used`.
- No ES source event was confirmed to exist for the alert.
- `search_past_cases` was never called — RAG is optional, not required. Even when
  called, its `hint` field (e.g. "mixed/other history") is descriptive text for the
  LLM only; `l1_disposition()` never reads it, so there's no code-enforced minimum
  neighbor count or disposition-consensus requirement.
- `mitre_technique` is never inspected by `l1_disposition()`. A `benign` verdict
  carrying `mitre_technique: T1003.002` (credential access) at 0.85 confidence
  closes today exactly like a genuinely benign one — no high-risk-technique block.
- `is_attack_signature()` is a title/tag keyword scan over ~25 hardcoded strings
  (`agent_orchestrator.py:60-65`). A novel or unusually-named rule that describes a
  real attack but doesn't contain one of those substrings passes through untouched.
  This is real (proven this week, §7.5 of `AGENT-ROADMAP.md`) but it is the ONLY
  safety net on this path today — a single keyword list, not defense-in-depth.
- No schema/consistency check beyond JSON parse + confidence-range clamp
  (`soc_agent.py:279-289`) — no check that `reason`/`key_evidence` text is
  consistent with the stated verdict.
- No policy versioning — nothing ties a decision to a specific policy revision.
- No idempotency check before closing (see P5).

### P2 — Malicious TruePositive closure
Better than P1, but one concrete gap: **containment "success" is trusted from
Cortex's own status report alone.** `_execute_containment()` polls
`wait_for_responder_action()` and treats Cortex's `"Success"` string as ground
truth — there is no independent post-action check against the actual pfSense
table (`pfctl`-equivalent) built into the code path. This is exactly the failure
class `e2e_soc_orchestrator.py`'s own docstring warns about (bug #5 in project
history: "the audit log claiming a block succeeded when Cortex had actually
rejected the job") — mitigated there by waiting for a terminal Cortex status, but
never independently re-verified against the firewall itself, in either codebase.
This week's real L1 capture WAS independently verified — by me, manually, via SSH
— not by the agent's own code.

Everything else in P2 is already correctly handled: confidence floor, guard
allow/refuse, external-only (transitively via `policy_guard`), refused/unavailable/
ambiguous/dry-run/unverified all correctly fall through to L2 escalate today
(`agent_orchestrator.py:109-124`). This priority is mostly "verify and add one
independent check," not a rebuild.

### P3 — Real L2 assignment
Does not exist. Today, L2 = `trigger_mailer_responder()` only
(`agent_orchestrator.py:292`) — no case assignee set, no `soc-l2` user resolution
(the account was created manually via curl this session; nothing in code references
it), no tags (`ai-escalated-l2` etc. don't exist anywhere), no post-assignment
verification query, no assignment-failure handling. `build_agent_comment()` is
reasonably structured (trace/verdict/containment/tier) but has no
missing-evidence/conflict/next-steps fields since those concepts don't exist yet.

### P4 — Reason codes
Does not exist. `l1_disposition()`'s `reason` is free-text
(`f"escalated to L2 — {why}"`), not a code from a closed enum. None of the 20
listed reason codes appear anywhere in the codebase.

### P5 — Idempotent state handling
Does not exist, and there's a real gap worth flagging precisely:
`process_alert_agent()` calls `close_case_l1(...)` at line 287-289 **and ignores
its return value**. If the PATCH fails or times out, `close_case_l1` audits
`agent_l1_close_failed` and returns `False` — but the caller doesn't check this,
so the case is left in an ambiguous state (comment posted claiming a tier decision,
TheHive possibly still open, no L2 fallback triggered). No idempotency key exists.
No pre-mutation "check current state" or post-mutation "verify actual state" reads
exist anywhere. No protection against double-promoting the same alert (a second
run would call `promote_to_case` again with no "already promoted" check).

### P6 — Benchmark scale
7 cases only (`ai/testset/`). `agent_bench.py` tests `soc_agent.investigate()`
exclusively — **`l1_disposition`, `is_attack_signature`, and closure have never
been benchmarked**, at any scale (this was already flagged as open in
`TOMORROW-TODO.md` item 7 before this audit). No Dataset A (locked, stratified,
human-reviewed) exists. No Dataset B (310-case replay) exists.

### P7 — RAG evaluation leakage
`search_past_cases()` has no leave-one-out logic, no self-exclusion parameter, no
"only older cases" preference, and returns no similarity score (matching is exact
IP/tag lookup, not semantic — so "similarity score" doesn't currently exist as a
concept to record). This is a real, not-yet-triggered risk: it only manifests once
Dataset B (replaying the 310 closed cases) exists, because a replayed case could
retrieve itself as its own "prior case." No test exists proving self-exclusion.

### P8 — Adversarial tests
None of the 24 scenarios exist as repeatable test code. Several were exercised
once, live, manually, this week (real Kali SQLi, a real C2 IOC, SSDP/STUN via the
campaign) — but ad hoc, against the live shared TheHive/Cortex/pfSense, not as an
automated suite. Timeout-specific behavior (Cortex/ES/Ollama) is not verified
beyond generic `try/except`. Prompt injection is entirely untested (see P9).
"Already-assigned-to-L2" and "Cortex success / pfSense confirmation missing" have
no test coverage — the latter is the same gap as P2.

### P9 — Prompt injection defense
**Unaddressed.** `soc_agent.investigate()` builds `user0` directly from
`alert.get("title")`/`alert.get("description")` — raw, attacker-influenceable
content (SQLi payloads, headers, log lines can all end up here) — and inserts it
into a user-role message with **no delimiting, no "this is untrusted data" framing**.
The `SYSTEM` prompt (`soc_agent.py:83-120`) never tells the model to disregard
instructions embedded in evidence. Tool results are similarly inserted raw
(`"TOOL RESULT:\n" + json.dumps(result)`). One real structural protection already
exists and is worth keeping: **tool names are constrained by the `ACTION_SCHEMA`
enum**, and **case-closing/containment functions are not, and have never been,
exposed as agent tools** — an injected instruction cannot invoke them because they
don't exist in the tool-call surface at all. Tool *arguments*, however, are
free-form strings with no sanitization. No test proves any of this.

### P10 — Full-pipeline integration tests
Do not exist. Everything validated so far has been live manual runs against the
real shared TheHive/Cortex/pfSense — exactly what this priority wants replaced
with a mocked/safe-environment harness for routine testing.

### Metrics
None of the specified metrics are computed anywhere. `agent_bench.py` computes a
much smaller ad hoc set (DETECTION correct/safe/wrong, SAFETY pass, avg latency) —
useful, but not what's specified, and not run against `l1_disposition` at all (P6).

### Shadow mode — one concrete finding
`SOAR_AGENT_DRY_RUN=1` already gives most of shadow mode structurally (no block,
no close — both gated). **But two things are NOT gated by dry-run and mutate/notify
on the shared instance even in "dry run" today:**
1. `promote_to_case()` — runs unconditionally (arguably acceptable/intended, same
   pattern as the main pipeline, needed for `run_analyzer` to have real observable
   ids — but it IS a real, visible mutation on shared TheHive during a "dry run").
2. **`trigger_mailer_responder()` on the L2 path (`agent_orchestrator.py:292`) is
   unconditional — a "dry run" invocation that reaches an L2 disposition sends a
   REAL EMAIL today.** This directly contradicts the target shadow-mode definition
   ("without closing, assigning, blocking, or **emailing**"). This is the one
   finding here I'd flag as most important to fix early, since it's a real external
   side-effect happening silently under a flag whose name implies it shouldn't.

---

## 4. Summary — what's genuinely solid vs. what's the real gap

**Solid, don't touch:** the ReAct loop, the 5 tools, RAG retrieval mechanism, the
guard import (containment decision is untouched and correct), dry-run gating on
close/block themselves, the tool-call surface already excluding closing/containment
functions, the malicious-path logic's fallback-to-L2 behavior on refuse/ambiguous/
dry-run.

**The real work, in the order I'd tackle it:**
1. Shadow-mode mailer leak (small, standalone fix, arguably should happen before
   anything else touches this file)
2. P1 — replace negative-selection with the positive allowlist (the actual ask)
3. P4 — reason codes (small, and P1/P3/P5 all want to emit them)
4. P5 — idempotency + the ignored-return-value bug in `close_case_l1`'s caller
5. P3 — real L2 assignment
6. P2 — the one independent-verification gap
7. P7 → P6 — leakage-safe replay harness, then the two datasets
8. P8/P9/P10 — adversarial + injection + integration tests
9. Metrics + shadow-mode gate + deployment/rollback checklist

Nothing above has been implemented yet. Per your instructions, I'm stopping here
for your review before starting Phase 1.

---

## 5. Phase 1 — IMPLEMENTED 2026-08-21

Scope actually built: **Phase 1** (positive L1 malicious eligibility) + the
standing **Phase 6** directive (disable automatic benign/FalsePositive closure —
folded in now since it's small, low-risk, and a pure reduction in unsafe surface).

### Files changed
| File | Change |
|---|---|
| `soar/l1_policy.py` | **NEW.** `Reason` enum (23 codes — the 20 specified + `AMBIGUOUS_TARGET`, `NOT_ARMED`, `INSUFFICIENT_CORROBORATION`, needed by the gates but not in the original list). `L1_ALLOWED_TECHNIQUES`/`L1_ALLOWED_RULE_KEYWORDS` — the narrow proposed allowlist (T1071.001 / C2 only — see §6). `evaluate_l1_malicious_eligibility()` — the positive-selection gate, 12 independent checks, all must pass. `already_processed()` — audit-log-backed idempotency check (gate 17), fail-safe on read error. |
| `soar/agent_orchestrator.py` | `l1_disposition()` rewritten: benign/inconclusive now **unconditionally** escalate (Phase 6 — no confidence threshold, no keyword-veto branch, `is_attack_signature()` kept as informational-only context on the escalation). Malicious path now requires `eligibility["eligible"]` in addition to `containment.executed`. `process_alert_agent()`: eligibility is now evaluated **before** containment is attempted (previously containment was attempted on guard-allow alone) and audited as its own `agent_l1_eligibility` event. `AGENT_ARMED` added — `SOAR_AGENT_DRY_RUN=0` alone is no longer sufficient; `SOAR_AGENT_MODE=armed` is also required (gate 18's primitive; full Phase 8 preflight/banner/cutoff not built yet). `build_agent_comment()` now shows reason codes. Tier-decision audit event now includes `reason_codes` + `policy_version`. |
| `soar/test_l1_policy.py` | **NEW.** 40 pure unit-test assertions, zero network calls, zero live TheHive/Cortex/pfSense/Ollama access. |

**Not touched** (per deployment constraints): `soc_agent.py`, `agent_tools.py`,
`e2e_soc_orchestrator.py` — no shared function needed a fix this phase.

### Test results
```
PHASE 1 TESTS: 40 passed, 0 failed
```
Coverage: golden eligible case; non-allowlisted technique; low confidence; missing
required tool; tool error; no corroboration (fresh IOC, clean analyzer, no
history); conflicting RAG history; guard-refused; ambiguous target; malformed
verdict schema; not-armed; duplicate processing (+ distinct case_id NOT
flagged, malformed lines skipped, missing-log vs. genuinely-unreadable-log
fail-safe distinguished and both tested); `l1_disposition()` benign-never-closes
(including the former SSDP auto-close case, now also escalates); malicious+
eligible+executed→L1 TruePositive; malicious+ineligible→L2 with propagated reason
codes; malicious+eligible+unconfirmed→L2 not L1.

### Design decisions worth surfacing
- **The allowlist is deliberately narrow and may not fire on the exact demo IOC.**
  `REQUIRED_TOOLS_FOR_L1_CONTAIN` requires **both** `search_past_cases` AND
  `run_analyzer` to have been called, AND `INSUFFICIENT_CORROBORATION` requires a
  tool-derived (not LLM-stated) malicious/suspicious signal. This week's real
  captures often showed AbuseIPDB/VT returning **clean** on a freshly-flagged
  ThreatFox IOC (no prior reports yet) — meaning a genuinely fresh IOC with no RAG
  history will correctly fail the corroboration gate and escalate to L2 on FIRST
  sighting. A human closing that case TruePositive then builds the RAG history
  that lets the *same* IP/pattern pass automatically next time. This is a
  deliberate design choice (learn from confirmed history, not from the LLM's own
  claim), not an oversight — flagging it now because it directly affects whether
  Phase 12's rehearsal produces an L1 auto-block on the first try or needs a
  second sighting / prompt tuning to reliably reach eligibility.
- **`is_attack_signature()` is fully preserved**, just currently inert for the
  close decision (nothing auto-closes as FalsePositive to veto). Still computed
  and surfaced as an informational note on every benign escalation.
- **TruePositive closure still trusts Cortex's own status only** — the
  independent pfSense verification is explicitly Phase 2, not built this turn.
  `l1_disposition()`'s TruePositive branch says so directly in its `reason` text
  so this isn't silently glossed over in the audit trail either.
- `MIN_CONF_L1_CLOSE` (the old benign-closure threshold) is left defined but
  unused, ready for a future benign allowlist.

### Remaining before Phase 1 is "complete" per the full spec
Nothing — Phase 1 as scoped (positive malicious-eligibility gates) is done and
tested. What's still open belongs to later phases: independent pfSense
verification (P2), real L2 assignment (P3/P4), the email matrix (P5), the
locked/replay datasets (P6/P7), the adversarial + injection + integration test
suites (P8/P9/P10), armed demo mode + preflight (P8/P10), and the rehearsals
(P12).

---

## 6. Composite idempotency — IMPLEMENTED 2026-08-21

Built as the shared safety foundation for containment/closure/assignment/email,
per Ayman's explicit instruction, before starting Phase 2.

### Files changed
| File | Change |
|---|---|
| `soar/idempotency.py` | **NEW.** The generic two-phase claim/complete primitives, disk-persisted, cross-process-safe via `os.O_CREAT\|os.O_EXCL`. `decision_key()`/`action_key()` builders. `resolve_ambiguous()` — the hook Phase 2 will fill with a real Cortex+pfSense verifier. `record_tier_decision()`/`get_tier_decision()` — immutable per-case tier record (requirement 7). |
| `soar/test_idempotency.py` | **NEW.** 34 tests on the primitives, including a **real multi-process** concurrency test (8 OS processes racing to claim one key — exactly one wins, verified via `multiprocessing`, not just sequential in-process calls). |
| `soar/l1_policy.py` | `already_processed()` (the old audit-log-scan approach) **removed**, superseded. Gate 17 now reads `idempotency.get_tier_decision()`. `evaluate_l1_malicious_eligibility()` signature changed: `alert_id` added, `audit_log_path` replaced with `store_dir`; now returns `decision_key` and `execution_mode` too. Remains read-only w.r.t. the store — it never records a decision itself. |
| `soar/agent_orchestrator.py` | `process_alert_agent()`: computes the decision key once per case; containment is now claimed/completed under `<dkey>:containment:<ip>` (ambiguous/INTENDED records fail closed via a documented placeholder `verify_fn` — real Cortex/pfSense verification is Phase 2, not built here); the tier decision is recorded **immutably before any side effect**; a belt-and-braces check refuses to close unless the just-confirmed immutable record says L1. Close/notify logic extracted into two standalone, independently-testable functions: `close_l1_idempotent()` (fixes the audit's ignored-return-value finding — the return of `close_case_l1()` is now checked, completed in the store either way, and a failure triggers the mailer escalation fallback instead of vanishing silently) and `notify_l2_idempotent()` (one email per decision key). |
| `soar/test_l1_policy.py` | `eval_case()`/test 12 updated for the new signature and the composite store (old audit-log fixtures removed — that coverage now lives in `test_idempotency.py`). **5 new tests (17-21)** added, isolating the ignored-return-value fix and duplicate-action prevention without mocking the full pipeline. |

**Not touched**: `soc_agent.py`, `agent_tools.py`, `e2e_soc_orchestrator.py`.

### Idempotency state format
One JSON file per action key in the store directory, filename
`<sanitized-key-prefix>__<sha256-16>.json`:
```json
{
  "action_key": "~alert1|~case1|l1-policy-v1-2026-08-21|armed:containment:202.61.130.163",
  "status": "completed",
  "claimed_at": "2026-08-21T...Z",
  "completed_at": "2026-08-21T...Z",
  "pid": 12345,
  "meta": {"target": "202.61.130.163"},
  "detail": {"executed": true, "target": "202.61.130.163"}
}
```
`status` ∈ `intended | completed | failed | skipped`. Claim = atomic file create
(`O_CREAT|O_EXCL`) — exactly one process ever wins a race on the same key.
Complete = atomic rename (`os.replace`) — no torn writes visible to a concurrent
reader.

### Test results
```
IDEMPOTENCY TESTS:  34 passed, 0 failed   (soar/test_idempotency.py)
PHASE 1 TESTS:      57 passed, 0 failed   (soar/test_l1_policy.py — was 40, +12 for
                                            the composite-store integration, +5 for
                                            close/notify idempotency)
TOTAL: 91 passed, 0 failed
```
Confirmed after the full run: the real production store
(`soar/idempotency_store/`) does not exist — no test wrote to real state.

### Requirements checklist
| # | Requirement | Status |
|---|---|---|
| 1 | Persist across process restarts | ✅ tested (module reload simulating a fresh process, state survives on disk) |
| 2 | Record intent AND completion | ✅ INTENDED → COMPLETED/FAILED/SKIPPED |
| 3 | Not in-memory only | ✅ every primitive is disk-backed, no module-level cache |
| 4 | Ambiguous containment → verify before retry | 🟡 mechanism built (`resolve_ambiguous`), **placeholder `verify_fn` returns "unknown"** until Phase 2 wires a real Cortex+pfSense check — correctly fails closed today, doesn't yet actually query anything live (forbidden this phase) |
| 5 | Ambiguous closure → verify before retry | 🟡 same mechanism available; not yet wired to a real TheHive check (Phase 3/4) |
| 6 | Ambiguous assignment → verify before retry | 🟡 same; assignment itself doesn't exist yet (Phase 4) |
| 7 | L2 case never auto-closed by retry | ✅ tested directly — immutable `record_tier_decision`, plus the belt-and-braces re-check right before any close call |
| 8 | Containment never runs twice | ✅ tested |
| 9 | Email never sent twice | ✅ tested (both the generic `test_idempotency.py` action-key level and the real `notify_l2_idempotent()` integration) |
| 10 | Corrupted store fails closed | ✅ tested — raises `IdempotencyError`, never silently proceeds |
| 11 | Ignored-return-value bug fixed | ✅ tested directly (`close_l1_idempotent` tests 17-18) |
| 12 | Two concurrent processes, one owner | ✅ tested with **real OS processes** via `multiprocessing` |
| 13 | Duplicate skips audited with `DUPLICATE_PROCESSING` | ✅ (gate 17 in `l1_policy.py`) |
| 14 | Armed production orchestrator untouched | ✅ |
| 15 | No live calls / deployment | ✅ |

### Honest limitation carried forward
Items 4-6 are the real gap remaining: the *mechanism* to force independent
verification before resolving an ambiguous action is built and tested, but the
actual Cortex/pfSense/TheHive queries that would resolve real ambiguity don't
exist yet — that's explicitly Phase 2 (containment) and Phase 3/4 (closure/
assignment). Today, any ambiguous record correctly fails closed (escalates)
rather than guessing, which is the safe default — but it means an ambiguous
state currently *always* escalates rather than sometimes self-resolving.

Stopping here for review, per instruction, before starting Phase 2.

---

## 7. Invariant confirmation (before Phase 2 began)

**Confirmed the suspected bug was real** before writing any Phase 2 code:
`action_key(decision_key(alert_id, case_id, policy_version, mode), "containment", ip)`
produces a **different** key for the same alert/case/IP whenever `policy_version`
changes (verified directly: `~a|~c|policy-v1|armed:containment:9.9.9.9` vs.
`~a|~c|policy-v2|armed:containment:9.9.9.9` — different strings). A policy
upgrade would therefore have re-triggered a real firewall block on an IP
already blocked under the prior policy version.

**Fixed**: `idempotency.containment_action_key(alert_id, case_id, target_ip,
execution_mode)` — a dedicated key builder for the destructive action only,
deliberately excluding `policy_version` (which governs *eligibility*, not the
physical action's identity) while keeping `execution_mode` (a dry-run "would
block" record must not block a later genuinely-armed attempt). Tier decisions,
closure, and email remain on the policy-version-scoped `decision_key()` — only
containment needed this fix, per the explicit scope of the ask.

Test 19 in `test_containment_verification.py` confirms this directly: a
completed containment is reused (Cortex not re-triggered) across what a policy
upgrade would produce, and `containment_action_key()` is shown to not vary
with policy version at all — the earlier bug has no surface to reappear on.

## 8. Phase 2 — independent pfSense containment verification — IMPLEMENTED 2026-08-21

### Files changed
| File | Change |
|---|---|
| `soar/pfsense_verify.py` | **NEW.** `validate_target_ip()` (pure, `ipaddress`-based). `parse_pfctl_table()` — parses `pfctl -t EasyRuleBlockHostsWAN -T show` output into a set of real `ipaddress` objects (never string/substring matching). `check_ip_in_pfsense_table()` — the public check, `ssh_runner` injectable. `_ssh_pfctl_show()` — the ONLY function touching the network (sshpass+SSH, same pattern used manually throughout this project; `PFSENSE_SSH_PASSWORD` from env only, never hardcoded). |
| `soar/test_pfsense_verify.py` | **NEW.** 23 tests — substring-vs-exact matching, IPv4 normalization (whitespace, `/32` CIDR), malformed/empty/None target rejection, private/CGNAT/protected-asset handling (confirms `policy_guard()` — reused, not duplicated — still refuses correctly), query-failure and malformed-table-line handling. |
| `soar/idempotency.py` | `containment_action_key()` added (see §7). |
| `soar/l1_policy.py` | Two new reason codes: `CONTAINMENT_ALREADY_PRESENT`, `PFSTATE_QUERY_FAILED`. |
| `soar/agent_orchestrator.py` | **Fixed a real bug found while editing**: a dangling, unreachable `print()` statement referencing out-of-scope variables (`alert_id`, `disposition`) was left stranded after `notify_l2_idempotent()`'s `return` — a leftover from the Phase-1/idempotency extraction. Moved to the correct place (end of `process_alert_agent()`) and fixed. `_execute_containment()` now returns a rich dict (`cortex_reported_success`, `responder_id`, `job_id`, `cortex_status`, `error`) instead of a bare bool — Cortex's own claim is captured but never trusted as proof on its own. **New `execute_and_verify_containment()`** — the full Phase 2 flow (pre-check → claim → trigger-or-skip → post-check → complete/leave-ambiguous), `pfsense_check_fn`/`execute_fn` injectable. `l1_disposition()` updated to surface the specific reason code Phase 2 computed instead of only the coarser Phase-1 guess. |
| `soar/test_containment_verification.py` | **NEW.** 47 tests — the full required list (items 1-7, 14-19) plus a sanity section, using injected fakes throughout; item 18 uses **real OS processes** again (multiprocessing), same atomic primitive already proven in `test_idempotency.py`. |

**Not touched**: `soc_agent.py`, `agent_tools.py`, `e2e_soc_orchestrator.py`,
`policy_guard()` (reused unchanged, re-invoked as a defense-in-depth check
immediately before containment, not modified).

### How pfSense output is parsed
```python
def parse_pfctl_table(raw_output: str) -> set:
    ips = set()
    for line in (raw_output or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if "/" in line:
                net = ipaddress.ip_network(line, strict=False)
                ips.add(net.network_address)      # tolerate a /32 suffix
            else:
                ips.add(ipaddress.ip_address(line))
        except ValueError:
            continue                              # skip, don't fail the whole parse
    return ips
```
Membership is then real Python object equality (`ip_obj in table`) — never a
string `in`/substring check, which is what would let `"202.61.130.16"` in the
table wrongly match a query for `"202.61.130.163"` (tested explicitly, §8 test
suite item 8).

### The ambiguous-record resolver (item 5, wired to a real verifier)
```python
def _verify():
    recheck = pfsense_check_fn(target_ip)
    if recheck["result"] == pfsense_verify.RESULT_PRESENT:
        return "completed"          # resolved complete, Cortex NOT re-triggered
    if recheck["result"] == pfsense_verify.RESULT_ABSENT:
        return "failed"             # confirmed negative — do not retry
    return "unknown"                # still ambiguous — fail closed, escalate
resolved = idempotency.resolve_ambiguous(c_key, _verify, store_dir=store_dir)
```
This is the Phase-1 placeholder (`lambda: "unknown"`) now replaced with a real
independent check. Semantics, confirmed by tests 14-16: **present** → resolved
COMPLETED, Cortex never called again; **absent** → resolved FAILED (a
*confirmed* negative, not an assumption that the original action "never
happened" — and still no automatic retry); **query failure** → the record is
left `INTENDED` (genuinely unknown), so a future invocation re-resolves via
this same real check rather than the system inventing an answer.

### Design decisions worth surfacing
- **Post-check query failure does NOT mark the record FAILED** — it's left
  `INTENDED` on purpose (test 7), distinct from a *confirmed* absent (which
  IS marked FAILED). The difference matters: "we don't know" should re-resolve
  later via a real check; "we checked and it's not there" should not be
  re-litigated indefinitely.
- **Item 5's "use the Cortex job ID as additional evidence when available" is
  only partially realized**: `job_id` is captured and audited (`agent_
  containment_cortex_result`... /`agent_containment_verification` audit
  events) but is not yet persisted *into* the idempotency record between claim
  and complete — if a process crashes in that exact window, the job_id from
  that attempt isn't available to a later `resolve_ambiguous()` call (which
  falls back to the pfSense check alone, which remains authoritative per the
  spec: "pfSense membership remains the independent verification source").
  Flagging this as a minor, accepted gap rather than over-building an
  intermediate-state primitive for a narrow crash window.
- **"Never construct an SSH command from an unvalidated raw string"** — already
  true by construction: `_ssh_pfctl_show()`'s command is a fixed literal
  (`pfctl -t <table> -T show`, table name from a config env var, not
  attacker-controlled data); no IP or other request-derived string is ever
  interpolated into it. Confirmed, not newly built.
- **"Verify the selected address is the attacker, not the victim"** — already
  `e2e_soc_orchestrator.select_containment_target()`'s job (src/dst-tag-based),
  reused unchanged. Confirmed, not newly built.

### Test results
```
IDEMPOTENCY TESTS:                34 passed, 0 failed
PHASE 1 TESTS:                    57 passed, 0 failed
PFSENSE VERIFY TESTS:             23 passed, 0 failed
CONTAINMENT VERIFICATION TESTS:   47 passed, 0 failed
GRAND TOTAL: 161 passed, 0 failed
```
Confirmed after the full run: `soar/idempotency_store/` (the real production
store) does not exist — no test wrote to real state, and no live pfSense/
Cortex/TheHive call was made by any test.

### Requirements checklist
| # | Requirement | Status |
|---|---|---|
| 1 | Validate the containment target (ipaddress, malformed rejection, unambiguous target, re-run guard, no raw-string SSH construction, attacker-not-victim) | ✅ all six pieces, tested |
| 2 | Pre-containment check: ABSENT/ALREADY_PRESENT/QUERY_FAILED/AMBIGUOUS | ✅ tested (1, 5, 6) |
| 3 | Trigger+verify Cortex: claim, trigger, store job id, wait, record terminal status, don't complete yet, continue to pfSense | ✅ tested (1-4) |
| 4 | Independent pfSense post-check: exact membership, timestamp, no auto-retry on absent/query-failure | ✅ tested (1, 2, 7) |
| 5 | Resolve ambiguous records via a real verifier | ✅ tested (14-16) |
| 6 | Reuse existing mechanisms; no duplicate credentials/second implementation; `policy_guard()`/`e2e_soc_orchestrator.py` untouched; no GPU deploy; no live test calls | ✅ |
| 7 | Audit fields (alert/case/policy/target/precheck/responder/job/cortex-status/pfsense-result/timestamp/idempotency-key/final-state/escalation-reason) | ✅ all present in `audit_fields`, emitted as `agent_containment_verification` |

## 9. Phase 2.5 — Cortex job-ID persistence — IMPLEMENTED 2026-08-21

Closes the "job_id captured and audited but not persisted into the idempotency
record between claim and complete" gap flagged as an accepted limitation at
the end of §8.

### Files changed
| File | Change |
|---|---|
| `soar/idempotency.py` | **NEW primitive** `update_meta(akey, updates, store_dir=...)` — atomically MERGES into an existing record's `meta` dict without touching `status`, via the same write-tmp-then-`os.replace` pattern as `complete()`. Requires the record to already exist (raises `IdempotencyError` otherwise — this is not a way to create a record; fail closed like every other read in the module). |
| `soar/agent_orchestrator.py` | `_execute_containment()` now accepts `idempotency_key`/`store_dir` and calls `idempotency.update_meta()` **immediately after** `create_responder_action()` returns a job id — before the up-to-120s `wait_for_responder_action()` call — then again after the wait with the terminal status. **New `_peek_cortex_job_status()`** — a best-effort, short (5s) reuse of `orch.wait_for_responder_action`, diagnostic-only, never raises, never authoritative. `execute_and_verify_containment()`'s ambiguous-resolve branch now reads `prior_meta["cortex_job_id"]` off the claimed record and, if present, peeks the Cortex status and passes both as `extra_detail` into `resolve_ambiguous()` — supplementary evidence recorded alongside the resolution, never the deciding factor. **New**: on an ordinary Cortex-reported failure, a second pfSense check now runs before completing FAILED — if the IP is unexpectedly present, this is a distinct `CONTAINMENT_STATE_CONFLICT`, not a generic failure. |
| `soar/l1_policy.py` | One new reason code: `CONTAINMENT_STATE_CONFLICT`. |
| `soar/test_cortex_metadata.py` | **NEW.** 8 required tests (26 assertions) — job id persisted before the wait, survives a simulated process restart, `update_meta()` merges (doesn't erase prior fields) and rejects updates to a non-existent record, 10-real-process concurrent `update_meta()` never corrupts the file, ambiguous-resolve falls back cleanly to pfSense alone when no job id is on record, ambiguous-resolve peeks Cortex as a diagnostic hint when a job id IS on record (pfSense still authoritative), Cortex-success-but-pfSense-absent still persists job metadata en route to UNVERIFIED, the state-conflict reason code exists and is distinct. |
| `soar/test_containment_verification.py` | Test 3 updated: pfSense is now checked **twice** on an ordinary Cortex failure (the pre-existing check plus the new Phase 2.5 conflict check), so the fake sequence and assertion were updated (`[ABSENT, ABSENT]`, `pf_calls["n"] == 2`). New test 3b added for the conflict path itself (`[ABSENT, PRESENT]` → `CONTAINMENT_STATE_CONFLICT`). |

**Not touched**: `soc_agent.py`, `agent_tools.py`, `e2e_soc_orchestrator.py`,
`policy_guard()`.

### Cortex job metadata format
Persisted into the containment action's idempotency record (`meta` dict),
written in two passes:

```jsonc
// immediately after create_responder_action() returns, BEFORE the wait:
{
  "cortex_job_id": "~12345",
  "responder_id": "~67890",
  "target_ip": "202.61.130.163",
  "triggered_at": "2026-08-21T12:00:00.000000+00:00",
  "last_cortex_status": "Waiting",
  "last_status_checked_at": "2026-08-21T12:00:00.000000+00:00"
}
// after wait_for_responder_action() returns a terminal status:
{
  "last_cortex_status": "Success",           // merged in — prior fields untouched
  "last_status_checked_at": "2026-08-21T12:00:02.500000+00:00"
}
```
A crash between the two passes leaves `cortex_job_id`/`responder_id`/
`triggered_at` on record with `last_cortex_status` still `"Waiting"` — exactly
the information a later ambiguous-resolve needs to peek Cortex as
supplementary evidence, without ever making Cortex's own status the
authoritative answer (pfSense membership still decides).

### Design decisions worth surfacing
- **Persistence is best-effort and non-blocking**: a failure to persist job
  metadata (`IdempotencyError`, e.g. disk issue) is logged but never aborts a
  containment attempt already in flight against a real firewall — the
  physical action and its bookkeeping are deliberately decoupled so a
  bookkeeping failure can't leave an attacker un-blocked.
- **Cortex status is diagnostic only, never authoritative** — confirmed by
  test 6: pfSense presence is what resolves the ambiguous record to
  COMPLETED even when the peeked Cortex status is captured alongside it; the
  hint is recorded in `resolved` detail but doesn't participate in the
  completed/failed decision.
- **`update_meta()` cannot create a record** — deliberately narrower than
  `claim()`; this keeps "did we ever intend this action" answerable from
  `claim()`/`complete()` alone, with `update_meta()` purely additive.
- **The double pfSense check on Cortex failure is a real behavior change**,
  not just a test fixture update — an ordinary "Cortex says it failed" now
  costs one extra pfSense query per occurrence, accepted as the cost of
  distinguishing a genuine state conflict (something else already blocked
  the IP, or Cortex's failure report was itself wrong) from an ordinary
  no-op failure.

### Test results
```
IDEMPOTENCY TESTS:                34 passed, 0 failed
PHASE 1 TESTS:                    57 passed, 0 failed
PFSENSE VERIFY TESTS:             23 passed, 0 failed
CONTAINMENT VERIFICATION TESTS:   50 passed, 0 failed
CORTEX METADATA TESTS:            26 passed, 0 failed
GRAND TOTAL: 190 passed, 0 failed
```
Confirmed after the full run: `soar/idempotency_store/` (the real production
store) does not exist — no test wrote to real state, and no live pfSense/
Cortex/TheHive call was made by any test.

### Requirements checklist
| # | Requirement | Status |
|---|---|---|
| 1 | Persist job id + responder id before the (potentially slow) wait | ✅ tested (1) |
| 2 | Survives a simulated process restart (fresh module load reads the same store) | ✅ tested (2) |
| 3 | `update_meta()` merges, never erases prior fields; rejects updates to non-existent records | ✅ tested (3) |
| 4 | Concurrent `update_meta()` from real OS processes never corrupts the file | ✅ tested (4), 10-process real concurrency |
| 5 | Ambiguous-resolve with no job id falls back to pfSense alone, no crash | ✅ tested (5) |
| 6 | Ambiguous-resolve with a job id peeks Cortex as diagnostic-only evidence; pfSense remains authoritative | ✅ tested (6) |
| 7 | Cortex success + pfSense absent still persists job metadata en route to UNVERIFIED | ✅ tested (7) |
| 8 | Cortex failure + unexpected pfSense presence → distinct `CONTAINMENT_STATE_CONFLICT` | ✅ tested (8, and 3b in `test_containment_verification.py`) |

## 10. Phase 3 — verified TruePositive closure — IMPLEMENTED 2026-08-21

Same "never trust a subsystem's self-report" philosophy Phase 2 applied to
Cortex, now applied to the closure PATCH itself: `close_case_l1()`'s own
HTTP-success is never sufficient — a case is only ever marked closed in the
idempotency store after an INDEPENDENT re-query of the live case confirms the
disposition actually stuck.

### Files changed
| File | Change |
|---|---|
| `soar/l1_policy.py` | **New `evaluate_l1_closure_eligibility()`** — the positive-eligibility gate for closure, same shape/philosophy as `evaluate_l1_malicious_eligibility()`. 10 gates: ids valid, tier decision is L1, verdict malicious, containment record COMPLETED+verified, containment target IP consistent with the closure request, closure not already completed, case-state query succeeded, no conflicting live disposition, policy-version not drifted since the decision was recorded (gate 8's dedicated "not-already-L2-escalated" requirement is judged from the immutable tier record — item 2 — since no real Phase 4 assignment field exists yet to check independently; documented as a deliberate merge, not an oversight). Two idempotency short-circuits run BEFORE the gates: our own closure key already COMPLETED (`CASE_ALREADY_CLOSED_TRUE_POSITIVE`), or the LIVE case already shows `TruePositive` even though our key was never claimed (a human, or a prior run whose completion record was lost) — both treated as an idempotent no-op success, never a failure. PURE — reads the idempotency store and calls the injected `case_state_fn` once; never claims/completes/PATCHes anything itself. |
| `soar/agent_orchestrator.py` | **New `close_l1_verified()`** — the Phase 3 orchestration, mirroring `execute_and_verify_containment()`'s shape: eligibility gate → claim → structured pre-closure comment (must succeed or the close is aborted) → PATCH (`close_case_l1()`, reused unchanged) → independent re-query → complete only if the live state matches. Ambiguous (`INTENDED`) closure records are resolved by a **dedicated closure-specific recovery function** (not a reuse of containment's pfSense-shaped `resolve_ambiguous()` verify_fn): it re-queries the live case, and — because closing is naturally idempotent (unlike Cortex's trigger) — safely **re-applies** the PATCH itself as the recovery action when the case isn't yet `TruePositive` and carries no conflicting human disposition; if a conflicting disposition is found instead, the PATCH is never re-applied and the record resolves `FAILED`. **New `build_closure_comment()`** and **new `_default_case_state_fn()`** (thin `api.case.get()` wrapper). `process_alert_agent()`'s call site now routes the `close_true_positive` action through `close_l1_verified()` instead of `close_l1_idempotent()`. |
| `soar/l1_policy.py` | (10 reason codes were pre-added in the Phase 2.5 round in anticipation of this phase — see §9's Reason-class listing; no further codes needed.) |
| `soar/test_truepositive_closure.py` | **NEW.** 20 tests (74 assertions) — full happy path, tier-record refusal, all 7 independently-failing eligibility gates (verdict/containment-missing/containment-unverified/target-mismatch/query-failure/conflicting-disposition/policy-drift), both idempotency short-circuits (workflow-adopted, human-adopted), structured-comment content, comment-failure abort, PATCH-failure abort, PATCH-success-and-verified, PATCH-success-but-unverified (left ambiguous, not falsely COMPLETED), duplicate-attempt idempotency, and three distinct ambiguous-record recovery outcomes (adopt-via-eligibility-short-circuit, safe-re-apply, and a genuine race where the live disposition turns conflicting between the eligibility check and the recovery re-check). |

**Not touched**: `soc_agent.py`, `agent_tools.py`, `e2e_soc_orchestrator.py`,
`policy_guard()`. `close_l1_idempotent()` (Phase 2.5's extracted primitive)
is left in place, unchanged, and its 5 existing tests still pass — it is no
longer the production path for `close_true_positive` (superseded by
`close_l1_verified()`), but remains a valid, independently-tested generic
"claim → apply → complete, checking the return value" primitive, kept rather
than deleted since removing tested working code wasn't asked for and Phase 6
(disabled) would still need an equivalent primitive if a benign-closure
allowlist is ever reactivated.

### Closure schema (reused unchanged)
`close_case_l1()` — the same function from Phase 1/2.5, not modified —
still PATCHes exactly: `{"status": "TruePositive", "stage": "Closed", "summary": ...}`.
Phase 3 changes nothing about *what* is sent; it changes *when* the
idempotency record is allowed to say the send worked.

### Structured pre-closure comment (new, `build_closure_comment()`)
Posted BEFORE the PATCH; a failed post aborts the close entirely (`CASE_COMMENT_FAILED`,
record `FAILED`, case left open, escalated) — a closed case with no evidentiary
trail is not acceptable. Renders:
```
## 🔒 SOC Agent — verified TruePositive closure
### Disposition       — verdict, confidence, MITRE technique, reasoning, key evidence
### Containment        — target IP, Cortex job ID + status, pfSense precheck/postcheck + timestamp
### Evidence trail      — tools used, past cases (RAG) consulted, analyzer results
### Closure verification — policy version, all 10 gate results, reason code(s), verification time
```

### The verified closure state transition
```python
claimed = idempotency.claim(close_key, store_dir=store_dir, meta={"case_id": case_id})
# ... (not claimed -> COMPLETED reuse / FAILED no-retry / INTENDED -> dedicated
#      ambiguous recovery, see below) ...

if not orch.post_case_comment(case_id, build_closure_comment(res, containment_result, eligibility)):
    idempotency.complete(close_key, STATUS_FAILED, detail={"reason": Reason.CASE_COMMENT_FAILED}, ...)
    return False   # PATCH never attempted

applied = close_case_l1(api, case_id, "TruePositive", summary=...)   # the PATCH
if not applied:
    idempotency.complete(close_key, STATUS_FAILED, detail={"reason": Reason.CASE_CLOSE_FAILED}, ...)
    return False

# INDEPENDENT re-verification — the PATCH's own HTTP-success is NEVER trusted alone.
live = case_state_fn(case_id)
if live.get("status") == "TruePositive":
    idempotency.complete(close_key, STATUS_COMPLETED, detail={"status": "TruePositive", "verified_at": ...}, ...)
    return True
# mismatch/query-failure -> record LEFT INTENDED (genuinely unknown, not FAILED,
# not COMPLETED) so a later ambiguous-resolve re-checks rather than the system
# inventing an answer now; escalate immediately regardless.
return False
```
Confirmed by test 15 (verification confirms → `COMPLETED`) vs. test 16 (PATCH
reports success but re-query still shows the old status → left `INTENDED`,
returns `False`, never falsely marked `COMPLETED`).

### Design decisions worth surfacing
- **Two distinct idempotency short-circuits, both success not failure**: our
  own key already `COMPLETED` (repeat call, e.g. a retry) vs. the live case
  already `TruePositive` with our key never claimed (a human beat the agent
  to it, or a prior run's completion record was lost). Both adopt the fact
  and resolve any stale `INTENDED` record rather than leaving it stuck —
  found and fixed live during testing (test 18 initially failed: the
  adoption branch only handled "no record yet," not "a stale `INTENDED`
  record exists"; see Errors below).
- **The ambiguous-closure recovery re-applies the PATCH itself when safe** —
  a deliberate difference from containment's ambiguous recovery (which never
  re-triggers Cortex). Closing is naturally idempotent: re-sending the same
  `status`/`stage`/`summary` is a safe no-op if it already landed. The
  recovery function still refuses to re-apply if the live case shows a
  **conflicting** disposition (`FalsePositive`/`Other`/`Indeterminate`) —
  never overwrite a human's decision — confirmed by test 20's genuine race
  (the live disposition turns conflicting between the eligibility check's
  query and the recovery's re-check).
- **A `not eligible` refusal also resolves a stale ambiguous record** — same
  fix as the adoption path: if eligibility now says "no" for a key that a
  prior crashed attempt already claimed, that `INTENDED` record is resolved
  `FAILED`, not left hanging forever.
- **Gate 8 (not-already-L2-escalated) is judged from the immutable tier
  record alone**, not a live "assignee" field — Phase 4 (real L2 case
  assignment) doesn't exist yet, and inventing a field to check against it
  would be building ahead of that phase. Flagged explicitly, not silently
  merged.

### Test results
```
IDEMPOTENCY TESTS:                 34 passed, 0 failed
PHASE 1 TESTS:                     57 passed, 0 failed
PFSENSE VERIFY TESTS:              23 passed, 0 failed
CONTAINMENT VERIFICATION TESTS:    50 passed, 0 failed
CORTEX METADATA TESTS:             26 passed, 0 failed
TRUEPOSITIVE CLOSURE TESTS:        74 passed, 0 failed
GRAND TOTAL: 264 passed, 0 failed
```
Confirmed after the full run: `soar/idempotency_store/` (the real production
store) does not exist — no test wrote to real state, and no live pfSense/
Cortex/TheHive call was made by any test.

### Requirements checklist
| # | Requirement | Status |
|---|---|---|
| 1-10 | Pre-closure validation (ids, tier=L1, verdict malicious, containment verified, target consistency, closure not already done, case-state query ok, not L2-escalated, no conflicting disposition, no policy drift) | ✅ each independently tested (3-9) |
| — | Reuse existing closure schema (`close_case_l1()`, unmodified) | ✅ |
| — | Structured pre-closure comment, close aborts if it fails | ✅ tested (12, 13) |
| — | 7-step closure transition (claim → comment → PATCH → re-query → verify → complete-only-if-verified) | ✅ tested (1, 14, 15, 16) |
| — | 5 existing-case-state behaviors | ✅ workflow-adopted (10), human-adopted (11), conflicting-disposition refusal (8, 20), L2-escalated refusal (2), query-failure refusal (7) |
| — | Ambiguous closure recovery wired to a real TheHive case-state check, closure-specific (not reused from containment) | ✅ tested (18, 19, 20) |
| — | Email kept separate, non-blocking, idempotent | ✅ unchanged — `notify_l2_idempotent()` still handles L2 email on any refusal/escalation path above |

### Errors found and fixed during this phase
The first run of `test_truepositive_closure.py` failed test 18 with a
`KeyError` — root cause: the "already closed" adoption branch in
`close_l1_verified()` only created a fresh idempotency record when none
existed yet; it silently did nothing (returning `True` regardless) when a
**stale `INTENDED` record already existed** from a simulated crashed prior
attempt, leaving that record stuck unresolved forever even though the
function reported success. Fixed by unconditionally resolving to `COMPLETED`
whenever the live fact confirms `TruePositive`, regardless of the prior
record's state (none / `INTENDED`) — and the same fix was applied
symmetrically to the `not eligible` refusal path, which had the identical gap
in the opposite direction (a stale `INTENDED` record left hanging on a
refusal instead of being resolved `FAILED`). Re-run after the fix: 0 failures.

Stopping here for review, per instruction, before L2 assignment (Phase 4).

## 11. Phase 4 — verified L2 assignment — IMPLEMENTED 2026-08-21

Same "never trust the mutation's own lack-of-exception as proof" philosophy
as Phases 2 and 3, applied to case assignment: `api.case.update({"assignee":
...})` not raising is never sufficient — an independent re-query must show
`assignee` actually landed before the assignment idempotency record is
marked `COMPLETED`. Assignment and email are kept as two SEPARATE idempotent
actions, as instructed — this phase never sends email; `notify_l2_
idempotent()` (unchanged) is still called immediately afterward by
`process_alert_agent()`'s escalate branch. The full email content matrix
(Phase 5) is not built here.

### Files changed
| File | Change |
|---|---|
| `soar/idempotency.py` | **New `assignment_action_key(alert_id, case_id, analyst_login, execution_mode)`** — deliberately excludes `policy_version` (same reasoning, and the same class of bug Phase 2 fixed for containment: a policy upgrade must never cause the same case to be reassigned to the same analyst twice). Keyed on the analyst's **login**, not any internal TheHive id, so the key is stable even if that id ever changes. |
| `soar/l1_policy.py` | 11 new reason codes (`L2_ASSIGNMENT_FAILED` already existed). **New `evaluate_l2_assignment_eligibility()`** — pure gate function, same shape as Phases 1/3: 5 idempotency short-circuits checked BEFORE the gates (our own key already `COMPLETED`; a verified L1 closure already completed on the same decision key; the live case already closed `TruePositive` some other way; the live case already assigned to soc-l2; the live case already owned by another human — the last two never require a live-state write to resolve), then gates for tier-requires-L2, case-state query success, and case-open (`stage`, not `status` — confirmed from the real thehive4py schema: `status` carries the disposition type, `stage` is the actual New/InProgress/Closed workflow indicator). |
| `soar/agent_orchestrator.py` | `SOAR_L2_LOGIN` config (default `soc-l2@thehive.local`, env-overridable, not a credential). **New `resolve_l2_user()`** — live `api.user.find(filters=Eq("login", ...))` lookup, process-local cache, requires exactly one ACTIVE (`not locked`) match, never caches a transient query exception. **New `build_l2_escalation_comment()`**, **`l2_escalation_tags()`** (bounded: exactly 2-3 deterministic tags, never grows), **`_post_l2_comment_and_tags()`**, **`_apply_l2_assignment()`**, and **`assign_l2_verified()`** — the full orchestration, mirroring `close_l1_verified()`'s shape: eligibility gate → claim → comment+tags (must succeed or the assignment is aborted) → PATCH → independent re-query → complete only if verified. Ambiguous (`INTENDED`) records are resolved by a dedicated recovery function wired to a REAL case-state check: already soc-l2 → completed; already another human → preserved, completed; still unassigned → the PATCH is idempotent, retried once; unknown → stays unresolved. `process_alert_agent()`'s escalate branch now calls `assign_l2_verified()` and `notify_l2_idempotent()` as two independent calls. |
| `soar/test_l2_assignment.py` | **NEW.** 24 tests (81 assertions) — full happy path; routing checks (benign/low-confidence/guard-refused/containment-unverified all route to L2 via `l1_disposition()`); user resolution (found/cached, not-found, ambiguous, disabled); all 5 existing-assignment behaviors (already-soc-l2, human-owned, verified-L1-closed, conflicting-disposition, query-failure); comment-failure and PATCH-failure aborts; both ambiguous-recovery outcomes (adopt-soc-l2, preserve-human); duplicate invocation; **real 8-process concurrent claim** (only one winner); restart-survival; policy-version-change non-duplication; tag boundedness/determinism. |

**Not touched**: `soc_agent.py`, `agent_tools.py`, `e2e_soc_orchestrator.py`,
`policy_guard()`, `close_l1_verified()`, `close_l1_idempotent()`.

### How the L2 user is resolved
```python
SOAR_L2_LOGIN = os.environ.get("SOAR_L2_LOGIN", "soc-l2@thehive.local")   # not a credential

def resolve_l2_user(api, login=None, user_find_fn=None, force_refresh=False) -> dict:
    login = login or SOAR_L2_LOGIN
    if not force_refresh and login in _l2_user_cache:
        return _l2_user_cache[login]           # process-local cache only
    matches = api.user.find(filters=Eq("login", login))   # LIVE lookup, every fresh resolution
    active = [u for u in matches if not u.get("locked")]
    if len(matches) == 0:   -> L2_USER_NOT_FOUND
    elif len(active) > 1:   -> L2_USER_AMBIGUOUS
    elif len(active) == 0:  -> L2_USER_DISABLED   (all matches locked)
    else:                   -> resolved: True, user_id = active[0]["_id"]
```
The **assignment field and identifier were confirmed from the actual
installed thehive4py schema**, not guessed: `thehive4py/types/case.py`
(`InputUpdateCase.assignee: Optional[str]`, `OutputCase.assignee`) and
`thehive4py/types/user.py` (`OutputUser._id`) — assignment is
`api.case.update(case_id, {"assignee": <user _id>})`, keyed on the user's
internal `_id`, never the login string and never a hardcoded id. A query
exception is never cached (a later call can still retry after a blip);
`L2_USER_NOT_FOUND`/`AMBIGUOUS`/`DISABLED` ARE cached (they're a real
definitive answer at query time) until `force_refresh=True`.

### The verified assignment state transition
```python
claimed = idempotency.claim(assign_key, store_dir=store_dir, meta={...})
# ... (not claimed -> COMPLETED reuse / FAILED no-retry / INTENDED -> dedicated
#      ambiguous recovery, mirrors closure's shape) ...

if not _post_l2_comment_and_tags(api, case_id, res, disposition, containment):
    idempotency.complete(assign_key, STATUS_FAILED, detail={"reason": Reason.L2_COMMENT_FAILED}, ...)
    return  # PATCH never attempted

if not _apply_l2_assignment(api, case_id, l2_user["user_id"]):   # api.case.update({"assignee": ...})
    idempotency.complete(assign_key, STATUS_FAILED, detail={"reason": Reason.L2_ASSIGNMENT_FAILED}, ...)
    return

# INDEPENDENT re-verification — the PATCH's own lack of an exception is NEVER trusted alone.
live = case_state_fn(case_id)
if live["raw"]["assignee"] == l2_user["user_id"]:
    idempotency.complete(assign_key, STATUS_COMPLETED, detail={"assignee": ..., "verified_at": ...}, ...)
    return True
# mismatch/query-failure -> record LEFT INTENDED (genuinely unknown), escalate regardless.
```
Confirmed by test 1 (comment → tags → PATCH → verified → `COMPLETED`) and
tests 16-17 (ambiguous/timed-out record resolved via a real re-query — either
adopting the confirmed soc-l2 assignment or preserving a human's, in both
cases without ever repeating the PATCH).

### Design decisions worth surfacing
- **`stage`, not `status`, is the case-open indicator** — discovered by
  reading the actual installed thehive4py schema rather than guessing:
  `CaseStatusValue` is `New | InProgress | Indeterminate | FalsePositive |
  TruePositive | Other | Duplicated` (the disposition TYPE, open and closed
  values mixed together), while `stage` is the separate `New/InProgress/
  Closed` workflow field this project's own `close_case_l1()` already sets
  explicitly. Phase 3's `_default_case_state_fn()` already captured both
  fields; Phase 4 is the first phase to actually gate on `stage`.
- **Human ownership is a first-class satisfied state, not a failure** — an
  already-human-assigned case returns `verified: True` from
  `assign_l2_verified()`, with `assigned_analyst` reporting the human, not
  soc-l2. The escalation EVIDENCE (comment/tags) is still added if missing —
  ownership and evidence are tracked as separate concerns.
- **Comment/tag failure semantics differ deliberately**: a failed comment
  post aborts the whole assignment (no evidence, no action — same rule as
  Phase 3's closure comment); a failed tag-add is logged and does NOT abort
  it — tags are supplementary evidence alongside the comment, not the
  primary trail.
- **The assignment key is login-keyed, not user-id-keyed** — chosen so a
  TheHive-side user record change (e.g. the account being deleted and
  recreated) doesn't silently fragment the idempotency key space for what a
  human would still consider "the same analyst."
- **Ambiguous recovery never re-posts the comment**, only re-applies the
  PATCH — the same asymmetry Phase 3 established for closure recovery (an
  ambiguous record implies the comment step may or may not have run; not
  re-attempting it avoids a possible duplicate while the idempotent PATCH is
  always safe to retry).

### Test results
```
IDEMPOTENCY TESTS:                 34 passed, 0 failed
PHASE 1 TESTS:                     57 passed, 0 failed
PFSENSE VERIFY TESTS:              23 passed, 0 failed
CONTAINMENT VERIFICATION TESTS:    50 passed, 0 failed
CORTEX METADATA TESTS:             26 passed, 0 failed
TRUEPOSITIVE CLOSURE TESTS:        74 passed, 0 failed
L2 ASSIGNMENT TESTS:               81 passed, 0 failed
GRAND TOTAL: 345 passed, 0 failed
```
Confirmed after the full run: `soar/idempotency_store/` (the real production
store) does not exist — no test wrote to real state, and no live
TheHive/Cortex/pfSense call was made by any test.

### Requirements checklist
| # | Requirement | Status |
|---|---|---|
| 1-9 | Pre-assignment checks (ids, tier decision loaded, requires L2, no verified L1 closure, case-state queried, case open, existing owner checked, comment/tag idempotency, assignment idempotency record) | ✅ each independently tested |
| — | L2 user resolution: live API, correct field/identifier confirmed from the real schema, no guessing, no hardcoded id, process-local cache only, fail-safe on missing/ambiguous/disabled | ✅ tested (6-9) |
| — | 5 existing-assignment behaviors (already-soc-l2, human-owned, closed-TP, closed-other-disposition, query-failure) | ✅ tested (10-13, 18) |
| — | Structured escalation comment + deterministic bounded tags, idempotent, failure keeps case open | ✅ tested (1, 14, 23) |
| — | 9-step assignment transition (claim → resolve user → query → comment+tags → PATCH → re-query → verify → complete-only-if-verified → audit expected-vs-actual) | ✅ tested (1, 14, 15) |
| — | Policy-version change never causes duplicate reassignment | ✅ tested (22) |
| — | Ambiguous recovery wired to a real assignment-verification function, bounded retry, never overwrites a human | ✅ tested (16, 17) |
| — | Rich result dict for the future email phase (case id/link, assigned analyst, verified, reason codes, summary, critical-failure flag) | ✅ every `assign_l2_verified()` test asserts on this dict directly |
| — | No real email sent; assignment/comment failures don't cause repeated actions | ✅ `notify_l2_idempotent()` untouched, called separately; tests 19-22 confirm no duplication |

Stopping here for review, per instruction, before the L1/L2 email notification
phase (Phase 5).

## 12. Phase 5 — verified, idempotent L1/L2 email notifications — IMPLEMENTED 2026-08-21

Reuses the existing Cortex Mailer responder (`orch.trigger_mailer_responder()`'s
tag-then-fire mechanism) — no second SMTP/mail implementation was built.
Adds a deterministic template layer, verified-job-status idempotency (same
claim→trigger→verify→complete shape as Phases 2/3/4), and precise
accepted-vs-delivered terminology.

### Files changed
| File | Change |
|---|---|
| `soar/idempotency.py` | **New `notification_action_key(alert_id, case_id, notification_type, recipient, execution_mode, target="")`** — excludes `policy_version` (same reasoning as containment/assignment keys); `notification_type` (`"L1_CONTAINED"`/`"L2_ESCALATED"`) is part of the key, so the two spaces can never collide. |
| `soar/l1_policy.py` | 5 new reason codes: `NOTIFICATION_ACCEPTED`, `NOTIFICATION_FAILED`, `NOTIFICATION_AMBIGUOUS`, `NOTIFICATION_ALREADY_SENT`, `L1_NOTIFICATION_SKIPPED_UNVERIFIED`. `evaluate_l2_assignment_eligibility()` gained `allow_l1_fallback` (tier gate now accepts `L1` when explicitly authorized — the ONE new legitimate exception, for when a decided-L1 case's verified closure fails and must still reach a human). |
| `soar/agent_orchestrator.py` | `import hashlib, html, re`. Sanitization: `_redact_secrets()`, `_sanitize_for_email()`, `_correlation_id()`. Deterministic templates: `build_l1_contained_email()`, `build_l2_escalation_email()`, `_observable_summary()`, `_case_number()`. Mailer trigger: `_trigger_mailer_verified()` (mirrors `_execute_containment()` — job id persisted via `update_meta()` before the wait). Orchestration: `send_l1_contained_notification()`, `send_l2_escalation_notification()`, `_resolve_ambiguous_notification()` (a genuinely NEW recovery shape — never re-sends, see below), `_run_l2_escalation()` (bundles assignment + notification, reused by both the normal escalate branch and the new L1-verification-failure fallback), `_armed_mode_preflight_check()`. `assign_l2_verified()` gained `l1_fallback`. `process_alert_agent()`'s tail rewired: L1 close now branches on `close_l1_verified()`'s return — `True` → `send_l1_contained_notification()`; `False` → `_run_l2_escalation(..., l1_fallback=True)`, never both. `main()` now calls `_armed_mode_preflight_check()` before processing any alert. |
| `soar/test_notifications.py` | **NEW.** 20 tests (64 assertions) — matching the full required list (§ below). |

**Not touched**: `soc_agent.py`, `agent_tools.py`, `e2e_soc_orchestrator.py`,
`policy_guard()`, `close_l1_verified()`'s own internals, `assign_l2_verified()`'s
core eligibility logic beyond the additive `l1_fallback` parameter.
`close_l1_idempotent()`/`notify_l2_idempotent()` are left in place, unchanged,
their own tests still passing — `notify_l2_idempotent()` is no longer called
from `process_alert_agent()` (superseded by `send_l2_escalation_notification()`,
same "keep the tested primitive, stop calling it in production" pattern as
Phase 3/4's superseded functions).

### Notification decision matrix
| Situation | L1_CONTAINED email | L2_ESCALATED email |
|---|---|---|
| `close_l1_verified()` returns `True` (containment + closure BOTH independently verified) | ✅ sent | not sent |
| `close_l1_verified()` returns `False` (closure verification failed for any reason) | ❌ never sent | ✅ sent (`l1_fallback=True` assignment) |
| Any non-`close_true_positive` disposition (benign, inconclusive, low-confidence, guard-refused, containment-unverified, closure-eligibility failure, any fail-safe route) | never applicable | ✅ sent |
**Correction (Phase 5.5)** — the original wording here overstated this as
"structurally impossible to send both or neither," which is too broad: which
*type* of notification is selected is structural (a single call site gated
on `close_l1_verified()`'s return — tested: 1-6), but the selected mailer
action can still fail. The accurate statement:

> Exactly one notification type is selected for each terminal routing path:
> `L1_CONTAINED` or `L2_ESCALATED`. Notification acceptance can still fail
> and is recorded separately.

Email delivery itself is never guaranteed by this selection logic — see
`NOTIFICATION_ACCEPTED` vs `DELIVERY_VERIFIED` below.

### Action-key format
```
notification_action_key(alert_id, case_id, notification_type, recipient, execution_mode, target="")
  = f"{alert_id}|{case_id}|{execution_mode}:notification:{notification_type}:{recipient}[:{target}]"
```
`notification_type` ∈ `{"L1_CONTAINED", "L2_ESCALATED"}` — part of the key
string itself, so the two key spaces are structurally distinct, never a
matter of careful bookkeeping (tested: 16). `policy_version` is deliberately
excluded (tested: 11) — same invariant class as containment/assignment.

### State transitions
```
claim(nkey) -> build deterministic email -> post as case comment (audit trail)
  -> _trigger_mailer_verified():
       tag case with mail= recipients
       resolve Mailer_1_0 responder id (case-level)
       create_responder_action(..., parameters={"subject":, "body":})
       update_meta(nkey, {"mailer_job_id":, ...})   <- BEFORE the wait (tested: 15)
       wait_for_responder_action(case_id)            <- terminal status
       update_meta(nkey, {"last_mailer_status": status})
  -> interpret status:
       "Success"  -> idempotency.complete(nkey, COMPLETED, {"result": NOTIFICATION_ACCEPTED})
       "Failure"  -> idempotency.complete(nkey, FAILED,    {"result": NOTIFICATION_FAILED})
       anything else (Timeout / call exception / responder unavailable)
                  -> record LEFT INTENDED — complete() is never called at all
```
Ambiguous recovery (a claimed-but-INTENDED record from a crash or timeout) —
**a genuinely different shape from Phase 3/4's recovery**: those safely
RE-APPLY an idempotent PATCH; sending mail is NOT idempotent, so
`_resolve_ambiguous_notification()` NEVER re-triggers the mailer. It only
re-polls the SAME job's terminal status via a fresh, short
`wait_for_responder_action()` call — Success/Failure resolve the record;
anything else stays unresolved. This is how "retry only when duplicate
delivery cannot already be confirmed" is satisfied: the send itself is never
retried, only the read (tested: 13, 14).

### Exact meaning of ACCEPTED versus DELIVERED
- **`NOTIFICATION_ACCEPTED`** — the Cortex Mailer responder JOB reported
  `Success`. This is the only status this module can ever mark `COMPLETED`
  with. It means "Cortex accepted and ran the mailer job successfully" —
  nothing more.
- **`DELIVERY_VERIFIED`** — actual mailbox receipt, confirmed
  programmatically (e.g. IMAP polling an inbox). **Does not exist anywhere
  in this codebase** — not a reason code, not a status, not a claim any
  function makes (tested: 14 explicitly asserts `l1_policy.Reason` has no
  `DELIVERY_VERIFIED` attribute). For the live demo, actual mailbox receipt
  is captured as external, manual evidence (a screenshot) — the code and
  audit trail never claim it themselves.

### Redaction rules
Every field sourced from an alert title/description, analyzer output, or
agent-generated text passes through `_sanitize_for_email()` — ONE choke
point: `_redact_secrets()` (regex-based, replaces the ENTIRE matched span
with `[REDACTED]`) THEN `html.escape()`. Patterns redacted: `Authorization:`
header (whole value, not just the scheme token — a bug found and fixed
during testing, see below), `Bearer <token>`, JWTs (`eyJ...eyJ...` 3-segment
pattern), `api_key=`/`apikey=`, `password=`/`passwd=`/`pwd=`,
`secret=`/`token=` (case-insensitive, `:` or `=` separator). HTML-escaping
runs AFTER redaction, so `<script>`/`onerror=` payloads in alert titles or
agent reasoning text render as inert escaped text, never executable markup
(tested: 17, 18).

### Recovery behavior
| Scenario | Behavior |
|---|---|
| Cortex job reports `Success` | `COMPLETED`, `NOTIFICATION_ACCEPTED` |
| Cortex job reports `Failure` | `COMPLETED` as `FAILED`, `NOTIFICATION_FAILED` — a real confirmed negative, not retried automatically |
| `wait_for_responder_action` times out, or the trigger call itself raises | record left `INTENDED` — genuinely unknown, never marked either way |
| A later run finds an `INTENDED` record | re-polls the SAME job's status ONCE (short timeout); resolves `COMPLETED`/`FAILED` if the job has since reached a terminal state, else stays `INTENDED` — the send is NEVER repeated |
| Process restart / alert replay | the SAME notification key is reconstructed deterministically; `COMPLETED` short-circuits, no resend (tested: 10) |
| Policy-version bump | key excludes `policy_version` — same physical notification, no duplicate (tested: 11) |
| Concurrent invocation | OS-level atomic `claim()` — exactly one process wins (tested: 12, real 8-process race) |

### Test results
```
IDEMPOTENCY TESTS:                 34 passed, 0 failed
PHASE 1 TESTS:                     57 passed, 0 failed
PFSENSE VERIFY TESTS:              23 passed, 0 failed
CONTAINMENT VERIFICATION TESTS:    50 passed, 0 failed
CORTEX METADATA TESTS:             26 passed, 0 failed
TRUEPOSITIVE CLOSURE TESTS:        74 passed, 0 failed
L2 ASSIGNMENT TESTS:               81 passed, 0 failed
NOTIFICATION TESTS:                64 passed, 0 failed
GRAND TOTAL: 409 passed, 0 failed
```
Confirmed after the full run: `soar/idempotency_store/` (the real production
store) does not exist — no test wrote to real state, and no live
TheHive/Cortex/mailer call was made by any test.

### Bug found and fixed during this phase
The `Authorization:` redaction regex (`authorization\s*:\s*\S+`) only
consumed ONE whitespace-delimited token after the colon — for
`"Authorization: Bearer abc123def456"` it matched and replaced only
`"Authorization: Bearer"`, leaving the actual token `abc123def456`
UNREDACTED in the output. Caught by test 18. Fixed by widening the pattern
to consume the rest of the line (`authorization\s*:\s*.+`), verified by
re-running the full redaction test set (0 failures after the fix).

### Requirements checklist
| # | Requirement | Status |
|---|---|---|
| — | Reuse the existing Cortex Mailer responder; no second SMTP implementation | ✅ `_trigger_mailer_verified()` calls the same responder-action mechanism, `orch.MAILER_RESPONDER_NAME`/`CORTEX_ID` unchanged |
| — | Deterministic templates only, no LLM-generated body | ✅ `build_l1_contained_email()`/`build_l2_escalation_email()` are pure Python string formatting |
| — | A failed-verification containment never sends L1_CONTAINED, switches to L2 | ✅ tested (1-6), enforced structurally (single call site gated on `close_l1_verified()`'s return) |
| — | Assignment and email are independent idempotent actions; assignment failure doesn't block email | ✅ tested (8) |
| — | Distinct, stable, policy-version-independent notification keys; L1/L2 spaces distinct | ✅ tested (11, 16) |
| — | `claim → build → trigger → verify → complete`; job id persisted via `update_meta()` before the wait | ✅ tested (15) |
| — | Ambiguous/crashed state never marked delivered; retried only when duplicate delivery can't already be confirmed (i.e., never re-sent) | ✅ tested (13, 14) |
| — | `NOTIFICATION_ACCEPTED` vs `DELIVERY_VERIFIED` used precisely; the latter never claimed | ✅ tested (14) |
| — | Deterministic subject/body field lists (both templates) | ✅ every listed field present in `build_l1_contained_email()`/`build_l2_escalation_email()`, exercised in tests 7-9, 19 |
| — | Secrets/HTML escaped/redacted before insertion | ✅ tested (17, 18) |
| — | Armed mode fails startup clearly on missing config; no silent dry-run fallback | ✅ `_armed_mode_preflight_check()` implemented and wired into `main()` — **not exercised against a live TheHive/Cortex instance in this phase**, per the explicit instruction not to arm or invoke a live responder |
| — | No test performs a network call or touches the real idempotency store | ✅ confirmed (real store absent after the full run) |

### Remaining limitations — honest gaps before the live integration rehearsal
1. **The Mailer_1_0 responder's own `parameters` contract is UNVERIFIED.**
   This project's `_trigger_mailer_verified()` passes the deterministic
   subject/body via thehive4py's standard `InputResponderAction.parameters`
   field — a reasonable, standard integration point — but Mailer_1_0's
   actual Cortex-side implementation is Badr's, not in this repo, and I have
   not read its source. It may ignore unrecognized parameters and instead
   compose the email from the case's own title/description/summary. The
   case comment posted alongside every notification is a deliberate
   belt-and-braces fallback so the deterministic content is on record
   regardless — but **whether the actual email a human receives matches
   `build_l1_contained_email()`/`build_l2_escalation_email()`'s content
   needs to be confirmed by a real send during the live rehearsal.**
2. **`_armed_mode_preflight_check()` has never run against a live TheHive
   instance** — its logic (resolve the L2 user, confirm `MAILER_RECIPIENTS`
   non-empty, `sys.exit` clearly if not) is implemented and unit-tested
   indirectly (via `resolve_l2_user()`'s own tests), but the function itself
   has no dedicated test and has never executed for real, per this phase's
   explicit "do not arm or invoke a live responder" instruction.
3. **`DELIVERY_VERIFIED` is a real, permanently absent capability** — not a
   bug, a scope boundary: this project has no IMAP/mailbox-polling
   mechanism, so no code path can ever move a notification past
   `NOTIFICATION_ACCEPTED`. Actual delivery must be confirmed manually for
   the demo, every time, and that evidence lives outside the audit trail.
4. **`_trigger_mailer_verified()`'s case-level `wait_for_responder_action()`
   reuse depends on TheHive's `listAction` query matching on `objectId`
   alone** — confirmed correct by inspection (the same function already
   matches on `objectId` regardless of whether that id is an observable or a
   case), but has only been exercised against the `FakeApi`/monkeypatched
   `wait_for_responder_action` in tests, never a live case-level responder
   action.

Stopping here, per instruction — implementation, tests, and documentation
complete; no deployment, arming, or live responder invocation was performed.

## 13. Phase 5.5 — native Mailer contract compatibility correction — IMPLEMENTED 2026-08-21

Before the live integration checkpoint (limitation #1 from §12), the user
inspected a real successful Cortex job AND the email it produced. The
installed `Mailer_1_0` worker's actual behavior differs from what Phase 5
assumed and from the public upstream implementation — **the upstream source
must not be treated as an exact copy of the deployed worker.** This section
corrects the implementation against the CONFIRMED LIVE contract before any
live send is attempted.

### Confirmed live Mailer_1_0 behavior
1. Invoked on a complete `thehive:case` object (unchanged from Phase 5).
2. **No custom subject/body parameters were consumed** — the observed job
   used none.
3. Recipients are resolved **solely from `mail=<address>` case tags**.
4. Subject format: `[Case #<caseId>] <case title>`.
5. Body: an HTML case summary — severity, stage, TLP/PAP, owner, assignee,
   creator, description, non-mail tags, case link.
6. **The structured AI comment was NOT reflected in the received email
   body.**
7. Cortex's own report on success: `success: true`, `full.message: "message
   sent"`, an `AddTagToCase` operation for the tag `mail sent`.

### Files changed
| File | Change |
|---|---|
| `soar/l1_policy.py` | 2 new reason codes: `NOTIFICATION_RECIPIENT_CONFIG_MISSING`, `NOTIFICATION_RECIPIENT_TAG_UNVERIFIED`. |
| `soar/agent_orchestrator.py` | **Removed**: `parameters={"subject":, "body":}` from `create_responder_action()` — confirmed unconsumed. **New**: `_validate_email_address()`, `_mask_email()`, `_configured_recipients()` (reuses `orch.MAILER_RECIPIENTS`, refuses rather than guessing if empty), `_sanitize_tag_component()`, `_l1_contained_routing_tags()`/`_l2_escalated_routing_tags()` (deterministic `soc-ai:l1-contained`/`soc-ai:l2-escalated`/`soc-ai:reason-<code>` tags — visible in the native email's tag list even though the template text isn't), `_ensure_case_tags()` (idempotent `mail=`+routing tag merge, then an INDEPENDENT re-query to confirm every expected tag landed BEFORE the responder is ever invoked), `_fetch_action_record()` (a new, independent, read-only `listAction` query — deliberately NOT a modification of `e2e_soc_orchestrator.wait_for_responder_action()`, which discards `responderId`/`objectId` — so responder identity and objectId can be verified from what TheHive itself recorded), `_validate_mailer_report()` (the exact confirmed-live acceptance criteria). **Rewritten**: `_trigger_mailer_verified()` (new signature: `recipients`, `routing_tags` instead of `subject`, `body`; tag-then-verify BEFORE invoking; injectable `action_record_fn` for testability), `_resolve_ambiguous_notification()` (re-poll now re-validates the SAME report-content criteria, not just `status == "Success"`), `send_l1_contained_notification()`/`send_l2_escalation_notification()` (refuse immediately if no configured recipients; FAILED-vs-AMBIGUOUS branching sharpened: no job id ever created, or a job reached a terminal state but failed validation → confirmed `FAILED`; a job exists but times out → genuinely `AMBIGUOUS`; case comment wording corrected to say "audit record, NOT the literal received email"). |
| `soar/test_notifications.py` | **REWRITTEN.** 24 tests (82 assertions) against the corrected contract — see requirements checklist below. |
| `soar/L1-L2-SAFETY-AUDIT.md` | §12's decision-matrix overstatement corrected (see below); this section added. |

**Not touched**: `soc_agent.py`, `agent_tools.py`, `e2e_soc_orchestrator.py`
(including `wait_for_responder_action()` — a genuinely new, separate,
read-only function was added instead of modifying it), `policy_guard()`,
`build_l1_contained_email()`/`build_l2_escalation_email()`'s field lists or
sanitization (still valid — now explicitly documented as case-comment audit
evidence, not email content), the assignment/closure/containment logic from
Phases 2-4.

### Documentation correction (Step 2)
§12's decision-matrix note previously read "structurally impossible to send
both or neither." Corrected in place (see §12 above) to: *"Exactly one
notification type is selected for each terminal routing path: L1_CONTAINED
or L2_ESCALATED. Notification acceptance can still fail and is recorded
separately."* Selection is structural; delivery/acceptance is not guaranteed.

### Corrected recipient handling
```
_configured_recipients()               # reuses orch.MAILER_RECIPIENTS — never guessed
  -> [] : refuse immediately, NOTIFICATION_RECIPIENT_CONFIG_MISSING (before
          claiming, before posting the audit comment)
  -> [...]: _ensure_case_tags(api, case_id, recipients, routing_tags)
       validate each address (strict regex) -> drop invalid ones
       mail_tags = [f"mail={addr}" for addr in valid]
       merge with EXISTING tags (routing tags included), de-duplicated,
         nothing removed
       api.case.update(case_id, {"tags": merged})
       RE-QUERY the case -> confirm every expected tag actually landed
       missing tags -> ok=False, Mailer NEVER invoked
```
Every returned/audited value uses `_mask_email()` — e.g. `s***@e***.com` —
never the raw address (tested: 4).

### Exact Cortex report acceptance criteria (`_validate_mailer_report()`)
`NOTIFICATION_ACCEPTED` requires ALL of:
- a terminal `Success` Cortex status;
- (when independently re-derived via `_fetch_action_record()`) the
  responder id and case `objectId` match what was requested;
- `report["success"] is True`;
- `report["full"]["message"] == "message sent"`;
- if the report carries an `operations` list at all, an `AddTagToCase`
  operation for `mail sent` within it (opt-in — absent entirely in some
  report shapes, per the confirmed-live observation; not required when
  missing, required when present).

Missing/malformed report fields NEVER produce acceptance (tested: 8, 9). The
live re-query confirming the `mail sent` tag is actually present on the case
is captured separately as `mail_sent_tag_confirmed_live` — **supporting
evidence only, never gating acceptance** (tested: 10) — and it is NEVER
treated as, or renamed to, mailbox delivery.

### Idempotency (unchanged shape, sharper failure classification)
The notification action key is unchanged (`notification_action_key()`, still
excludes `policy_version`, L1/L2 spaces still distinct — tested: 21). The
generic Cortex `mail sent` tag is explicitly NOT used as any part of the
idempotency key (tested: 21) — it can't distinguish L1 from L2 and isn't
even present in some report shapes. `_resolve_ambiguous_notification()`
still NEVER re-invokes the responder; it now re-validates the SAME report
criteria on re-poll, not merely `status == "Success"` (tested: 22).

FAILED vs AMBIGUOUS is now classified on whether a job ever existed:
| Situation | Outcome |
|---|---|
| Tag verification fails / responder unresolvable / trigger call raises (no job id) | `COMPLETED` as `FAILED` — a confirmed, resolvable refusal (tested: 18) |
| A job ran and reached `Success`/`Failure` but failed report validation | `COMPLETED` as `FAILED` — confirmed, resolvable |
| A job exists but times out | left `INTENDED` — genuinely `AMBIGUOUS` (tested: 19) |

### Test results
```
IDEMPOTENCY TESTS:                 34 passed, 0 failed
PHASE 1 TESTS:                     57 passed, 0 failed
PFSENSE VERIFY TESTS:              23 passed, 0 failed
CONTAINMENT VERIFICATION TESTS:    50 passed, 0 failed
CORTEX METADATA TESTS:             26 passed, 0 failed
TRUEPOSITIVE CLOSURE TESTS:        74 passed, 0 failed
L2 ASSIGNMENT TESTS:               81 passed, 0 failed
NOTIFICATION TESTS:                82 passed, 0 failed
GRAND TOTAL: 427 passed, 0 failed
```
Confirmed after the full run: `soar/idempotency_store/` does not exist — no
test wrote to real state; `_fetch_action_record()` is always injected
(`action_record_fn=`) in tests, so no test ever performs a real HTTP
request; no live TheHive/Cortex/mailer call was made by any test. The fresh
`THEHIVE_API_KEY` provided for the upcoming live checkpoint was NOT used
anywhere in this turn's work (no live call was made) and is not present in
any file, test fixture, or log line in this repo.

### Requirements checklist
| # | Requirement | Status |
|---|---|---|
| — | No reliance on `parameters.subject`/`parameters.body`; templates no longer claimed to control the received email | ✅ tested (1); docstrings/comments corrected |
| — | Recipients derived only from explicit configuration; converted to `mail=` tags; idempotent; non-mail tags preserved; no duplicates; independently re-verified; Mailer never invoked if verification fails | ✅ tested (2, 3, 5, 7) |
| — | No raw recipient address in logs/comments/reason codes/test fixtures; masked in audit output | ✅ tested (4) — `_mask_email()` used everywhere a recipient could otherwise leak |
| —| Missing recipient configuration refuses and reports the gap, never guesses | ✅ tested (3) |
| — | Original title/description preserved; deterministic `soc-ai:` routing tags added | ✅ tested (6, 7) |
| — | Exact Cortex report acceptance checks; missing/conflicting fields never accept | ✅ tested (8, 9) |
| — | `mail sent` tag treated as supporting evidence only, never gating; `DELIVERY_VERIFIED` never created/used | ✅ tested (10, 19) |
| — | Notification action key unchanged; `mail sent` never used as the key; replay/policy-version/restart/concurrency don't duplicate; ambiguous jobs only re-polled, never re-sent | ✅ tested (13, 14, 16, 17, 21, 22) |
| — | Deterministic comments remain sanitized | ✅ tested (11, 12, 23) |
| — | No test sends a real email or touches the real store | ✅ confirmed (real store absent; `action_record_fn` always injected) |

### Masked live-test plan (for approval — NOT executed this turn)
Per the live checkpoint's Step 4, once approved:
1. Create one TheHive case tagged `synthetic`, `notification-test`,
   `phase-5-live-validation`, with a title that unambiguously states it is
   not a real incident, and a fresh, collision-proof alert/case identifier.
2. Call `send_l2_escalation_notification()` directly (the production
   function — never a manual Cortex UI trigger) with a synthetic `res`/
   `disposition` carrying a safe test reason code, `execution_mode="armed"`,
   and the real `THEHIVE_API_KEY` (env-only, never written to any file).
3. Confirm `_ensure_case_tags()` reports `ok: True` and the case shows the
   expected `mail=` (masked in any output I show you) and `soc-ai:l2-
   escalated`/`soc-ai:reason-*` tags via an independent re-query.
4. Confirm the responder job's terminal status and `_validate_mailer_report()`
   result — report exact (masked) checks, never a raw report dump if it
   could contain a recipient address.
5. Call the SAME notification function a second time and confirm
   `create_responder_action` is invoked exactly once total (idempotent
   replay), using the real idempotency store in a **dedicated, clearly-named
   temp subdirectory** — not the shared production store path — for this
   checkpoint only.
6. Stop and ask you to confirm mailbox receipt and content before writing
   anything beyond `NOTIFICATION_ACCEPTED` — `DELIVERY_VERIFIED` will not be
   written to code under any circumstance; manual confirmation is recorded
   as external evidence in the audit doc only.

Stopping here, per instruction — no live send performed this turn. Awaiting
approval of the plan above before proceeding to the live checkpoint's Steps
3-7.

## 14. Phase 5.5 live checkpoint — EXECUTED 2026-08-21

The GCP GPU VM (`ollama-l4-server-spot`) had been manually restarted after
being found stopped. Before any live send, a read-only recovery check was
run, followed by a real (masked) TheHive/Cortex live checkpoint. Recorded
here in full per instruction.

### Recipient configuration patch (prerequisite)
`_configured_recipients()` did not previously support a canonical multi-
recipient set. Patched: now prefers `SOAR_L2_EMAILS` (comma-separated env
var) over `orch.MAILER_RECIPIENTS`, and always returns a **parsed,
validated, de-duplicated, canonically sorted** list — the same
configuration always produces the same order regardless of env-var
whitespace/formatting. Full test suite re-run before any live call (437
passed, 0 failed, before the checkpoint).

### Step 1 — Read-only GCP recovery check
All 15 items checked via SSH, zero mutations performed at this stage.
**Critical finding**: `soar-orchestrator.service` (the legacy, pre-Phase-1
`e2e_soc_orchestrator.py` pipeline) had restarted **ARMED**
(`Dry run: False`, unit description literally `"...- PERMANENTLY ARMED"`),
contradicting `PROJECT-STATE.md`'s documented dry-run-only behavior. Stable
(no crash-looping, `NRestarts=0`, clean boot log), but actively polling
TheHive every 10s with real containment capability. Deployed-vs-local
checksums also mismatched: the GPU VM's `agent_orchestrator.py` was the
pre-Phase-1 version (2026-08-20); `l1_policy.py`/`idempotency.py` did not
exist on the VM at all — **no Phase 1-5.5 work has ever been deployed
there**, and none was deployed during this checkpoint either.

Per the user's own recovery-decision rule ("stop and report before creating
the synthetic case" on a competing armed process), work paused here for
explicit direction.

### Step 1 (continued) — neutralizing the legacy service
User-authorized action executed: `sudo systemctl disable --now soar-orchestrator.service`
on the GPU VM. Independently verified:
- `systemctl is-active` → `inactive`; `systemctl is-enabled` → `disabled`.
- No `e2e_soc_orchestrator.py` or `agent_orchestrator.py` process present
  (checked by full venv-interpreter path, not a bare string match).
- Re-checked after a 30s wait: still `inactive`/`disabled`, still no
  process — systemd did not restart it (unit removed from
  `multi-user.target.wants`, not just stopped).

**Boot-to-shutdown log review** (full journal, `15:02:30` → `15:39:27`, plus
`soar_audit.jsonl` entries `>= 15:02`): exactly **one** audit event the
entire window — `pipeline_started`. No alert selection, no Cortex responder
invocation, no containment request, no TheHive case mutation, no email, no
evidence of any pfSense change. **No unexpected live side effect occurred**
— safe to proceed per the stated stop condition.

**Not done, per explicit prohibition**: the unit file was not edited or
deleted; no dry-run change was made to it; no kill switch was created or
modified; no code was deployed to the VM; pfSense was not touched; the
service was not restarted or re-enabled.

### Step 2 — Armed notification preflight (enhanced + run live)
`_armed_mode_preflight_check()` was found to only check `MAILER_RECIPIENTS`
non-empty + L2 user resolution — insufficient for a real go/no-go gate.
**Enhanced** (tested offline first — 6 new mocked tests, `test_notifications.py`
25-30, then the full suite re-run) to also check: TheHive
authentication/connectivity (`api.user.get_current()`), Cortex connectivity
(`api.cortex.list_analyzers()` — entity-free; `Mailer_1_0`'s own resolution
is inherently case-scoped, confirmed instead as part of the actual send),
and idempotency-store writability (a throwaway claim+complete in the exact
`store_dir` the caller intends to use). Added a `force` parameter so the
function can be validated live outside the normal armed alert-processing
entry point without flipping the module's global armed state. Returns a
results dict with `masked_recipients` only — never raw addresses.

**Live result** (real TheHive/Cortex, masked):
```
thehive_auth:              true
cortex_connectivity:       true
recipient_count:           2
masked_recipients:         ["a***@g***.com", "e***@g***.com"]
l2_user_resolved:          true   (soc-l2@thehive.local -> internal user id, masked)
idempotency_store_writable: true   (isolated store)
```
All checks passed — proceeded to Step 3.

### A second bug found live (and fixed) — string-encoded Cortex reports
The first live send attempt **crashed**: `_validate_mailer_report()` assumed
`report` was always an already-parsed dict, but the real TheHive API
returned it as a **JSON-encoded string** (confirmed: `report`, and
potentially its nested `full`/`operations` fields, can each independently
arrive as strings depending on API path). This is exactly the kind of
defect live testing exists to catch — Python's `dict.get()` on a `str`
raised `AttributeError`, uncaught.

**Fixed**: `_validate_mailer_report()` now defensively `json.loads()`s any
of `report`/`report["full"]`/`report["operations"]` that arrive as a string,
falling back to an empty dict/`None` (fails closed, never crashes) if
parsing fails. **Added regression test 31** to `test_notifications.py`
(fully-string-encoded report parses and accepts correctly; an unparseable
string fails closed; `None` fails closed) — full suite re-run (441 passed,
0 failed) before resuming the live checkpoint.

**Consequence of the crash**: it occurred AFTER Cortex had already run the
responder job to a reported terminal `Success` — meaning the real mailer
action had almost certainly already fired once before the crash. The
checkpoint was **resumed, not restarted**: the same synthetic case, alert
id, and notification key were reused, which correctly routed the resumed
call through the **ambiguous-recovery re-poll path** (the record was
`INTENDED`, not `COMPLETED`) — proving that path live, and, more
importantly, guaranteeing no second Cortex action or second email was ever
risked. Action count was independently verified `1` before, during, and
after every subsequent call in this checkpoint.

### Step 3 — Authorized synthetic test (final results)
| Item | Result |
|---|---|
| Synthetic case | **#338**, titled `[SYNTHETIC TEST] Phase 5.5 L2 notification validation`, description explicitly states it is not a real incident, no real IOC |
| Masked recipients | `a***@g***.com`, `e***@g***.com` |
| Required tags present | `synthetic` ✅ `notification-test` ✅ `phase-5-live-validation` ✅ `soc-ai:l2-escalated` ✅ a `soc-ai:reason-*` tag ✅ |
| `mail=` tags | both present (2), verified via independent re-query, displayed masked only |
| Cortex responder terminal status | `Success` (re-confirmed via an independent, read-only re-poll) |
| `_validate_mailer_report()` checks | `status_success: true`, `report_success_true: true`, `report_message_ok: true` (`full.message == "message sent"`), `add_tag_op_ok: true` (an `AddTagToCase` op for `mail sent` was present) — **all four passed** |
| `report["success"]` | `true` |
| `report["full"]["message"]` | `"message sent"` |
| `mail sent` case tag | **present**, confirmed via independent re-query — supporting evidence only, not treated as delivery |
| Notification record result | **`NOTIFICATION_ACCEPTED`** (never `DELIVERY_VERIFIED` — that value does not exist in this codebase) |
| Cortex action count | **before: 1, after resume: 1, after duplicate call: 1** — exactly one responder action ever created, proven by an independent `listAction` count, not an assumption |
| Duplicate-call idempotency | second call logged `already sent for this decision — not resending`; idempotency record `status: completed`; `resolved_via: notification_status_recheck` (the resumed call resolved the ambiguous record; the duplicate call after that was a pure short-circuit) |
| Isolated store (sanitized path) | `soar/LIVE_CHECKPOINT_2026-08-21_notification_store/` — outside the production store and all test-fixture directories; preserved, not deleted |

### Test results (offline suite, before and after the live checkpoint)
```
IDEMPOTENCY TESTS:                 34 passed, 0 failed
PHASE 1 TESTS:                     57 passed, 0 failed
PFSENSE VERIFY TESTS:              23 passed, 0 failed
CONTAINMENT VERIFICATION TESTS:    50 passed, 0 failed
CORTEX METADATA TESTS:             26 passed, 0 failed
TRUEPOSITIVE CLOSURE TESTS:        74 passed, 0 failed
L2 ASSIGNMENT TESTS:               81 passed, 0 failed
NOTIFICATION TESTS:                96 passed, 0 failed
GRAND TOTAL: 441 passed, 0 failed
```
`soar/idempotency_store/` (production) was never touched by any test or by
this checkpoint — the checkpoint used only the dedicated isolated directory
above.

### Manual mailbox confirmation (external evidence — 2026-08-21)
```
MANUAL_EXTERNAL_EVIDENCE: one notification received by each of the two configured L2 recipients.
```
Confirmed by the user directly (one mailbox) and by their binôme (the second
mailbox): exactly one email in each, no duplicate observed or reported. The
inspected copy's visible content matched the synthetic case exactly: **Case
#338**, the synthetic-test title, **LOW** severity, **Open** stage,
**CLEAR/CLEAR** TLP/PAP, the synthetic description, the L2 escalation and
reason tags, and the TheHive case link — with no exposed API key, password,
IOC, or sensitive payload visible in the email.

This confirmation is recorded strictly as **external, manual evidence**. It
does **not** create, and this project will never create, a `DELIVERY_VERIFIED`
application state or reason code — `l1_policy.Reason` has no such member,
and no code path sets one. The automated, code-level result for this
notification remains, and will always remain, exactly
**`NOTIFICATION_ACCEPTED`**. The full precise statement:

> Cortex accepted and completed the notification action.
> Effective receipt and content were confirmed manually in the destination
> mailbox (external evidence, both recipients, 2026-08-21).

### Assignee note — `badr@thehive.local` visible in the email
The received email's "assignee" field shows `badr@thehive.local`, not the
configured `soc-l2@thehive.local` L2 account. This is expected and
consistent with what was actually run: this checkpoint invoked
`send_l2_escalation_notification()` **directly**, in isolation, specifically
to validate the Phase 5.5 notification path — it deliberately did **not**
call `assign_l2_verified()` (Phase 4). Case #338 was created with whatever
default/existing assignee TheHive's case-creation flow applies (here,
apparently the account that created it), and nothing in this checkpoint
touched that field. **Phase 4's verified L2 assignment was NOT exercised in
this checkpoint** and still needs its own live validation — carried forward
as an explicit open item for the full L2 integration rehearsal, not treated
as a Phase 5.5 defect (Phase 5.5's own scope was notifications only, and its
34 assignment-focused tests from Phase 4's own test suite already cover the
assignment logic in isolation offline).

### Final Phase 5.5 state
- **Case #338 remains open** — not closed, not modified further by this
  checkpoint after the notification calls.
- **`soar-orchestrator.service` remains inactive and disabled** — verified
  stable at the time of this update; not restarted, not re-enabled, not
  edited.
- **`soar/LIVE_CHECKPOINT_2026-08-21_notification_store/`** — preserved on
  disk, untouched since the checkpoint, outside the production store and
  every test-fixture directory.
- No code was deployed to the GPU VM.
- No real alert was processed; the full agent/legacy loop was not started;
  Ollama/the LLM was never invoked; no containment was executed; pfSense was
  not touched; no real case was closed; no L1 notification was sent; Phase 7
  was not started.

**Phase 5.5 is COMPLETE**: the native Mailer contract is corrected and
tested (441 offline tests, 0 failed), the live preflight passed against real
TheHive/Cortex, one real, controlled `L2_ESCALATED` notification was sent
and independently verified end to end (exactly one Cortex action, idempotent
on replay, exactly the confirmed-live acceptance criteria), and mailbox
receipt was confirmed by the user as external evidence for both configured
recipients. One real bug (string-encoded Cortex reports) was found by this
live test and could not have been caught by mocks alone — fixed, regression-
tested, and the fix is now part of the same code path every future
notification uses.

## 15. Phase 5.6 — full L2 integration live checkpoint — EXECUTED 2026-08-21

Validates the complete production L2 path — escalation decision → verified
L2 assignment → case comment/tags → L2 email notification → independent
verification → idempotent replay — in one live synthetic execution, through
the existing production integration function `_run_l2_escalation()`, not a
manually-reproduced sequence.

### Preconditions (all confirmed live, read-only, before any mutation)
```
soar-orchestrator.service:  inactive, disabled (re-confirmed, no processes running)
thehive_auth:                true
cortex_connectivity:         true
recipient_count:             2
masked_recipients:           ["a***@g***.com", "e***@g***.com"]
l2_user_resolved:            true  (soc-l2@thehive.local -> exactly one active user)
idempotency_store_writable:  true  (NEW isolated directory)
```

### Synthetic case
**Case #339**, `[SYNTHETIC TEST] Full L2 assignment and notification
integration`, LOW severity, CLEAR/CLEAR TLP/PAP, tags `synthetic` /
`l2-integration-test` / `phase-5-6-live-validation`, description explicitly
states it is not a real incident. TheHive auto-assigned the case creator on
creation — independently detected and cleared on this synthetic case only,
then independently re-verified as unassigned before the production call.

### Two real bugs found live (both fixed, both regression-tested)

**Bug 1 — assignee round-trips as LOGIN, not `_id`.** The first
`_run_l2_escalation()` call PATCHed the case correctly (`{"assignee": <user
_id>}`) but the independent post-PATCH re-query returned the user's LOGIN
string, not the `_id` — every comparison in `assign_l2_verified()` and
`l1_policy.evaluate_l2_assignment_eligibility()` was checking against
`user_id`, producing a **false verification-mismatch** on a genuinely
correct assignment (`L2_ASSIGNMENT_VERIFY_FAILED`, `critical_failure:
true`). Root cause: TheHive5's `assignee` field is written with either
representation but always **read back as `login`** — confirmed by direct
live observation, not documentation. **Fixed**: every live-assignee
*comparison* now uses `l2_user["login"]` (the PATCH itself still sends
`user_id`, confirmed to correctly resolve the account); `l1_policy.py`'s two
live-assignee short-circuits and `agent_orchestrator.py`'s post-PATCH
verification, ambiguous-recovery closure, and every `assigned_analyst`
report value were all corrected. 3 existing `test_l2_assignment.py`
fixtures (which had encoded the same wrong assumption) corrected to match
confirmed live behavior. Full suite re-run (441 passed) before resuming.

**Bug 2 — duplicate escalation comment on the "existing_analyst" adoption
path.** Independently re-querying case #339's comments after resuming found
**3** escalation comments where at most 2 were expected (one from the
assignment evidence trail, one from the notification's own audit-record
comment). Root cause: the "human-owned, adopt it" branch guarded
comment-posting on `needs_resolve` (record not yet `COMPLETED`) — but "not
yet completed" is not the same fact as "no comment posted yet." A fresh
attempt that posts its comment and then fails only its OWN verification
(exactly Bug 1's failure mode) leaves the record `INTENDED`; a later call
reaching the adoption branch then incorrectly re-posted. **Fixed**: comment-
posting success is now tracked explicitly via `idempotency.update_meta(assign_key,
{"comment_posted": True}, ...)`, set once, immediately after a successful
post in BOTH the fresh-claim path and the adoption path; the adoption
path's guard now checks this flag, not record status. 2 new regression
tests added (`test_l2_assignment.py` 25-26: adoption does NOT re-post when
already recorded; adoption DOES post when genuinely missing). Full suite
re-run (447 passed) before finalizing.

### Live results (after both fixes, resumed safely — no second PATCH, no second Cortex action risked at any point)
| Item | Result |
|---|---|
| Initial assignee | auto-set by TheHive on creation, detected and cleared, re-verified empty |
| Final live assignee | `soc-l2@thehive.local` — confirmed via independent re-query, hash-matched against the freshly-resolved L2 user's login (masked) |
| Case stage / status | `New` / `New` — **still open** throughout |
| Assignment comment | present (independently confirmed via a direct case-comments query — 1 assignment-evidence comment + 1 notification audit-record comment, not 3, after the fix) |
| Required tags | `synthetic` ✅ `l2-integration-test` ✅ `phase-5-6-live-validation` ✅ `soc-ai:l2-escalated` ✅ a `soc-ai:reason-*` tag ✅ |
| `mail=` tags | both present (2), masked in all output |
| Assignment idempotency record | `status: completed` (adopted from the corrected, re-evaluated state) |
| Cortex action count | **1** before the resumed call, **1** after, **1** after the replay call — exactly one responder action ever created, independently counted via `listAction`, never assumed |
| `_validate_mailer_report()` checks | all 4 passed: `status_success`, `report_success_true`, `report_message_ok`, `add_tag_op_ok` |
| `mail sent` case tag | present |
| Notification record | `status: completed`, result `NOTIFICATION_ACCEPTED` |
| Replay call | assignment: `already satisfied (this_workflow)`, no PATCH; notification: `already sent for this decision`, no new Cortex action; case remained assigned to the same L2 login and remained open |
| Containment / pfSense | not touched — `containment={"attempted": False}` throughout, `execute_and_verify_containment()` never called in this checkpoint |
| L1 closure / L1 notification | never invoked — only `_run_l2_escalation()` (the L2-only integration function) was called |
| Isolated store (sanitized path) | `soar/LIVE_CHECKPOINT_2026-08-21_phase5_6_l2_integration_store/` — outside production and all test-fixture directories, preserved |

### Test results
```
IDEMPOTENCY TESTS:                 34 passed, 0 failed
PHASE 1 TESTS:                     57 passed, 0 failed
PFSENSE VERIFY TESTS:              23 passed, 0 failed
CONTAINMENT VERIFICATION TESTS:    50 passed, 0 failed
CORTEX METADATA TESTS:             26 passed, 0 failed
TRUEPOSITIVE CLOSURE TESTS:        74 passed, 0 failed
L2 ASSIGNMENT TESTS:               87 passed, 0 failed
NOTIFICATION TESTS:                96 passed, 0 failed
GRAND TOTAL: 447 passed, 0 failed
```
`soar/idempotency_store/` (production) was never touched.

### Manual mailbox and TheHive-GUI confirmation (external evidence — 2026-08-21)
```
MANUAL_EXTERNAL_EVIDENCE: exactly one notification received by each configured
L2 recipient; visible email assignee confirmed as soc-l2@thehive.local;
TheHive GUI independently confirmed the live L2 assignment and open case state.
```
Confirmed by the user directly:
- **Mailbox**: exactly one notification email in each of the two configured
  L2 mailboxes, no duplicate observed or reported. The visible email shows
  assignee `soc-l2@thehive.local`, Case #339 as **LOW** severity and
  **Open**, the correct synthetic subject/description/tags, the TheHive case
  link, and no secret, API key, password, or real IOC anywhere in the body.
- **TheHive GUI, independently**: Case #339 shows assignee **`SOC Analyst
  L2`** (the display name behind the `soc-l2@thehive.local` account), the
  case remains `New`/open, all required tags (`synthetic`,
  `l2-integration-test`, `phase-5-6-live-validation`, `soc-ai:l2-escalated`,
  the reason-code tag, both `mail=` recipient tags, and `mail sent`) are
  present, and the case — originally created by Badr's account — is now
  correctly owned/assigned to the L2 account.

This confirmation is recorded strictly as **external, manual evidence**.
Per every prior phase in this project, it does **not** create, and this
project will never create, a `DELIVERY_VERIFIED` application state or
reason code — `l1_policy.Reason` has no such member, no code path sets one,
and none was added in this turn. The automated, code-level result for this
notification remains exactly **`NOTIFICATION_ACCEPTED`**.

### Phase 5.6 final status: COMPLETE
The full production L2 integration path — decision → verified assignment →
comment/tags → notification → independent verification → idempotent replay
— was validated end to end through `_run_l2_escalation()`, the real
production function, with zero manual reproduction of its internal
sequence. Two real defects were found by this live exercise (neither
catchable by mocks alone — both depended on the actual live TheHive API's
field-representation behavior), both fixed, both regression-tested, full
suite green at 447/447. Case #339 remains open, assigned to
`soc-l2@thehive.local`/`SOC Analyst L2`, exactly as intended for an ongoing
synthetic validation record. Both live-checkpoint isolated stores
(`LIVE_CHECKPOINT_2026-08-21_notification_store/` from Phase 5.5 and
`LIVE_CHECKPOINT_2026-08-21_phase5_6_l2_integration_store/` from this
checkpoint) are preserved on disk, untouched, outside production and every
test-fixture directory.

### Prohibited actions — confirmed not taken
No code was deployed to the GPU VM; `soar-orchestrator.service` remains
inactive and disabled, was not restarted or enabled; no real alert was
processed; the full agent loop was not run; Ollama/an LLM was never
invoked; no unrelated analyzer ran; no containment was executed; pfSense
was not touched; case #339 was not closed and remains open; no L1
notification was sent; Mailer configuration was not modified; Phase 7 was
not started (implementation-wise) in this checkpoint.

Phase 5.6 is accepted complete. Proceeding to Phase 7 pre-implementation
planning only, per instruction — no Phase 7 code in this turn.

## 16. Phase 7A — leakage-safe offline replay harness FOUNDATION — IMPLEMENTED 2026-08-21

Schemas, offline harness foundation, leakage controls, tests, and the
review workflow. No live 310-case export was performed. Neither Dataset A
nor Dataset B was locked. This section documents the foundation only.

### Files created
| File | Purpose |
|---|---|
| `soar/sanitization.py` | Side-effect-free redaction primitives, extracted verbatim from `agent_orchestrator.py` (Phase 5.5) — zero behavior change, proven by the full existing suite passing unchanged post-refactor. `agent_orchestrator.py` now imports these under their original names; every call site is unchanged. |
| `soar/dataset_schema.py` | `SCHEMA_VERSION = "phase7-v1"`; strict hand-rolled validator (`validate_case()`/`assert_valid_case()`) — rejects unknown fields, enforces every mandatory-correction rule (disputed→L2-or-null, approved requires reviewer+timestamp+expected_tier, event_time-null forces pending, label_source closed allowlist that structurally excludes policy-derived values, reason codes cross-checked against the REAL `l1_policy.REASON_CODES`); `canonical_json()`/`case_content_hash()`/manifest validation. |
| `soar/rag_snapshot.py` | Offline RAG snapshot builder + `query_similar()` enforcing all 4 leakage controls (exact case-ID, canonical content-hash, incident-group, temporal cutoff); manifest build/verify with SHA-256 tamper-evidence; `find_duplicate_content()`; the Dataset B exporter FOUNDATION (`export_case_from_thehive_record()`) — pure transform, no query, tested exclusively with fixtures. |
| `soar/replay_harness.py` | `network_guard()` (blocks every socket connection including localhost); `run_policy_replay()` (deterministic, frozen-fixture, reuses the REAL `l1_policy.evaluate_l1_malicious_eligibility()`/`e2e_soc_orchestrator.policy_guard()`/`agent_orchestrator.l1_disposition()` — all pure by construction, not reimplemented); the hard `false_auto_containment_count > 0` → fail gate; `wilson_upper_bound()`; programmatic reason-code classification + coverage manifest; `run_agent_benchmark()` as an explicitly-gated, unimplemented stub. |
| `soar/migrate_golden_seven.py` | One-shot migration of the 7 golden cases to Phase 7 draft records — every migrated case `review_status: "pending"`. |
| `soar/test_sanitization.py` | 30 tests. |
| `soar/test_replay_harness.py` | 66 tests. |
| `soar/.gitignore` | Protects live-checkpoint stores, the production idempotency store, the audit log, and (pre-emptively) any future raw Dataset B export from ever being committed. |
| `ai/testset/dataset_a_draft/*.json` (7 files) | The migrated golden seven, schema-valid, all pending. |
| `ai/testset/dataset_a_draft/REVIEW_WORKSHEET.md` | Labeling/adjudication workflow documentation. |
| `ai/results/phase7a-reason-code-coverage.{json,md}` | Coverage snapshot (0/21 `policy_decision` codes — honest starting point, not a target reached this phase). |

### Files modified
| File | Change |
|---|---|
| `soar/agent_orchestrator.py` | Redaction/masking function DEFINITIONS replaced with imports from `sanitization.py` (same names, zero call-site changes); removed a leftover duplicate `_EMAIL_RE`/`_validate_email_address`/`_mask_email` block that had been silently shadowing part of an earlier extraction attempt; unused `hashlib`/`html`/`re` imports removed. `agent_bench.py` — **confirmed untouched** (md5 verified, no edit made). |

### Final schemas
**Case record** (`dataset_schema.REQUIRED_FIELDS`, 22 fields): `schema_version`,
`case_uid`, `incident_group_id`, `event_time`, `source`, `alert`,
`observables`, `fixtures`, `rag_snapshot_ref`, `dataset_version`,
`policy_version_frozen_against`, `label_source`, `label_confidence`,
`review_status`, `reviewed_by`, `reviewed_at`, `label_notes`,
`expected_tier`, `expected_primary_reason`, `required_reason_codes`,
`forbidden_reason_codes`, `must_not_auto_contain`, `must_remain_open` — plus
3 legacy-only allowed extras (`id`, `note`, `ground_truth`) for golden-seven
backward compatibility. Unknown fields are rejected, not ignored.

**Manifest**: `manifest_version`, `dataset_name`, `dataset_version`,
`schema_version`, `built_at`, `case_count`, `cases` (per-`case_uid`
`content_hash` + `incident_group_id`), `policy_version_frozen_against`,
`manifest_hash` (SHA-256 tamper-evidence over the canonical serialization of
everything else).

### Network-isolation proof
`network_guard()` patches `socket.socket.connect` AND `socket.create_connection`
(the two entry points `requests`/urllib3 ultimately use) for its duration —
deliberately not localhost-exempted. Test 21 proves a real `connect(("127.0.0.1",
1))` attempt raises `NetworkAccessError` from INSIDE the guard before the OS
even gets a chance to refuse it; test 22 proves normal offline computation is
unaffected; test 23 proves the original `socket.socket.connect` is restored
after `__exit__`. `run_policy_replay()` runs every case through this guard by
default.

### Leakage-control tests
All 4 controls independently proven (tests 14-17), each with a "without the
control, the leak DOES happen" companion assertion where feasible (test 15)
so the tests prove the control does something, not just that a query
returns *something*:
- Exact case-ID exclusion — a case never retrieves itself.
- Incident-group exclusion — a related/duplicate case in the same group is
  excluded even under a different id (and shown to leak WITHOUT the
  control, proving it's real).
- Canonical content-hash exclusion — a byte-identical clone under a
  different id/group is still excluded.
- Temporal cutoff — a case can only retrieve neighbors strictly BEFORE its
  own `event_time`; a later related case is proven unreachable.

### Sanitization and secret-scan results
`test_sanitization.py`: 30/30 passed, including a zero-side-effect import
proof (no `requests`/`thehive4py`/`socket` pulled in) and full behavior
parity with the pre-refactor implementation. The golden-seven migration ran
`sanitization.contains_unredacted_secret()` as the LAST step before writing
any file — all 7 passed the scan (expected: these are synthetic/documented
cases with no real secrets, but every case goes through the identical gate
regardless of source).

### Golden-seven migration status
All 7 migrated to `ai/testset/dataset_a_draft/*.json`, schema-valid,
`review_status: "pending"` — **none approved, none locked**. Legacy
`ground_truth` preserved verbatim. 5/7 (`02`, `04`, `05`, `06`, `07`) got a
safely-derived `expected_tier: "L2"` directly from their pre-existing
`must_not_auto_block: true` label (never from policy internals); 2/7 (`01`,
`03`, both `must_not_auto_block: false`) got `expected_tier: null` — not
independently establishable from the old schema's fields alone. **All 7
have `event_time: null`** (never recorded in the original source) and
**empty `fixtures`** (no frozen verdict/trace/tool-call recording exists
yet) — neither was invented; both are explicit, human-reviewable gaps in
each case's `label_notes`.

### Labels requiring human review
Per `ai/testset/dataset_a_draft/REVIEW_WORKSHEET.md`: all 7 cases, in full —
`event_time` for all 7; `expected_tier` confirmation for the 5 with a draft
`L2` value, and independent determination (not derivable from existing
fields) for the 2 with `null`; `fixtures` capture for all 7 (blocks replay-
readiness, not schema validity); `required_reason_codes`/
`expected_primary_reason` for all 7 (currently unset, driving the 0/21
`policy_decision` coverage figure below).

### Reason-code coverage classification
54 codes enumerated PROGRAMMATICALLY (never a hardcoded "~36") via
`l1_policy.REASON_CODES`, classified into policy_decision (21) /
operational_recovery (8) / assignment_notification (12) /
internal_not_reachable (13) — completeness enforced by a dedicated test
(a newly-added Reason code with no classification entry fails
`classify_reason_codes()` loudly). Dataset coverage is required ONLY for the
21 `policy_decision` codes; the other 33 are covered through the existing
447-test unit/integration suite instead. Current draft coverage: **0/21**
(honest — none of the 7 pending cases has reason-code expectations set
yet). Full snapshot: `ai/results/phase7a-reason-code-coverage.md`.

### `agent_bench.py` backward compatibility
Untouched — md5 checksum confirmed unmodified before and after this phase's
work. Not deleted, not wrapped, not superseded. Its own decision (wrap vs.
leave standalone) is explicitly deferred to you, per instruction, not made
unilaterally here.

### Test results
```
IDEMPOTENCY TESTS:                 34 passed, 0 failed
PHASE 1 TESTS:                     57 passed, 0 failed
PFSENSE VERIFY TESTS:              23 passed, 0 failed
CONTAINMENT VERIFICATION TESTS:    50 passed, 0 failed
CORTEX METADATA TESTS:             26 passed, 0 failed
TRUEPOSITIVE CLOSURE TESTS:        74 passed, 0 failed
L2 ASSIGNMENT TESTS:               87 passed, 0 failed
NOTIFICATION TESTS:                96 passed, 0 failed
SANITIZATION TESTS:                30 passed, 0 failed
REPLAY HARNESS TESTS:              66 passed, 0 failed
GRAND TOTAL: 543 passed, 0 failed
```
`soar/idempotency_store/` (production) was never touched.

### Exact proposal for the controlled Dataset B export (Phase 7B — NOT executed)
1. Live, READ-ONLY export of the 310 closed TheHive cases via
   `rag_snapshot.export_case_from_thehive_record()` (already built,
   fixture-tested) driven by a NEW thin script that fetches real case+
   observable data through an injected `thehive_query_fn` and assigns real
   pseudonymous `case_uid`/`incident_group_id` values (grouping logic for
   near-duplicate/related incidents — not yet designed — is the one piece
   of real Phase 7B design work, separate from the already-built exporter).
2. Output goes to a `raw_export/` directory excluded by `.gitignore` —
   never committed, never sanitized-in-place (sanitization happens as the
   export function runs, producing the COMMITTABLE draft directly; the raw
   TheHive response is discarded, not retained as a second copy).
3. Every exported record starts `review_status: "pending"`,
   `label_source: "human_historical_disposition"` — structurally
   impossible to skip review, per the mandatory correction.
4. `rag_snapshot.find_duplicate_content()` run over the full 310 immediately
   after export, BEFORE any review begins, so incident-group assignment can
   account for real duplicates found, not just assumed ones.
5. Requires your explicit go-ahead to (a) run the live export at all, and
   separately (b) begin human review — these should not be bundled into one
   approval, since (a) touches live TheHive (read-only) and (b) is pure
   human labor with no infrastructure risk.

### Exact human-review work required before dataset locking
- **Dataset A**: all 7 migrated cases reviewed per the worksheet above,
  PLUS additional hand-authored cases to close the 21-code
  `policy_decision` coverage gap (0/21 currently) — realistically more new
  cases than migrated ones, given 7 cases cannot plausibly cover 21
  distinct policy-decision reason codes with any redundancy margin.
- **Dataset B**: after the Phase 7B export (not yet run), every one of the
  310 candidate records reviewed against the adjudication rules in the
  worksheet — a HISTORICAL closed disposition is a candidate, not
  automatic ground truth, so this is genuinely 310 individual review
  decisions, not a bulk rubber-stamp; realistically the dominant cost of
  the whole Phase 7 effort, consistent with the original plan's own
  estimate ("human-paced dataset curation time... likely the actual
  bottleneck, not the code").
- Neither dataset locks until `rag_snapshot.write_manifest()` is run over
  the FINAL reviewed case set and the resulting manifest is itself
  reviewed/approved.

### Prohibited actions — confirmed not taken
No live TheHive/Cortex/pfSense/Ollama call was made (network-guard-proven
for the harness's own replay path; every other module's tests use fixtures
exclusively); nothing was deployed; the legacy service was not restarted
(still inactive/disabled — re-confirm before Phase 7B if time has passed);
no real alert was processed; no live case was modified; no responder was
invoked; no containment was executed; neither dataset was locked; Phase 8
was not started.

Stopping here, per instruction. Awaiting your review of this Phase 7A
foundation before any Phase 7B live export work begins.

## 17. Phase 7B — controlled, read-only Dataset B candidate export — EXECUTED 2026-08-21

One live, read-only export against real TheHive. No case was created,
updated, assigned, commented on, reopened, or closed. No Cortex responder or
analyzer was invoked. Neither dataset was locked.

### Files created
| File | Purpose |
|---|---|
| `soar/export_dataset_b_candidates.py` | The export script — read-only TheHive queries only (`api.case.find()`/`api.case.find_observables()`, no write method referenced anywhere, confirmed by grep), reuses `rag_snapshot.export_case_from_thehive_record()` (Phase 7A) as the per-case transform. |
| `sanitization.stable_pseudonym()` / `pseudonymize_identities_in_text()` | New primitives — stable, salted, non-reversible-looking pseudonyms for identity values; email-in-free-text detection+replacement. 8 new tests. |
| `dataset_schema.py`: `closure_time` | New OPTIONAL extra field (nullable ISO8601, validated when present, `closure_time >= event_time` cross-check) — added without a schema-version bump so the 7 already-migrated golden-seven records remain valid unchanged. |
| `.gitignore` (project root, NEW) | **Fixes a real Phase 7A gap**: `soar/.gitignore` cannot cover `ai/testset/` (a sibling directory, not a subtree of `soar/`) — a root-level file was required. `ai/testset/dataset_b_candidates/` is now explicitly gitignored. |
| `ai/testset/dataset_b_candidates/*.json` (226 files) + `MANIFEST.json` | The sanitized candidates + their checksummed manifest. |
| `ai/testset/dataset_b_candidates/REVIEW_SUBSET_WORKSHEET.md` | The 60-case deterministic review subset worksheet. |
| `ai/results/phase7b-export-report.json` | The full sanitized export report (counts/distributions only — no case content). |

### Preflight (sanitized)
```
thehive_auth:            true
read_only_methods_only:  true   (structural — no write method exists in the script)
output_dir_gitignored:   true   (after the root .gitignore fix)
raw_api_response_logged: false
legacy service:           inactive, disabled (re-confirmed via SSH immediately before export)
```

### Export results
```
cases_queried:              334   (NOT assumed to be 310 — the real count)
eligible_candidate_count:   226
excluded — still_open:                85
excluded — explicitly_synthetic_or_test_case: 15   (includes this project's own
                                    Phase 5.5/5.6 live-checkpoint cases #338/#339,
                                    correctly excluded by title/tag match)
excluded — handling_restriction_incompatible:  8   (TLP > 2)
sanitization failures:       0
schema validation failures:  0
duplicate content groups:    0   (independently re-verified via a second, fresh pass)
temporal ordering violations: 0
incident groups:            82   (70 singleton, largest group 60 — one large
                                    repeated-pattern cluster, e.g. a scan/brute-
                                    force campaign against the same target)
historical disposition:     TruePositive 145 / FalsePositive 72 / Other 9
severity:                   sev1: 1, sev2: 176, sev3: 49
```
Every one of the 226 candidates is `label_source: "human_historical_disposition"`,
`review_status: "pending"` — **none approved, none locked, no tier or reason
code auto-assigned**.

### Sanitization / secret-scan / schema verification (independent, post-export)
- `contains_unredacted_secret()` re-run across all 226 candidates + the
  manifest + the export report: **0 flagged**.
- `validate_case()` re-run across all 226 candidates (fresh process, not
  reusing the export run's own in-memory state): **0 failures**.
- `rag_snapshot.verify_manifest()` re-run against the written files: **0
  discrepancies** (content hashes match, no missing/extra case_uids,
  `manifest_hash` matches a fresh recomputation).
- Grep-confirmed: zero references to any TheHive write method
  (`.create`/`.update`/`.delete`/`.comment.*`/`.cortex.*`) anywhere in
  `export_dataset_b_candidates.py` or `rag_snapshot.py`.

### Deterministic review subset
60 of 226 candidates, frozen seed `20260821`, stratified by (historical
disposition, `must_not_auto_contain` draft, severity, a rule-family bucket
derived from the sanitized alert title) — every non-empty stratum
guaranteed at least one representative before proportional random fill.
Selection ran BEFORE any policy replay (none was run against these
candidates in this phase at all — `run_policy_replay()` was never invoked
here) — not cherry-picked by outcome. Full stratum breakdown in the export
report; every selected case remains `pending`.

### Test results
```
IDEMPOTENCY TESTS:                 34 passed, 0 failed
PHASE 1 TESTS:                     57 passed, 0 failed
PFSENSE VERIFY TESTS:              23 passed, 0 failed
CONTAINMENT VERIFICATION TESTS:    50 passed, 0 failed
CORTEX METADATA TESTS:             26 passed, 0 failed
TRUEPOSITIVE CLOSURE TESTS:        74 passed, 0 failed
L2 ASSIGNMENT TESTS:               87 passed, 0 failed
NOTIFICATION TESTS:                96 passed, 0 failed
SANITIZATION TESTS:                38 passed, 0 failed
REPLAY HARNESS TESTS:              66 passed, 0 failed
GRAND TOTAL: 551 passed, 0 failed
```
`soar/idempotency_store/` (production) was never touched.

### Design decisions worth surfacing
- **The `still_open` exclusion (85 cases) is the single largest exclusion
  category** — expected: this instance has been under active, continuous
  operation, so a meaningful fraction of cases are legitimately still in
  progress. None were queried further (no observable fetch was even
  attempted for excluded cases, minimizing unnecessary API calls).
- **Incident-group heuristic (Phase 7A's flagged "not yet designed" piece)**
  is now a concrete first pass: union-find over shared observable IPs. The
  one 60-case group is worth a specific look during Dataset B review — a
  cluster that large will dominate `query_similar()`'s exclusion behavior
  for every case inside it.
- **`closure_time` added without a schema-version bump** — a deliberate,
  minimal, backward-compatible extension (see files-created table);
  flagged in case a future reviewer wonders why it's an "extra" field
  rather than a core required one.
- **The root `.gitignore` gap was a real Phase 7A oversight**, not
  Phase 7B's — found and fixed before it mattered (nothing was ever
  committed in the gap window; this project is not yet a git repository at
  all, so the practical exposure was zero, but the fix is real and now
  correct for whenever it becomes one).

### Prohibited actions — confirmed not taken
No case was created, updated, assigned, commented on, reopened, or closed;
no Cortex responder or analyzer was invoked; pfSense was not touched; no
code was deployed; the legacy service was not restarted; no raw TheHive
record was ever written to disk (the export script sanitizes in memory,
per-case, before the first write — there is no raw intermediate file at any
point in the pipeline); no historical label was auto-approved; neither
dataset was locked; Phase 8 was not started.

Stopping here, per instruction. Awaiting your review before any human label
approval, Dataset A expansion, dataset locking, or Phase 8 work begins.

## 18. Phase 7C — offline human-review preparation — EXECUTED 2026-08-21

No TheHive/Cortex/pfSense/Ollama query of any kind. No label was approved by
the agent. Neither dataset was locked. No live infrastructure touched, no
code deployed. The 226 Dataset B candidate files and their `MANIFEST.json`
were re-verified byte-identical against the Phase 7B manifest hash both
before and after every step below.

### Files created / modified
| File | Purpose |
|---|---|
| `soar/dataset_schema.py` (modified) | Added `extract_historical_disposition_hint()` — a documented, non-authoritative regex recovery of the historical disposition from `label_notes` prose (see "Findings" below: the structured field was never persisted in Phase 7B). No schema-version bump; existing records unaffected. |
| `soar/export_dataset_b_candidates.py` (modified) | Added `select_review_subset_v2()` alongside the untouched Phase 7B `select_review_subset()` (v1) — adds a per-`incident_group_id` cap (default 3, documented exception up to 5), sorts candidates by `case_uid` before shuffling (fixes an order-dependence gap found while reconstructing v1, see Findings). |
| `soar/regenerate_review_sample_v2.py` (new) | One-shot script: verifies the candidate set, preserves the original v1 sample (parsed from the existing worksheet, not recomputed — see Findings), generates v2, writes a comparison report. Never overwrites the original `REVIEW_SUBSET_WORKSHEET.md`. |
| `soar/review_rubric.py` (new) | Policy-independent evidentiary checklist (`evaluate_positive_gate_checklist()`) + hard validation gate (`validate_decision()`). Deliberately never reproduces `l1_policy.py`'s actual gate logic — circular-ground-truth is the failure mode this is built to avoid. |
| `soar/assign_reviewers.py` (new) | Deterministic 30/30 primary split (seed `20260821`) + dual-review queueing. Writes `soar/review_overlays/ASSIGNMENTS.json`. Neutral reviewer identifiers only (`reviewer-a`/`reviewer-b`). |
| `soar/review_dataset.py` (new) | The offline review CLI — pure/testable core (`load_and_verify_candidates`, `record_decision`, `atomic_append_jsonl`, `read_overlay`, `compute_conflicts`, `write_adjudication_queue`, `compute_progress`, `format_case_for_display`) + a thin interactive layer, entire `main()` wrapped in `replay_harness.network_guard()`. |
| `soar/test_review_dataset.py` (new) | 32 tests covering all 12 required properties (below). |
| `ai/testset/dataset_b_candidates/REVIEW_RUBRIC.md` (new) | Human-readable rubric documentation, mirrors `review_rubric.py`'s enforcement exactly. |
| `ai/testset/dataset_b_candidates/REVIEW_SUBSET_WORKSHEET_v1.md` (new) | The original Phase 7B worksheet, preserved verbatim under a version-1 name. `REVIEW_SUBSET_WORKSHEET.md` itself was never touched again. |
| `ai/testset/dataset_b_candidates/REVIEW_SUBSET_WORKSHEET_v2.md` (new) | The corrected 60-case sample. |
| `ai/testset/dataset_b_candidates/REVIEW_SAMPLE_v1_MANIFEST.json` / `REVIEW_SAMPLE_v2_MANIFEST.json` (new) | Per-sample case_uid lists + content-hash manifests, independently verifiable against the candidate files. |
| `ai/results/phase7c-sample-v1-vs-v2.json` (new) | The full v1-vs-v2 comparison report. |
| `soar/review_overlays/ASSIGNMENTS.json` (new) | Reviewer queues — created empty of any decisions; decisions accumulate only in per-reviewer `.jsonl` overlay files that don't exist yet (nobody has reviewed anything). |

### 1–2. Sample correction: v1 vs v2
```
v1 (Phase 7B, frozen, preserved):
  sample size:               60
  largest incident group:    9 cases  (15.0% of the sample)

v2 (Phase 7C, corrected):
  sample size:               60
  largest incident group:    5 cases  (8.3% of the sample) — via 3 documented exceptions
  exceptions:                 3  (grp-4a17528ae8fe x2, grp-21b88566bb61 x1)
  historical disposition:    TruePositive 46 / FalsePositive 6 / Other 8
  severity:                  sev1: 1, sev2: 41, sev3: 18
  cases added vs v1:          34   removed vs v1: 34   unchanged: 26
  sample_manifest_hash:       b93dc59d27dbd9d5f823a8bcfe7538e112990fca8e0e9ae7482f3445af30d96b
  seed (frozen, same family as Phase 7B): 20260821
```
Selection ran with **zero policy replay** — `run_policy_replay()` was not
invoked anywhere in this phase, and `select_review_subset_v2()` takes no
policy-outcome input at all, only static case fields (disposition hint,
`must_not_auto_contain`, severity, rule-family bucket, `incident_group_id`).

### 3. The offline review tool
```
soar/review_dataset.py --reviewer reviewer-a   # start/resume a review session
soar/review_dataset.py --reviewer reviewer-b
soar/review_dataset.py --progress              # per-reviewer completion counts
soar/review_dataset.py --conflicts              # compute + write the adjudication queue
```
Runs entirely inside `replay_harness.network_guard()` (patches
`socket.socket.connect` and `socket.create_connection` — blocks every
transport a network-capable library could use, localhost included, for the
tool's full runtime). Verifies the candidate manifest and the sample
manifest independently before showing a single case. Decisions autosave via
a POSIX-atomic single-`write()` append (`os.O_APPEND|os.O_CREAT`, one JSON
line ≤ 4096 bytes) to a per-reviewer `.jsonl` overlay file — the original
candidate JSON is never opened for writing by this tool.

### 4. Rubric
Documented in `ai/testset/dataset_b_candidates/REVIEW_RUBRIC.md`, enforced
in code by `review_rubric.validate_decision()` (a hard gate — the CLI
refuses to save a violating decision, it does not warn-and-allow). Only the
21 `POLICY_DECISION`-classified reason codes are ever offered to a human
reviewer (verified live: `len(review_rubric.EXTERNALLY_EVALUABLE_REASON_CODES) == 21`)
— the remaining 33 operational/assignment/internal codes stay covered by
the existing 583-test suite, never exposed to human labeling.

**Current practical consequence, stated plainly**: none of the 226 Dataset B
candidates has `fixtures` populated (no investigation trace was captured at
export time), so under rule 6 (cannot approve L1 with required evidence
missing) **no Dataset B case can currently be approved as L1** — every
reviewable case in this sample is, as of today, either L2-expected,
disputed, or excluded, until a later phase captures fixtures. This is real
and current, not hypothetical, and both reviewers should know it going in
so an all-L2 first pass doesn't read as a tool bug.

### 5. Reviewer split
```
primary_counts:   {reviewer-a: 30, reviewer-b: 30}   (deterministic, seed 20260821)
dual_review_count: 60 of 60   (100% — see Finding below)
queue_sizes:       {reviewer-a: 60, reviewer-b: 60}
```
**Finding, reported plainly, not silently altered**: the two dual-review
criteria "every proposed L1-eligible case" (`must_not_auto_contain ==
False`) and "every case marked `must_not_auto_contain`"
(`must_not_auto_contain == True`) are complementary over that one boolean
field — together they cover 100% of any sample, so every one of the 60
cases matches at least one required-dual-review criterion by construction.
`assign_reviewers.needs_dual_review()` implements both criteria literally
as specified; the 100% outcome is a correct, direct consequence of the
instruction as given, not a bug. Flagging for your call: if the intent was
a smaller dual-review subset, the fix is to narrow one of those two
criteria (e.g. restrict "proposed L1-eligible" to cases where the
*historical* disposition was TruePositive, rather than any case not marked
`must_not_auto_contain`) — I have not made that change without your
direction, since it changes what "every proposed L1-eligible case" means.

### 6. Adjudication
`review_dataset.py --conflicts` calls `compute_conflicts()`, which compares
the **latest** decision from each reviewer who has decided a given
dual-reviewed case (only once 2+ reviewers have decided it — a lone
decision is never flagged), and writes disagreements to
`soar/review_overlays/ADJUDICATION_QUEUE.json`. Nothing is auto-resolved;
resolution follows the same "record a new, superseding decision line" rule
as every other overlay write — the disagreement history is never erased.

### 7. Proof candidates remained unchanged
`regenerate_review_sample_v2.py`'s own run re-verified the 226 candidates
against `MANIFEST.json` immediately before AND after every step (identical
`manifest_hash` both times: `1a933d0ca211ba0c48ae2b7dc7a917144dbf4a7cf48ffb7e246fba77a0d23b03`,
0 errors both times). `test_review_dataset.py` test 7 independently repeats
this proof at the byte level: reads every candidate file's raw bytes,
runs a full simulated review pass (`record_decision()` for every case) into
a throwaway overlay directory, then re-reads the same files and asserts
byte-for-byte equality — passes.

### 8. Network-isolation proof
`test_review_dataset.py` tests 1–2: (a) directly proves
`network_guard()`'s primitive-level patch actually refuses both
`socket.socket().connect()` and `socket.create_connection()` while active
(and fully restores the originals afterward — no permanent breakage), (b)
proves the tool's entire pure-function review flow (load, verify, decide,
save) completes successfully *inside* that same guard. Together these prove
the property the instruction asked for: not merely "the tool doesn't happen
to make a network call today" but "a network call is structurally
impossible for the whole duration real review sessions run under."

### 9. Test results
```
IDEMPOTENCY TESTS:                 34 passed, 0 failed
PHASE 1 TESTS:                     57 passed, 0 failed
PFSENSE VERIFY TESTS:              23 passed, 0 failed
CONTAINMENT VERIFICATION TESTS:    50 passed, 0 failed
CORTEX METADATA TESTS:             26 passed, 0 failed
TRUEPOSITIVE CLOSURE TESTS:        74 passed, 0 failed
L2 ASSIGNMENT TESTS:               87 passed, 0 failed
NOTIFICATION TESTS:                96 passed, 0 failed
SANITIZATION TESTS:                38 passed, 0 failed
REPLAY HARNESS TESTS:              66 passed, 0 failed
REVIEW DATASET TESTS (NEW):        32 passed, 0 failed
GRAND TOTAL: 583 passed, 0 failed
```
`soar/idempotency_store/` (production) and every prior phase's fixtures
were never touched by this phase's work.

### 10. Estimated review time
No empirical timing yet (no human review has occurred — none was
performed by the agent, per instruction). Structural estimate: 60 cases,
each requiring reading a sanitized case summary + a policy-independent
6-item checklist + entering 6–7 decision fields. Comparable manual-review
tooling in this project (Dataset A's worksheet-based process) ran roughly
2–4 minutes/case for reviewers already familiar with the format; a first
pass with a new tool is typically slower. Budget **~1–3 hours per reviewer
for their 60-case queue** (primary + dual together, since dual review
means both reviewers see all 60), with the caveat that today's "no
fixtures → no L1 possible" state (§4) may make this first pass faster than
usual, since there's no fixture evidence to weigh — but that data
limitation should be understood as a limitation, not banked as time saved.

### Findings surfaced this phase (not fixed by silently changing scope)
1. **Historical disposition was never persisted as a structured field in
   Phase 7B** — only recoverable via regex against `label_notes` prose.
   Worked around (`extract_historical_disposition_hint()`, explicitly
   documented as non-authoritative, used only for stratification/display),
   not fixed by re-touching the 226 protected candidate files.
2. **The original v1 sample was not reproducible from the frozen seed
   alone** — `random.Random(seed).shuffle()` is order-dependent, and the
   live Phase 7B export's TheHive query order differs from any offline
   re-load order. v1 was therefore preserved by parsing the existing
   worksheet directly (never recomputed); v2's algorithm now sorts by
   `case_uid` first specifically so this can't recur.
3. **Dual-review criteria as specified are complementary and cover 100% of
   the sample** — see §5. Reported, not silently narrowed.
4. **No Dataset B candidate currently has investigation fixtures** — see
   §4. This is a real, current data limitation of the Phase 7B export, not
   a Phase 7C tooling gap; it means every review decision in this sample
   is, today, structurally capped at L2/disputed/excluded.

### Prohibited actions — confirmed not taken
No TheHive/Cortex/pfSense/Ollama query was made. No human label was
approved by the agent (`review_dataset.record_decision()` was exercised
only inside tests and one manual smoke test against throwaway fixture
data in a temp directory, never against a real Dataset B candidate for the
purpose of an actual approval). No policy replay was run against pending
labels. Neither dataset was locked. No live infrastructure was touched. No
code was deployed. Phase 8 was not started.

### Exact instructions for Reviewer A and Reviewer B
**Do not begin yet** — per your instruction, this is presented for your
review of the tool and instructions first, not as a go-ahead.

When you authorize starting:
```
cd soar
./.venv/bin/python review_dataset.py --reviewer reviewer-a    # Reviewer A
./.venv/bin/python review_dataset.py --reviewer reviewer-b    # Reviewer B
```
Each reviewer works through their own queue (60 cases each, primary +
dual — see §5 finding above); the tool shows one case at a time, prompts
for `review_status` / `expected_tier` / `expected_primary_reason` /
`required_reason_codes` / `forbidden_reason_codes` / `label_confidence` /
notes, validates against the rubric before saving, and can be stopped and
resumed at any time (`Ctrl+C` is safe — the last save is always complete).
Check progress anytime with `--progress`; once both reviewers have made
initial passes, run `--conflicts` to generate the adjudication queue for
any disagreement on a dual-reviewed case.

Read `ai/testset/dataset_b_candidates/REVIEW_RUBRIC.md` first — in
particular §4 above (no case can currently be approved L1, given today's
data) and the finding in §5 (both reviewers will see all 60 cases, not a
30/30 split, given how "dual review" was specified).

Stopping here, per instruction. Awaiting your review of the tool and these
instructions before any actual label approval begins.

## 19. Phase 7D — dataset correction and evaluation-case preparation — EXECUTED 2026-08-21

Phase 7C was accepted with three required corrections. No human label was
approved by the agent. Neither dataset was locked. No live infrastructure
mutated, no code deployed, no policy metrics run, Phase 8 not started.

### Files created / modified
| File | Purpose |
|---|---|
| `soar/dataset_schema.py` (modified) | Schema v2 (`SCHEMA_VERSION_V2`), `HISTORICAL_DISPOSITION_VALUES`/`_SOURCES`, v1/v2 field-set separation in `validate_case()`, `get_authoritative_historical_disposition()`, the `specification_derived_pending_human` label source + the denylist-substring fix (`"derived"` -> `"policy_derived"`/`"derived_from_policy"`/`"policy_output"`). |
| `soar/rag_snapshot.py` (modified) | `export_case_from_thehive_record()` and `write_manifest()` both gained an optional `schema_version` parameter (defaults preserve exact v1 behavior for every existing caller). |
| `soar/export_dataset_b_candidates.py` (modified) | `DISPOSITION_VALUES` now sourced from `dataset_schema.HISTORICAL_DISPOSITION_VALUES` (single source of truth); otherwise untouched. |
| `soar/export_dataset_b_candidates_v2.py` (new) | The live, read-only, cutoff-enforced v2 export — **executed by the user** with their own key; reuses v1's `classify_case`/`fetch_all_cases`/`build_incident_groups`/`select_review_subset_v2`/`EXPORT_SALT` unmodified. |
| `soar/assign_reviewers.py` (rewritten) | Narrowed, corrected dual-review policy; prefers the v2 sample automatically, falls back to v1 with a warning. |
| `soar/review_rubric.py` (modified) | `historical_disposition_available` now uses the authoritative-only helper, never the prose extractor. |
| `soar/review_dataset.py` (modified) | `--dataset {a,b}` split, `resolve_dataset()`, `historical_disposition_display()`, `fixture_provenance()`, `effective_queue()` (dynamic dual-review), Dataset-B-aware L1-with-missing-fixtures refusal. |
| `soar/build_dataset_a_synthetic_fixtures.py` (new) | Generates the 25 Dataset A synthetic, specification-derived cases + coverage matrix. |
| `soar/test_phase7d.py` (new) | 49 tests covering all 13 required properties. |
| `ai/testset/dataset_b_candidates/DATASET_B_SCOPE.md` (new) | The Dataset B role clarification. |
| `ai/testset/dataset_a_synthetic/*.json` + `MANIFEST.json` (new, 26 files) | The 25 synthetic cases + manifest. |
| `ai/testset/dataset_b_candidates_v2/*.json` + `MANIFEST.json` + `REVIEW_SAMPLE_MANIFEST.json` (new, 228 files) | The live v2 export output — 226 candidates, schema v2, structured disposition. |
| `ai/results/phase7d-export-report.json`, `phase7d-dataset-a-coverage-matrix.json` (new) | Sanitized export/coverage reports (counts/hashes only, no case content). |
| `soar/review_overlays/ASSIGNMENTS_v2.json` (regenerated) | Now built from the authoritative v2 sample (`sample_source: phase7d_v2_authoritative`). |

### 1. Corrected dual-review scope

The withdrawn Phase 7C policy (100% dual review, §5 above) is replaced.
`assign_reviewers.py` was rewritten: every case gets one primary reviewer;
dual review is now limited to historical-`Other` disposition and a fixed,
seeded 12-case QC sample at ASSIGNMENT time, plus two **dynamic** triggers
(a case a reviewer actually proposes L1 for, or marks disputed) computed
live by `review_dataset.effective_queue()` as decisions accumulate — not
baked into the static file.

**A real second finding surfaced and self-corrected before running**: an
early draft computed "proposed L1-eligible" as a STATIC pre-review proxy
(historical disposition TruePositive AND not `must_not_auto_contain`).
Run against the real 60-case sample, that alone put 46/60 cases in dual
review — in practice nearly as total as the withdrawn policy, even though
the logic was no longer a tautology (most historically-closed SOC cases in
this dataset genuinely are TruePositive). Rejected before running for real;
moved to the dynamic, decision-triggered design described above and
documented in `assign_reviewers.py`'s own module docstring as a rejected
design, not silently dropped.

```
sample_source: phase7c_v1_fallback_prose_hint   (see §2 — v2 export blocked, see below)
primary counts: {reviewer-a: 30, reviewer-b: 30}
static dual review count: 20 of 60  (historical_other_disposition: 8, quality_control_sample: 12)
queue sizes: {reviewer-a: 38, reviewer-b: 42}
```
These numbers are real, computed against the actual 60-case Phase 7C
sample (the only one on disk today — see §2's blocker). They will be
recomputed automatically against the authoritative Phase 7D v2 sample the
moment that export can run; no code change is needed (`assign_reviewers.
load_sample()` prefers the v2 sample and only falls back with a printed
warning when it's absent).

### 2. Persist authoritative historical disposition — EXECUTED 2026-08-21

Schema v2 (`dataset_schema.SCHEMA_VERSION_V2 = "phase7-v2"`) adds structured
`historical_disposition` / `historical_disposition_source` /
`historical_disposition_metadata`, enforced by `validate_case()`, with a
genuine v1/v2 SEPARATION (a v1 record carrying a v2 field is rejected as
unknown; a v2 record missing the new required fields is rejected as
incomplete) — see `test_phase7d.py` §1.

The credential blocker documented below (originally: no `THEHIVE_API_KEY`
in this environment, and a separate leaked-key finding this agent refused
to use) was resolved out-of-band: the user manually exported a freshly
issued, least-privilege, read-only key into their own terminal session and
ran `export_dataset_b_candidates_v2.py` themselves — this agent never
received, saw, or handled the key at any point, per the user's explicit
"Antigravity will not receive or store any TheHive credential" instruction.
The agent's only role was inspecting the (unmodified) script and handing
back the exact, argument-free invocation command.

**Export result, independently re-verified against the live output (not
just the reported summary)**:
```
cases_queried_live:             334
excluded_created_after_cutoff:  0
eligible v2 candidates:         226
sanitization failures:          0    (re-confirmed: 0/226, fresh scan)
schema failures:                0    (re-confirmed: 0/226, fresh validate_case() pass)
manifest_hash:                  25facfdef786f18b19c0ea99e2baeaedcf08dd3b91d45d3c0c6dca9e9b87e106
manifest schema_version:        phase7-v2
duplicate content groups:       0    (re-confirmed via find_duplicate_content())
```

**v1 vs v2 population — byte-identical case set, structurally confirmed**:
```
v1_case_count:      226
v2_case_count:      226
unchanged_count:    226
added_in_v2:        0
removed_from_v2:    0
```
Every one of the 226 v1 cases is present, unchanged, in v2 — the cutoff
(`_createdAt <= 2026-08-21T20:03:22.473747Z`, the Phase 7B report's own
`run_at`) correctly bounded the live re-query to exactly the original
population; nothing newer silently entered, nothing was lost.

**Structured field vs. the old prose-derived count — exact match, no
drift introduced by the correction**:
```
v2 historical_disposition (STRUCTURED):  TruePositive 145 / FalsePositive 72 / Other 9
v1 (Phase 7B report, tracked in-memory,
   never persisted structurally):        TruePositive 145 / FalsePositive 72 / Other 9
v2 severity distribution:                 sev1: 1, sev2: 176, sev3: 49  (identical to v1)
```
This is the concrete proof the correction did what it was meant to do:
the SAME underlying disposition data, now durably captured as a validated,
authoritative field instead of a value that only ever existed in a
throwaway in-memory dict during the original Phase 7B run.

**Authoritative 60-case review sample, generated from the structured field
(no prose extraction anywhere in this path)**:
```
sample_version:        phase7d-v2-authoritative
seed:                  20260821  (frozen, same as Phase 7B/7C)
case_uids:             60
content-hash verification: 0 mismatches (independently re-hashed every
                            sampled case against the sample manifest)
largest incident group: 5 cases (8.3% of the sample) — same correction
                            quality as Phase 7C's v2 sample, now backed by
                            real, authoritative data
documented exceptions:  3 (grp-4a17528ae8fe x2, grp-e52e3ddf7d44 x1)
sample historical_disposition: TruePositive 46 / FalsePositive 6 / Other 8
sample severity:               sev1: 1, sev2: 41, sev3: 18
```

**Reviewer assignments regenerated against the authoritative sample**
(`assign_reviewers.py` re-run — it auto-detects the v2 export and no longer
prints the Phase 7C fallback warning):
```
sample_source:    phase7d_v2_authoritative   (was: phase7c_v1_fallback_prose_hint)
primary counts:   {reviewer-a: 30, reviewer-b: 30}
dual review:      20 of 60  (historical_other_disposition: 8, quality_control_sample: 12)
queue sizes:      {reviewer-a: 38, reviewer-b: 42}
```
Numbers are identical to the provisional v1-fallback run reported in the
prior stop-and-report — expected, since the underlying case population and
its disposition/severity/incident-group structure are unchanged (0 added,
0 removed) — but these are now computed from the AUTHORITATIVE source, not
a fallback.

**Labels remain pending — independently re-verified**: every one of the
226 v2 candidates has `review_status: "pending"` and `expected_tier: null`
(fresh scan, zero exceptions); no reviewer `.jsonl` overlay file exists yet
anywhere under `soar/review_overlays/` — no review has started, no label
was silently approved.

**Outstanding, NOT actioned this turn (scope discipline)**: the leaked
TheHive key still sits in plaintext at `PROJECT-STATE.md:430`. Redacting it
was part of an EARLIER instruction set but was not included in this turn's
specific numbered task list, so it was left untouched rather than acted on
without being asked — flagged again in the final report below.

### 3. Dataset B's role clarified

`ai/testset/dataset_b_candidates/DATASET_B_SCOPE.md` (new) states plainly:
Dataset B currently evaluates mandatory L2 escalation, false-auto-
containment prevention, historical TruePositive/FalsePositive/Other
handling, leakage controls, and malformed/missing-evidence behaviour — NOT
positive L1 automation, because every current candidate has empty
`fixtures`. `review_rubric.py` already enforced this in code before this
phase (Phase 7C); this phase adds the explicit documentation the
instruction asked for, plus a NEW dataset-aware refusal message in
`review_dataset.record_decision(dataset="b")` (functionally redundant with
the existing generic evidence gate, but explicit and directly named, per
instruction) — see `test_phase7d.py` §7. No historical analyzer result was
fabricated to work around this; Dataset B stays fixture-empty this phase.

### 4. Dataset A expanded — 25 synthetic, specification-derived cases

`ai/testset/dataset_a_synthetic/` (new), built by
`build_dataset_a_synthetic_fixtures.py`. Every case: `review_status:
"pending"`, `label_source: "specification_derived_pending_human"`,
fixtures tagged `_provenance: "synthetic"`. Expected outcomes were derived
by reading `l1_policy.py`'s gate docstrings/conditionals — proven by
EXECUTION, not just static claim: `test_phase7d.py` wraps
`l1_policy.evaluate_l1_malicious_eligibility` during a full `build_cases()`
run and asserts zero invocations.

```
5   fully eligible L1 positive controls (a01-a05) -> L1_TRUE_POSITIVE_CONTAINED
20  L2/failure-mode cases (a06-a25), covering the remaining 20 codes
25  total cases
```

**21-code coverage matrix** (`ai/results/phase7d-dataset-a-coverage-matrix.json`):
```
covered_by_dataset: 21 / 21 POLICY_DECISION codes  (missing_from_dataset: [])
covered_and_reachable_via_current_replay_harness:      15 codes
covered_but_NOT_reachable_via_current_replay_harness:    6 codes
```
The 6 not-reachable-today codes are a genuine, previously-undocumented
finding from this phase, not an artifact of case design: grep-verified
ZERO emit sites anywhere in `l1_policy.py`/`agent_orchestrator.py` beyond
their own `Reason` declaration — `ATTACK_SIGNATURE_VETO`,
`CASE_CLOSE_VERIFIED`, `HIGH_RISK_TECHNIQUE`, `PROMPT_INJECTION_SUSPECTED`,
`RAG_INSUFFICIENT_HISTORY`, `STALE_EVIDENCE`. Cases for all 6 are still
included (dataset-completeness, per `build_reason_code_coverage_manifest()`'s
own definition of "covered") with `label_notes` explaining the gap plainly
— **not fabricated as if the current policy produces them.**

Two additional cases (a18 `DUPLICATE_PROCESSING`, a19 `NOT_ARMED`) were
also built — **these turned out NOT to be among the 21 POLICY_DECISION
codes** (both are classified `OPERATIONAL_RECOVERY` in
`REASON_CODE_CLASSIFICATION`, confirmed by the coverage script's own
correct computation, not a hand-count) — so they aren't required by "all 21
externally evaluable policy-decision reasons," but were kept: both ARE
emitted in real production code, yet specifically unreachable through
`run_policy_replay()`'s current wiring (`_simulate_case()` hardcodes
`armed=True`, and never calls whatever records a tier decision, so
`DUPLICATE_PROCESSING` can never be observed in a replay batch regardless
of fixture design) — a genuinely useful, separate harness-scope finding,
kept and documented rather than discarded once found not to be required.

Bullet-by-bullet mapping to the instruction's minimum required scenarios:
benign→L2 (a09, NOVEL_CASE), low confidence (a07), non-allowlisted
rule/technique (a08, a06 for the partial-match variant), missing/failed
analyzer (a10, a12), insufficient RAG corroboration (a14), conflicting RAG
history (a11), attack-signature veto/unsafe ambiguity (a15 ambiguous
target + a21 veto placeholder), internal/private target refusal (a16),
malformed schema (a13), not-armed execution (a19), duplicate/idempotent
replay (a18), containment unverified (a17), verified containment+closure
success (a01-a05 + a20), closure-verification failure→L2 fallback (a17).

### 5. Review-tool updates

`review_dataset.py`: `--dataset {a,b}` required flag; `resolve_dataset()`
picks the v2 (authoritative) Dataset B export when present, v1 fallback
otherwise, with a printed warning; `historical_disposition_display()`
strictly separates `authoritative` (v2 structured field only) from
`non_authoritative_hint` (v1 prose, always labeled as such —
`extract_historical_disposition_hint()` is REMOVED from every authoritative
code path, confirmed in `review_rubric.evaluate_positive_gate_checklist()`
and `review_dataset.historical_disposition_display()`, both switched to
`dataset_schema.get_authoritative_historical_disposition()`);
`fixture_provenance()` classifies every case synthetic/historical/
independently_recorded/missing, shown in `format_case_for_display()`;
Dataset B L1-approval-with-missing-fixtures is explicitly refused
(`record_decision(..., dataset="b")`); `effective_queue()` implements the
narrowed + dynamic dual-review policy; append-only overlays and atomic,
resumable saves are unchanged from Phase 7C.

### 6. Verification

```
NEW (test_phase7d.py):              49 passed, 0 failed
PHASE 7C (test_review_dataset.py):  32 passed, 0 failed   (still green — dataset_schema/
                                                             review_rubric changes are additive)
IDEMPOTENCY TESTS:                  34 passed, 0 failed
PHASE 1 TESTS:                      57 passed, 0 failed
PFSENSE VERIFY TESTS:               23 passed, 0 failed
CONTAINMENT VERIFICATION TESTS:     50 passed, 0 failed
CORTEX METADATA TESTS:              26 passed, 0 failed
TRUEPOSITIVE CLOSURE TESTS:         74 passed, 0 failed
L2 ASSIGNMENT TESTS:                87 passed, 0 failed
NOTIFICATION TESTS:                 96 passed, 0 failed
SANITIZATION TESTS:                 38 passed, 0 failed
REPLAY HARNESS TESTS:               66 passed, 0 failed
GRAND TOTAL: 632 passed, 0 failed
```
All 13 required properties covered: schema-v1/v2 separation, authoritative
structured disposition, prohibition of prose-derived authoritative labels,
snapshot-cutoff enforcement (including refusal-to-guess when the report/
`run_at` is missing), v1 candidate byte preservation, corrected dual-review
selection, Dataset B missing-fixture L1 rejection, Dataset A frozen
synthetic fixture validation, specification-derived pending labels,
complete 21-code coverage, deterministic sample and reviewer queues, total
network prohibition (re-verified for the new export/assignment code, not
just asserted), secret-free outputs.

### Prohibited actions — confirmed not taken

No label was approved by the agent. Neither dataset was locked. No policy
metrics were run. No live Cortex/pfSense/Ollama call was made. TheHive was
read via `api.case.find()`/`api.case.find_observables()` ONLY — no write
method (`.update`/`.create`/`.delete`/`.comment.*`/`.cortex.*`) exists
anywhere in `export_dataset_b_candidates_v2.py`, grep-confirmed same as
v1 — and that read was run by the USER, manually, in their own terminal
with their own key; this agent never received, saw, printed, logged, or
persisted the credential at any point, and inspected only the resulting
sanitized files afterward. No code was deployed. Phase 8 was not started.
No historical analyzer result was fabricated for Dataset B. No leaked/
found credential was used to bypass the "process environment only"
requirement — the previously-found leaked key in `PROJECT-STATE.md` was
never touched or used.

Stopping here, per instruction. Awaiting further direction — in particular
on the still-outstanding `PROJECT-STATE.md` key exposure (§2) and the
dual-review-scope finding (§1) — before any human review begins.

## 20. Credential-incident record — TheHive key exposure, remediated in the current worktree — 2026-08-21

### Discovery
While checking for `THEHIVE_API_KEY` availability during Phase 7D (§19), a
live TheHive API key was found committed in plaintext at
`PROJECT-STATE.md`, in violation of this project's own CLAUDE.md rule
("Never write real API keys/tokens into any file — use `<PLACEHOLDER>`").
The agent did not use it. Flagged to the user immediately (see §19's
Phase 7D report).

### Revocation
**User-confirmed**: the exposed key has been revoked. The agent did not
revoke it, does not have the ability to, and took the user's confirmation
as authoritative before performing any redaction.

### Current-worktree redaction (this turn)
A full-value search of `PROJECT-STATE.md` (not just the originally-found
line) found the SAME revoked key value in **3 locations**, not 1:
- Line 430 (the `export THEHIVE_API_KEY=...` example — the one originally
  flagged);
- A plaintext credentials-reference table row;
- A troubleshooting note describing a since-fixed ElastAlert configuration
  drift, where the revoked key was quoted as "the old, pre-rotation key."

All 3 were replaced with the placeholder `<REVOKED_AND_REDACTED_THEHIVE_API_KEY>`,
plus a short explanatory note above the first occurrence stating the key
was revoked and must never be reused. Verified after the edit: zero
remaining occurrences of the raw value anywhere in `PROJECT-STATE.md`.
Surrounding historical documentation (what happened, why, the timeline) was
otherwise preserved verbatim — only the secret VALUE was touched.

### Broader scan result (reported, NOT remediated this turn — out of this
turn's specific authorization, which was scoped to the one revoked key)
A repository-wide pattern scan (labeled `key=`/`password=`/`token=`/
`Bearer `/JWT/AWS-key/private-key-block/Gmail-app-password shapes) found:
- The vast majority of matches are **code** (function parameter names like
  `password=`, variable references like `apikey=api_key`, or this project's
  OWN redaction-pattern documentation/tests describing what a secret regex
  looks like) — not real leaked values.
- `configs/elk/` and `configs/pfsense/` contain real, plaintext
  credentials — this is a **pre-existing, already-documented, user-
  approved exception** (CLAUDE.md: "kept unredacted per user decision...
  do not publish/share this folder externally"), not a new finding.
- `PROJECT-STATE.md`'s own credentials-reference table (separate from the
  now-redacted TheHive key) still lists other plaintext lab
  credentials (ELK SSH, Elasticsearch, pfSense), and `notes/3.md` contains
  a plaintext Elasticsearch password — **pre-existing, not touched this
  turn**, flagged for a future, separately-authorized cleanup pass.
- A **second, DIFFERENT API-key-shaped value** was found near the same
  ElastAlert troubleshooting note, described in the surrounding text as
  "the key the orchestrator uses" (i.e. possibly the CURRENT, still-active
  credential, not the one already confirmed revoked). **Self-reported
  mistake**: while inspecting redacted context around this area earlier in
  the session, this second value was inadvertently displayed in a tool
  output (a redaction regex targeted only the FIRST key's pattern, not
  this one) — an exposure this agent caused. Recommend treating that
  second value as exposed out of caution and rotating it too,
  independent of whether it was already due for rotation.
- 12 "Gmail-app-password-shaped" matches (4 groups of 4 lowercase letters)
  were all manually reviewed and are ordinary English prose coincidentally
  matching that shape — false positives, not real credentials.

### Git history
**Not applicable — this project is not a git repository** (`git
rev-parse --is-inside-work-tree` fails; no `.git` directory exists
anywhere in the tree). There is no commit history to search, no staged/
tracked/untracked distinction in the git sense, and no risk of the
revoked key surviving in a prior commit — every copy of it that ever
existed is exactly the plaintext copies found and redacted above.

### Tests
```
SANITIZATION TESTS:                 38 passed, 0 failed
PHASE 7D TESTS:                     49 passed, 0 failed
REVIEW DATASET TESTS:                32 passed, 0 failed
IDEMPOTENCY TESTS:                  34 passed, 0 failed
PHASE 1 TESTS:                      57 passed, 0 failed
PFSENSE VERIFY TESTS:                23 passed, 0 failed
CONTAINMENT VERIFICATION TESTS:      50 passed, 0 failed
CORTEX METADATA TESTS:               26 passed, 0 failed
TRUEPOSITIVE CLOSURE TESTS:          74 passed, 0 failed
L2 ASSIGNMENT TESTS:                 87 passed, 0 failed
NOTIFICATION TESTS:                  96 passed, 0 failed
REPLAY HARNESS TESTS:                66 passed, 0 failed
GRAND TOTAL: 632 passed, 0 failed  (unchanged from Phase 7D — PROJECT-STATE.md
                                     is documentation, not imported by any test)
```

### Remaining manual remediation
1. **Rotate the second, possibly-still-active key** found near the
   ElastAlert troubleshooting note (accidentally displayed by this agent
   during inspection — see above) — not yet redacted or confirmed revoked.
2. `PROJECT-STATE.md`'s remaining plaintext lab credentials (SSH/
   Elasticsearch/pfSense passwords) and `notes/3.md`'s Elasticsearch
   password — not authorized for remediation this turn, flagged for a
   future pass.
3. `configs/elk/`/`configs/pfsense/` remain deliberately unredacted per
   your prior, standing decision — no action needed unless you want to
   revisit that decision.

No label was approved. Neither dataset was locked. Nothing was committed,
pushed, or force-pushed (not applicable — no git repository exists). No
Git history was rewritten (not applicable, same reason). Phase 8 was not
started.

## 21. UNRESOLVED SECURITY BLOCKER — second exposed TheHive key — deferred 2026-08-21

**Status: OPEN. Must be remediated before any live integration test,
deployment, real demo, or re-enabling `soar-orchestrator.service`.**

A second, distinct TheHive-API-key-shaped value remains in plaintext in
`PROJECT-STATE.md` (near the ElastAlert-config-drift troubleshooting note,
§20), described in the surrounding text as "the key the orchestrator
uses." Unlike the first key, **this one has not been confirmed revoked**,
and its owning login/account is **not identifiable from the surrounding
documentation alone** (checked — the doc only ever refers to it
functionally, never by account name).

This agent additionally **caused a self-reported exposure**: while
inspecting redacted context around this area during the prior credential-
remediation turn, this value was inadvertently displayed once in a tool
output (a redaction regex targeted only the FIRST key's pattern). That
display, plus the plaintext copy in `PROJECT-STATE.md` itself, are the
full extent of this key's known exposure — no other read, use, or
authentication attempt has been made against it.

**Per explicit user instruction, this agent will not**: read, display,
copy, hash, partially display, authenticate with, or otherwise process
this credential's value, in this session or any future one, until the
user separately authorizes and personally performs identification/
rotation (as was done for the first key — manual export into the user's
own terminal, agent never touching the value).

**Consequence, stated plainly**: `soar-orchestrator.service` must remain
stopped/disabled (already the case per prior phases' documentation) until
this is resolved, since re-enabling it would put a still-unverified,
possibly-compromised key back into live use. No live integration test,
deployment, or demo should proceed against real TheHive/Cortex/pfSense
until the user confirms this key's status and — if still active — rotates
it, following the exact same manual, agent-blind pattern already used for
the first key.

## 22. Phase 7E — human review, in progress — review finding: synthetic/test-case exclusion filter gap

Found during reviewer-a's manual review of case `dsb-c-11b8b89478`
("Test case - Cortex integration", observable `8.8.8.8`, historical
disposition `Other`), excluded by the reviewer as a lab integration-test
artifact.

**Finding**: `export_dataset_b_candidates.py`'s (and, unmodified,
`export_dataset_b_candidates_v2.py`'s) `_is_excluded_test_case()` only
matches an EXACT title prefix (`"[SYNTHETIC TEST]"`) or a fixed tag set
(`{"synthetic", "notification-test", "phase-5-live-validation",
"l2-integration-test", "phase-5-6-live-validation"}`). A case titled
`"Test case - Cortex integration"` with no matching tag is semantically an
obvious lab-test artifact but does not match either condition, so it
passed both the v1 and v2 exports' classification and entered the
authoritative 226-candidate population and this reviewer's queue.

**Not remediated this turn** — per explicit instruction, the authoritative
v2 dataset/sample was NOT modified, regenerated, or reordered during
review. The case was instead correctly handled through the review
workflow itself: reviewer-a marked it `review_status: "excluded"`,
`expected_tier`/`expected_primary_reason: null` — the mechanism this
dataset's review process is designed to use for exactly this situation
(a candidate that shouldn't count toward any safety metric). No candidate
file was touched; the exclusion lives only in `reviewer-a`'s append-only
overlay.

**Recommendation for a future phase**: broaden `_is_excluded_test_case()`
to also flag titles containing case-insensitive "test case" / "integration
test" style phrasing, OR treat this as a known, acceptable residual gap
covered by the human review layer (as just demonstrated) rather than a
export-time filter — either is defensible; not decided here, since fixing
the export script is out of scope for a review-in-progress turn.

**Second occurrence, same finding**: case `dsb-c-23ed74f43f` (title
`jhhiu`, description `ljjpj`, observable `203.0.113.1` — a TEST-NET-3/
RFC 5737 documentation-range address, historical disposition `Other`) is
unambiguous keyboard-mash/manual test content that also passed
`_is_excluded_test_case()` for the same reason (no matching title prefix
or tag). Also excluded by reviewer-a via the review workflow, not by
modifying the export or dataset. Two occurrences in the first 6 cases
reviewed suggests this is not a one-off — the recommendation above (widen
the filter, or formally accept human review as the backstop for this
category) applies more strongly with a second data point.

## 23. Phase 7E — reviewer-a's full 38-case queue COMPLETE — 2026-08-22

10 cases decided individually (one at a time, each independently validated
and saved on the user's explicit instruction), then a batch-assisted pass
covering the remaining 28: this agent produced a dry-run-only proposal
table (`ai/results/phase7e-reviewer-a-remaining-draft.md`, every proposal
validated via `review_rubric.validate_decision()` called directly — a pure
function, never `record_decision()` — so nothing was saved during
proposal generation), the user reviewed it and approved all 28 with one
correction (`dsb-c-c2f63b996e`: disputed L2 -> excluded, since it is an
explicit self-declared "LAB TEST" on a TEST-NET-3 address), then this
agent applied the corrected batch via `record_decision()` one case at a
time, stopping-on-first-failure semantics armed (none triggered).

**Final reviewer-a result, independently re-verified against the overlay
file itself (not just the apply-loop's own report)**:
```
reviewer-a progress:        38 / 38 done, 0 remaining
status breakdown:            approved: 25   disputed: 5   excluded: 8
L1 approvals in the overlay: 0   (confirmed — Dataset B's fixture-less
                                  state, per §3/DATASET_B_SCOPE.md, was
                                  never violated across all 38 decisions)
reviewer-b overlay exists:   False (fully independent — never read or
                                  written during reviewer-a's review)
```
Every decision was individually validated by `review_rubric.validate_decision()`
(the same hard gate used throughout Phase 7C/7D — reject, don't warn) and
secret-scanned before being appended atomically to `soar/review_overlays/
reviewer-a.jsonl`. The v2 manifest and 60-case sample were re-verified
clean (0 discrepancies) both before the individual-case round and again
before the batch-apply round.

**Findings surfaced during this review round** (documented, not silently
fixed — see §22 for the first two):
1. The synthetic/test-case export-filter gap (§22) — 3 additional confirmed
   instances found during the batch pass (`run_analyzer wiring test`,
   two-plus `Cortex Responder API Test` cases), on top of the 2 found
   during individual review — 6 total among reviewer-a's 38 cases (a
   meaningful fraction, ~16%), reinforcing the recommendation to either
   widen `_is_excluded_test_case()` or formally treat human review as the
   backstop for this category.
2. 4 cases flagged `NEEDS_HUMAN_ATTENTION` for a genuine content/label
   tension rather than a clean gate failure — 3 remained `disputed` after
   the user's review (a mislabeled-sounding service name, a disposition
   that looked under-classified relative to its content, a title/content
   mismatch on a brute-force alert), 1 was reclassified straight to
   `excluded` on inspection.
3. Multiple cases referenced the project's OWN Tailscale-CGNAT-range
   devices, ELK/SIEM host, or pfSense WAN/gateway addresses as the
   recorded "attacker" IP — correctly routed to L2 via `PROTECTED_ASSET`/
   `CONTAINMENT_REFUSED` per the guard's own administrative-path and
   protected-asset rules, not a dataset defect, but worth noting as a
   recurring shape in this lab's alert corpus.

No label was approved as L1. Neither dataset was locked. No live
infrastructure accessed. Phase 8 not started. Reviewer-b's queue remains
completely independent and untouched — Phase 7E continues with reviewer-b
as a separate, later effort.

## 24. Phase 7E — reviewer-b's queue complete (40/42) — contamination on 2 cases, deferred

Reviewer-b's 42-case queue (30 primary + 12 dual-review secondary) was completed to 40/42
via the same batch-assisted-proposal-then-approval pattern as §23 (`ai/results/
phase7e-reviewer-b-proposals.md`, every proposal validated via `review_rubric.
validate_decision()` before any save). Final reviewer-b overlay, independently
re-verified: **40 decisions, status breakdown approved: 14, disputed: 8, excluded: 18, L1
approvals: 0.**

**2 cases withheld, not decided by reviewer-b**: `dsb-c-11b8b89478` and
`dsb-c-23ed74f43f`. While producing reviewer-b's proposals, this agent read §22 of this
document (above), which contains reviewer-a's actual decision and rationale for both
cases — breaking reviewer-b's independence for exactly these two. Per the project owner's
direction: no reviewer-b decision was created or copied for either case; reviewer-a's
existing decision stands as the sole authoritative primary decision for both; both are
excluded from every inter-reviewer agreement calculation. Documented explicitly as a
protocol deviation — **18 of the 20 statically-assigned dual-review cases have a clean,
uncontaminated second opinion ("18/20 clean dual reviews")**, not 20/20.

No candidate file, manifest, sample, or the other reviewer's overlay was touched while
producing these decisions. Neither dataset was locked. Phase 8 not started.

## 25. Phase 7E — adjudication finalized, Dataset B v2 review sample LOCKED — 2026-08-22

Comparison of the 18 clean dual-reviewed cases (reviewer-a vs. reviewer-b, contaminated
pair excluded per §24): **14 agreements, 4 disagreements — 77.8% preliminary exact
agreement**, computed once and never recomputed against post-adjudication labels (the
figure above is the one carried into the final lock, unchanged).

Across the full 60-case sample, 12 cases carried a `disputed` status from at least one
reviewer; the union of the 4 dual-review disagreements and these 12 disputed cases,
deduplicated, gave **14 unresolved cases** requiring adjudication
(`ai/results/phase7e-adjudication-proposals.md`, every proposal validated via
`review_rubric.validate_decision()` — dry-run only, nothing saved during proposal
generation).

The project owner approved the adjudication with two corrections: `dsb-c-1a1e45f08c` added
as `excluded` (for consistency with `dsb-c-ce88041225`/`dsb-c-dc1b7c7233` — same
unresolved-template-title, zero-observable defect shape reviewer-a had, in isolation,
approved rather than excluded), and `dsb-c-ec8679e908` changed from a proposed `excluded`
to final `disputed`/L2 (the `h4x0r` account-name signal judged insufficient on its own to
call it a test artifact rather than a genuine attacker-created account). **Final
adjudicated set: 15 cases — 8 approved/L2, 3 excluded, 4 disputed/L2, 0 L1.**

The 4 final disputed cases (`dsb-c-4a309f2549`, `dsb-c-8d06d04a08`, `dsb-c-c851a89a34`,
`dsb-c-ec8679e908`) are treated as terminal for this phase — excluded from safety-
performance metrics, no further reviewer required under the accepted single-primary-review
protocol; each represents a genuine, evidence-documented open question (a plausibly-
legitimate service name, an unverified subnet-topology claim, an ambiguous block
direction, an unresolved test-vs-real-account signal) rather than a gap in review effort.

**Applied via the project's existing decision-persistence mechanism** —
`review_dataset.record_decision()`, the same atomic, rubric-gated, secret-scanned
append-only writer already used for both primary reviewers — under a new, neutral
`reviewer_id: "adjudication"`. This is a NEW overlay file
(`soar/review_overlays/adjudication.jsonl`, 15 lines); no distinct "final-label" function
previously existed in this codebase, so the existing per-decision writer was reused rather
than inventing a parallel save path. `reviewer-a.jsonl` and `reviewer-b.jsonl` were
independently re-hashed before and after this session — byte-identical, confirming neither
was modified.

**Final 60-case label set** (`soar/review_overlays/FINAL_LABELS_v1.json`) built by taking
the adjudication decision for the 15 adjudicated cases and each case's assigned primary
reviewer's decision otherwise (15 adjudication + 24 reviewer-a-primary + 21
reviewer-b-primary = 60, 0 missing):

```
final status_counts: approved 35, excluded 21, disputed 4
final tier_counts:   L2 39, null 21, L1 0
approved (contributes to safety metrics per rubric rule 7): 35
primary-reason distribution, approved only:
  MISSING_EVIDENCE 26, CONFLICTING_EVIDENCE 3, RULE_NOT_L1_ELIGIBLE 3,
  AMBIGUOUS_TARGET 1, PROTECTED_ASSET 1, RAG_INSUFFICIENT_HISTORY 1
```

**Full local test suite executed** — every `soar/test_*.py` (no shared pytest runner
exists in this repo; each is a standalone script with its own PASS/FAIL counter and exit
code): **12/12 files, 632/632 checks passed, 0 failures, all exit codes 0.**

All validations and tests having passed, the dataset was locked:
`soar/review_overlays/DATASET_B_LOCK_v1.json` (`lock_id:
"dataset-b-v2-phase7e-final-v1"`), recording sha256 hashes of the candidate manifest,
review-sample manifest, assignments file, both reviewer overlays, the adjudication
overlay, the final label set, and the adjudication-proposals record, plus the full test
summary above.

Performed entirely offline inside `replay_harness.network_guard()`. No credentials
accessed, no live infrastructure (TheHive/Cortex/pfSense/Ollama) contacted. **Phase 8 has
not started.**
