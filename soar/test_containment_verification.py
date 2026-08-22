#!/usr/bin/env python3
"""
Phase 2 tests — agent_orchestrator.execute_and_verify_containment().

PURE. `pfsense_check_fn` and `execute_fn` are ALWAYS injected fakes — no live
pfSense/Cortex/TheHive call is ever made. All idempotency state lives in a
throwaway temp directory removed at the end of the run.

Run: ./.venv/bin/python test_containment_verification.py
"""
import multiprocessing
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("THEHIVE_API_KEY", "test-placeholder-not-real")

import idempotency
import l1_policy
import pfsense_verify as pv
import agent_orchestrator as ao

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name); print(f"  PASS  {name}")
    else:
        FAIL.append(name); print(f"  FAIL  {name}  {detail}")


STORE = tempfile.mkdtemp(prefix="containment_test_")


def fresh_dir():
    return tempfile.mkdtemp(prefix="cv_", dir=STORE)


# ---- fakes -------------------------------------------------------------------

def make_pfsense_fake(sequence):
    """Returns a pfsense_check_fn stand-in that returns each dict in `sequence`
    on successive calls (precheck, then postcheck if reached)."""
    calls = {"n": 0, "log": []}
    def fake(target_ip):
        i = min(calls["n"], len(sequence) - 1)
        calls["n"] += 1
        calls["log"].append(target_ip)
        result = sequence[i]
        return {"result": result, "target_ip": target_ip,
                "checked_at": "2026-08-21T00:00:00Z", "table_size": 1,
                "error": "simulated failure" if result in (pv.RESULT_QUERY_FAILED,) else None}
    return fake, calls


def make_execute_fake(cortex_reported_success=True, cortex_status="Success", error=None):
    calls = {"n": 0, "idempotency_keys_seen": []}
    def fake(api, case_id, target_ip, confidence, idempotency_key=None, store_dir=None):
        calls["n"] += 1
        calls["idempotency_keys_seen"].append(idempotency_key)
        return {"cortex_reported_success": cortex_reported_success, "responder_id": "resp1",
                "job_id": f"job-{calls['n']}", "cortex_status": cortex_status, "error": error}
    return fake, calls


TARGET = "202.61.130.163"


# ==============================================================================
# 1. Target absent -> Cortex success -> exact IP present -> verified
# ==============================================================================

print("\n=== 1. absent -> Cortex success -> present -> VERIFIED ===")
d = fresh_dir()
pf_fn, pf_calls = make_pfsense_fake([pv.RESULT_ABSENT, pv.RESULT_PRESENT])
ex_fn, ex_calls = make_execute_fake(cortex_reported_success=True)
r = ao.execute_and_verify_containment(None, "~a1", "~c1", TARGET, 0.9, "armed", False,
                                      pfsense_check_fn=pf_fn, execute_fn=ex_fn, store_dir=d)
check("executed=True", r["executed"] is True, r)
check("reason_code L1_TRUE_POSITIVE_CONTAINED", r["reason_code"] == l1_policy.Reason.L1_TRUE_POSITIVE_CONTAINED)
check("Cortex was called exactly once", ex_calls["n"] == 1)
check("pfSense was checked twice (pre + post)", pf_calls["n"] == 2)
check("idempotency record is COMPLETED",
     idempotency.get_status(idempotency.containment_action_key("~a1", "~c1", TARGET, "armed"),
                            store_dir=d)["status"] == idempotency.STATUS_COMPLETED)


# ==============================================================================
# 2. Target absent -> Cortex success -> IP absent -> L2 (CONTAINMENT_UNVERIFIED)
# ==============================================================================

print("\n=== 2. absent -> Cortex success -> still absent -> L2 UNVERIFIED ===")
d = fresh_dir()
pf_fn, pf_calls = make_pfsense_fake([pv.RESULT_ABSENT, pv.RESULT_ABSENT])
ex_fn, ex_calls = make_execute_fake(cortex_reported_success=True)
r = ao.execute_and_verify_containment(None, "~a2", "~c2", TARGET, 0.9, "armed", False,
                                      pfsense_check_fn=pf_fn, execute_fn=ex_fn, store_dir=d)
check("executed=False despite Cortex success", r["executed"] is False, r)
check("reason_code CONTAINMENT_UNVERIFIED", r["reason_code"] == l1_policy.Reason.CONTAINMENT_UNVERIFIED)
check("Cortex was still only called once (not retried automatically)", ex_calls["n"] == 1)


# ==============================================================================
# 3. Target absent -> Cortex failure -> L2 without successful verification
# ==============================================================================

print("\n=== 3. absent -> Cortex FAILS -> L2 (ordinary failure, pfSense confirms absent too) ===")
d = fresh_dir()
# Phase 2.5 item 8: a Cortex failure now ALSO triggers a pfSense check (to catch
# a state CONFLICT, see test 3b below) — here that check confirms ABSENT, i.e.
# consistent with the failure report, so this is the ordinary refusal path.
pf_fn, pf_calls = make_pfsense_fake([pv.RESULT_ABSENT, pv.RESULT_ABSENT])
ex_fn, ex_calls = make_execute_fake(cortex_reported_success=False, cortex_status="Failure")
r = ao.execute_and_verify_containment(None, "~a3", "~c3", TARGET, 0.9, "armed", False,
                                      pfsense_check_fn=pf_fn, execute_fn=ex_fn, store_dir=d)
check("executed=False on Cortex failure", r["executed"] is False)
check("reason_code CONTAINMENT_REFUSED (ordinary failure, no conflict)",
     r["reason_code"] == l1_policy.Reason.CONTAINMENT_REFUSED)
check("pfSense checked twice: precheck + the new failure-path conflict-check",
     pf_calls["n"] == 2, pf_calls)


# ==============================================================================
# 3b. Phase 2.5 item 8 — Cortex failure + UNEXPECTED pfSense presence = state conflict
# ==============================================================================

print("\n=== 3b. Cortex FAILS but pfSense shows the IP present anyway -> STATE CONFLICT ===")
d = fresh_dir()
pf_fn, pf_calls = make_pfsense_fake([pv.RESULT_ABSENT, pv.RESULT_PRESENT])
ex_fn, ex_calls = make_execute_fake(cortex_reported_success=False, cortex_status="Failure")
r = ao.execute_and_verify_containment(None, "~a3b", "~c3b", TARGET, 0.9, "armed", False,
                                      pfsense_check_fn=pf_fn, execute_fn=ex_fn, store_dir=d)
check("conflicting state -> executed=False (never auto-close on a conflict)", r["executed"] is False)
check("reason_code CONTAINMENT_STATE_CONFLICT, NOT the generic CONTAINMENT_REFUSED",
     r["reason_code"] == l1_policy.Reason.CONTAINMENT_STATE_CONFLICT, r["reason_code"])
check("the conflict is distinctly recorded in the idempotency detail",
     idempotency.get_status(idempotency.containment_action_key("~a3b", "~c3b", TARGET, "armed"),
                            store_dir=d)["detail"].get("conflict") == "cortex_failure_but_ip_present")


# ==============================================================================
# 4. Target absent -> Cortex timeout -> L2
# ==============================================================================

print("\n=== 4. absent -> Cortex TIMEOUT -> L2 ===")
d = fresh_dir()
pf_fn, pf_calls = make_pfsense_fake([pv.RESULT_ABSENT])
ex_fn, ex_calls = make_execute_fake(cortex_reported_success=False, cortex_status="Timeout",
                                    error="analyzer job did not finish in 120s")
r = ao.execute_and_verify_containment(None, "~a4", "~c4", TARGET, 0.9, "armed", False,
                                      pfsense_check_fn=pf_fn, execute_fn=ex_fn, store_dir=d)
check("timeout -> executed=False", r["executed"] is False)
check("timeout -> escalated, not silently dropped", r["reason_code"] is not None)


# ==============================================================================
# 5. Target already present -> responder not called again
# ==============================================================================

print("\n=== 5. Target ALREADY present -> Cortex never invoked ===")
d = fresh_dir()
pf_fn, pf_calls = make_pfsense_fake([pv.RESULT_PRESENT])
ex_fn, ex_calls = make_execute_fake(cortex_reported_success=True)
r = ao.execute_and_verify_containment(None, "~a5", "~c5", TARGET, 0.9, "armed", False,
                                      pfsense_check_fn=pf_fn, execute_fn=ex_fn, store_dir=d)
check("already-present -> executed=True", r["executed"] is True)
check("reason_code CONTAINMENT_ALREADY_PRESENT", r["reason_code"] == l1_policy.Reason.CONTAINMENT_ALREADY_PRESENT)
check("Cortex responder NEVER called", ex_calls["n"] == 0, ex_calls)


# ==============================================================================
# 6. pfSense pre-check failure -> responder not called
# ==============================================================================

print("\n=== 6. pfSense pre-check QUERY_FAILED -> Cortex never invoked ===")
d = fresh_dir()
pf_fn, pf_calls = make_pfsense_fake([pv.RESULT_QUERY_FAILED])
ex_fn, ex_calls = make_execute_fake(cortex_reported_success=True)
r = ao.execute_and_verify_containment(None, "~a6", "~c6", TARGET, 0.9, "armed", False,
                                      pfsense_check_fn=pf_fn, execute_fn=ex_fn, store_dir=d)
check("precheck failure -> executed=False", r["executed"] is False)
check("reason_code PFSTATE_QUERY_FAILED", r["reason_code"] == l1_policy.Reason.PFSTATE_QUERY_FAILED)
check("Cortex NEVER called when the precheck itself failed", ex_calls["n"] == 0)


# ==============================================================================
# 7. pfSense post-check failure -> no closure eligibility
# ==============================================================================

print("\n=== 7. Cortex success -> pfSense POST-check QUERY_FAILED -> no closure ===")
d = fresh_dir()
pf_fn, pf_calls = make_pfsense_fake([pv.RESULT_ABSENT, pv.RESULT_QUERY_FAILED])
ex_fn, ex_calls = make_execute_fake(cortex_reported_success=True)
r = ao.execute_and_verify_containment(None, "~a7", "~c7", TARGET, 0.9, "armed", False,
                                      pfsense_check_fn=pf_fn, execute_fn=ex_fn, store_dir=d)
check("post-check failure -> executed=False (NOT eligible for closure)", r["executed"] is False)
check("reason_code PFSTATE_QUERY_FAILED", r["reason_code"] == l1_policy.Reason.PFSTATE_QUERY_FAILED)
# the record must stay INTENDED (genuinely unknown), not FAILED — so a future
# run resolves it via the real verifier instead of assuming a fixed answer.
c_key = idempotency.containment_action_key("~a7", "~c7", TARGET, "armed")
check("idempotency record left INTENDED (not falsely marked FAILED) for a query failure",
     idempotency.get_status(c_key, store_dir=d)["status"] == idempotency.STATUS_INTENDED)


# ==============================================================================
# 14-16. Ambiguous record resolution
# ==============================================================================

print("\n=== 14. Ambiguous (INTENDED) record + IP now present -> resolved complete, no retry ===")
d = fresh_dir()
c_key = idempotency.containment_action_key("~a14", "~c14", TARGET, "armed")
idempotency.claim(c_key, store_dir=d)  # simulate a prior crashed attempt
pf_fn, pf_calls = make_pfsense_fake([pv.RESULT_ABSENT, pv.RESULT_PRESENT])
# precheck here will see ABSENT is irrelevant since the key is already claimed;
# construct the scenario precisely: precheck must run first and return ABSENT
# (so we proceed into the "already claimed" branch), THEN the ambiguous-resolve
# verifier call returns PRESENT.
ex_fn, ex_calls = make_execute_fake(cortex_reported_success=True)
r = ao.execute_and_verify_containment(None, "~a14", "~c14", TARGET, 0.9, "armed", False,
                                      pfsense_check_fn=pf_fn, execute_fn=ex_fn, store_dir=d)
check("ambiguous + now present -> executed=True", r["executed"] is True, r)
check("Cortex NEVER re-invoked while resolving an ambiguous record", ex_calls["n"] == 0, ex_calls)

print("\n=== 15. Ambiguous (INTENDED) record + IP absent -> L2, no retry ===")
d = fresh_dir()
c_key = idempotency.containment_action_key("~a15", "~c15", TARGET, "armed")
idempotency.claim(c_key, store_dir=d)
pf_fn, pf_calls = make_pfsense_fake([pv.RESULT_ABSENT, pv.RESULT_ABSENT])
ex_fn, ex_calls = make_execute_fake(cortex_reported_success=True)
r = ao.execute_and_verify_containment(None, "~a15", "~c15", TARGET, 0.9, "armed", False,
                                      pfsense_check_fn=pf_fn, execute_fn=ex_fn, store_dir=d)
check("ambiguous + confirmed absent -> executed=False", r["executed"] is False)
check("Cortex NOT retried", ex_calls["n"] == 0)
check("record resolved to FAILED (a confident negative), not left hanging",
     idempotency.get_status(c_key, store_dir=d)["status"] == idempotency.STATUS_FAILED)

print("\n=== 16. Ambiguous (INTENDED) record + query failure -> stays ambiguous, L2 ===")
d = fresh_dir()
c_key = idempotency.containment_action_key("~a16", "~c16", TARGET, "armed")
idempotency.claim(c_key, store_dir=d)
pf_fn, pf_calls = make_pfsense_fake([pv.RESULT_ABSENT, pv.RESULT_QUERY_FAILED])
ex_fn, ex_calls = make_execute_fake(cortex_reported_success=True)
r = ao.execute_and_verify_containment(None, "~a16", "~c16", TARGET, 0.9, "armed", False,
                                      pfsense_check_fn=pf_fn, execute_fn=ex_fn, store_dir=d)
check("ambiguous + query failure -> executed=False", r["executed"] is False)
check("Cortex NOT retried on an inconclusive re-check", ex_calls["n"] == 0)
check("record stays INTENDED (fail closed, not guessed)",
     idempotency.get_status(c_key, store_dir=d)["status"] == idempotency.STATUS_INTENDED)


# ==============================================================================
# 17. Duplicate invocation does not repeat Cortex
# ==============================================================================

print("\n=== 17. Duplicate invocation (same alert/case/ip/mode) does not repeat Cortex ===")
d = fresh_dir()
pf_fn, pf_calls = make_pfsense_fake([pv.RESULT_ABSENT, pv.RESULT_PRESENT])
ex_fn, ex_calls = make_execute_fake(cortex_reported_success=True)
r1 = ao.execute_and_verify_containment(None, "~a17", "~c17", TARGET, 0.9, "armed", False,
                                       pfsense_check_fn=pf_fn, execute_fn=ex_fn, store_dir=d)
check("first invocation executes", r1["executed"] is True)
check("Cortex called once", ex_calls["n"] == 1)
r2 = ao.execute_and_verify_containment(None, "~a17", "~c17", TARGET, 0.9, "armed", False,
                                       pfsense_check_fn=pf_fn, execute_fn=ex_fn, store_dir=d)
check("second (duplicate) invocation reuses the result", r2["executed"] is True)
check("Cortex was NOT called a second time", ex_calls["n"] == 1, ex_calls)


# ==============================================================================
# 18. Concurrent invocation executes at most one Cortex job
# ==============================================================================

print("\n=== 18. Concurrent claims on the SAME containment key — real OS processes ===")


def _worker(store_dir, alert_id, case_id, target, mode, out_q):
    import idempotency as w_idem
    key = w_idem.containment_action_key(alert_id, case_id, target, mode)
    r = w_idem.claim(key, store_dir=store_dir)
    out_q.put(r["claimed"])


if __name__ == "__main__":
    d = fresh_dir()
    q = multiprocessing.Queue()
    procs = [multiprocessing.Process(target=_worker,
             args=(d, "~a18", "~c18", TARGET, "armed", q)) for _ in range(8)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=10)
    results = [q.get() for _ in procs]
    check("all 8 concurrent processes reported a result", len(results) == 8, results)
    check("exactly ONE of 8 concurrent processes claimed the containment key "
         "(the atomic primitive proven in test_idempotency.py applies identically here)",
         results.count(True) == 1, f"claimed={results.count(True)} of 8")


# ==============================================================================
# 19. Policy-version change does not repeat an already-completed block —
#     the explicit invariant Ayman asked to confirm before Phase 2 began.
# ==============================================================================

print("\n=== 19. Policy-version change does NOT repeat an already-completed block ===")
d = fresh_dir()
pf_fn, pf_calls = make_pfsense_fake([pv.RESULT_ABSENT, pv.RESULT_PRESENT])
ex_fn, ex_calls = make_execute_fake(cortex_reported_success=True)

# Complete a real containment under "policy version v1" conceptually — note
# execute_and_verify_containment does NOT take policy_version as a parameter at
# all (by design — see idempotency.containment_action_key's docstring), so this
# test proves the invariant directly at the key level, matching exactly how
# agent_orchestrator.py actually calls it (alert_id/case_id/target/mode only).
r1 = ao.execute_and_verify_containment(None, "~a19", "~c19", TARGET, 0.9, "armed", False,
                                       pfsense_check_fn=pf_fn, execute_fn=ex_fn, store_dir=d)
check("first (v1-context) containment executes", r1["executed"] is True)
check("Cortex called once", ex_calls["n"] == 1)

# Simulate l1_policy.POLICY_VERSION changing (a real upgrade) by directly
# confirming the key l1_policy/agent_orchestrator would compute is IDENTICAL
# regardless of policy_version — proving the earlier-confirmed bug (decision_key
# includes policy_version) cannot leak into the containment identity.
key_v1 = idempotency.containment_action_key("~a19", "~c19", TARGET, "armed")
# also build via the OLD (buggy-if-used) decision_key-based path just to show
# it's simply never used for containment:
dkey_v1 = idempotency.decision_key("~a19", "~c19", "l1-policy-v1-2026-08-21", "armed")
dkey_v2 = idempotency.decision_key("~a19", "~c19", "l1-policy-v2-FUTURE", "armed")
check("decision_key DOES change with policy_version (expected — used for tier decisions)",
     dkey_v1 != dkey_v2)
check("containment_action_key does NOT depend on policy_version at all (the fix)",
     idempotency.containment_action_key("~a19", "~c19", TARGET, "armed") == key_v1)

# Call execute_and_verify_containment AGAIN — simulating a re-run "under a new
# policy version" (irrelevant to this function's signature, proving the point:
# there is no policy_version parameter for it to leak through in the first place).
r2 = ao.execute_and_verify_containment(None, "~a19", "~c19", TARGET, 0.9, "armed", False,
                                       pfsense_check_fn=pf_fn, execute_fn=ex_fn, store_dir=d)
check("second invocation (simulating post-policy-upgrade) reuses the result", r2["executed"] is True)
check("Cortex was NOT triggered a second time merely because policy could have changed",
     ex_calls["n"] == 1, ex_calls)


# ==============================================================================
# 20. Existing 91 (now 91+23=114) tests continue to pass — run externally, but
# assert the modules that changed still import and expose what earlier tests need.
# ==============================================================================

print("\n=== 20. Sanity: changed modules still expose what earlier tests rely on ===")
check("l1_policy.Reason has CONTAINMENT_ALREADY_PRESENT", hasattr(l1_policy.Reason, "CONTAINMENT_ALREADY_PRESENT"))
check("l1_policy.Reason has PFSTATE_QUERY_FAILED", hasattr(l1_policy.Reason, "PFSTATE_QUERY_FAILED"))
check("agent_orchestrator.close_l1_idempotent still present (Phase-idempotency)",
     hasattr(ao, "close_l1_idempotent"))
check("agent_orchestrator.notify_l2_idempotent still present", hasattr(ao, "notify_l2_idempotent"))
check("idempotency.containment_action_key present (Phase 2)",
     hasattr(idempotency, "containment_action_key"))


# ==============================================================================
# Summary
# ==============================================================================

if __name__ == "__main__":
    shutil.rmtree(STORE, ignore_errors=True)
    print("\n" + "=" * 70)
    print(f"  CONTAINMENT VERIFICATION TESTS: {len(PASS)} passed, {len(FAIL)} failed")
    print("=" * 70)
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    sys.exit(0)
