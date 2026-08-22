#!/usr/bin/env python3
"""
Tests for idempotency.py — the composite idempotency store.

PURE. No network, no live TheHive/Cortex/pfSense/Ollama. All state lives in a
throwaway temp directory removed at the end of the run. The concurrency test
spawns REAL OS processes (multiprocessing) to prove cross-process atomicity —
not just sequential in-process calls.

Run: ./.venv/bin/python test_idempotency.py
"""
import multiprocessing
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import idempotency as idem

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name); print(f"  PASS  {name}")
    else:
        FAIL.append(name); print(f"  FAIL  {name}  {detail}")


STORE = tempfile.mkdtemp(prefix="idem_test_")


def fresh_dir():
    d = tempfile.mkdtemp(prefix="idem_test_", dir=STORE)
    return d


# ==============================================================================
# 1. First processing succeeds
# ==============================================================================

print("\n=== 1. First claim succeeds ===")
d = fresh_dir()
r = idem.claim("case1:containment:1.2.3.4", store_dir=d)
check("first claim succeeds", r["claimed"] is True)
check("record status is INTENDED", r["record"]["status"] == idem.STATUS_INTENDED)


# ==============================================================================
# 2. Immediate duplicate is skipped
# ==============================================================================

print("\n=== 2. Immediate duplicate claim is rejected ===")
r2 = idem.claim("case1:containment:1.2.3.4", store_dir=d)
check("second claim on same key fails", r2["claimed"] is False)
idem.complete("case1:containment:1.2.3.4", idem.STATUS_COMPLETED, store_dir=d)
r3 = idem.claim("case1:containment:1.2.3.4", store_dir=d)
check("claim after completion still fails (already resolved)", r3["claimed"] is False)
check("resolved record shows COMPLETED", r3["record"]["status"] == idem.STATUS_COMPLETED)


# ==============================================================================
# 3. Duplicate after simulated restart is skipped
# ==============================================================================

print("\n=== 3. Duplicate survives a simulated process restart ===")
d = fresh_dir()
idem.claim("case2:closure:true-positive", store_dir=d)
idem.complete("case2:closure:true-positive", idem.STATUS_COMPLETED, store_dir=d)
# Simulate a restart: reload the module fresh (no shared Python object state at
# all — the ONLY thing carried across is the store_dir path on disk).
import importlib
idem_restarted = importlib.reload(idem)
r = idem_restarted.claim("case2:closure:true-positive", store_dir=d)
check("post-restart duplicate still rejected", r["claimed"] is False)
check("post-restart record still shows COMPLETED", r["record"]["status"] == idem.STATUS_COMPLETED)
idem = idem_restarted  # keep using the reloaded module for the rest of the file


# ==============================================================================
# 4. Concurrent duplicate processing — real OS processes, one owner only
# ==============================================================================

print("\n=== 4. Concurrent claim from real OS processes — exactly one owner ===")


def _worker(store_dir, key, result_queue):
    import idempotency as w_idem
    r = w_idem.claim(key, store_dir=store_dir)
    result_queue.put(r["claimed"])


if __name__ == "__main__":
    d = fresh_dir()
    key = "case3:containment:9.9.9.9"
    q = multiprocessing.Queue()
    procs = [multiprocessing.Process(target=_worker, args=(d, key, q)) for _ in range(8)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=10)
    results = [q.get() for _ in procs]
    check("exactly 8 workers reported a result", len(results) == 8, results)
    check("exactly ONE of 8 concurrent processes claimed the key",
         results.count(True) == 1, f"claimed={results.count(True)} of 8")


# ==============================================================================
# 5. Same alert, different action types stay independently tracked
# ==============================================================================

print("\n=== 5. Different action types on the same decision key are independent ===")
d = fresh_dir()
dkey = idem.decision_key("~alert1", "~case1", "policy-v1", "armed")
k_contain = idem.action_key(dkey, "containment", "202.61.130.163")
k_close = idem.action_key(dkey, "closure", "true-positive")
k_email = idem.action_key(dkey, "email", "l1-contained")
check("containment and closure keys differ", k_contain != k_close)
r_c = idem.claim(k_contain, store_dir=d)
r_l = idem.claim(k_close, store_dir=d)
r_e = idem.claim(k_email, store_dir=d)
check("containment claim independent", r_c["claimed"] is True)
check("closure claim independent", r_l["claimed"] is True)
check("email claim independent", r_e["claimed"] is True)
idem.complete(k_contain, idem.STATUS_COMPLETED, store_dir=d)
check("completing containment does not affect closure status",
     idem.get_status(k_close, store_dir=d)["status"] == idem.STATUS_INTENDED)


# ==============================================================================
# 6-9. Duplicate containment / closure / assignment / email prevented
# ==============================================================================

print("\n=== 6-9. Duplicate action prevention, per action type ===")
d = fresh_dir()
dkey = idem.decision_key("~a2", "~c2", "policy-v1", "armed")
for action, detail in [("containment", "1.1.1.1"), ("closure", "true-positive"),
                       ("assignment", "soc-l2"), ("email", "l1-contained")]:
    ak = idem.action_key(dkey, action, detail)
    first = idem.claim(ak, store_dir=d)
    idem.complete(ak, idem.STATUS_COMPLETED, store_dir=d)
    second = idem.claim(ak, store_dir=d)
    check(f"duplicate {action} prevented", first["claimed"] is True and second["claimed"] is False)


# ==============================================================================
# 10. Ambiguous containment checks external state before retry
# ==============================================================================

print("\n=== 10. Ambiguous (INTENDED, never completed) forces independent verification ===")
d = fresh_dir()
ak = "case4:containment:5.5.5.5"
idem.claim(ak, store_dir=d)   # claimed, then process "crashed" — never completed

calls = {"n": 0}
def verify_says_unknown():
    calls["n"] += 1
    return "unknown"

result = idem.resolve_ambiguous(ak, verify_says_unknown, store_dir=d)
check("verify_fn was actually called (not bypassed)", calls["n"] == 1)
check("unknown verification leaves it unresolved (fail closed)", result["resolved"] is False)
check("status still INTENDED after an inconclusive check",
     idem.get_status(ak, store_dir=d)["status"] == idem.STATUS_INTENDED)

def verify_says_completed():
    return "completed"

result2 = idem.resolve_ambiguous(ak, verify_says_completed, store_dir=d)
check("a conclusive 'completed' verification resolves it", result2["resolved"] is True)
check("status now COMPLETED after independent confirmation",
     idem.get_status(ak, store_dir=d)["status"] == idem.STATUS_COMPLETED)

# and a case where independent verification finds it actually did NOT happen:
ak2 = "case4:containment:6.6.6.6"
idem.claim(ak2, store_dir=d)
result3 = idem.resolve_ambiguous(ak2, lambda: "failed", store_dir=d)
check("a conclusive 'failed' verification resolves to FAILED, not silently retried",
     idem.get_status(ak2, store_dir=d)["status"] == idem.STATUS_FAILED)


# ==============================================================================
# 11 & 12. Tier decision: existing closure/assignment prevents re-action;
#           L2 case cannot transition to automatic L1 closure
# ==============================================================================

print("\n=== 11-12. Tier-decision immutability — L2 can never become L1 later ===")
d = fresh_dir()
dkey = idem.decision_key("~a3", "~c3", "policy-v1", "armed")
r1 = idem.record_tier_decision(dkey, "L2", detail={"reason": "low confidence"}, store_dir=d)
check("first tier-decision recording succeeds", r1["recorded_now"] is True)
check("recorded tier is L2", r1["tier"] == "L2")

# A later retry (e.g. re-processing the same alert) tries to record L1 instead —
# this must NOT overwrite the existing L2 decision.
r2 = idem.record_tier_decision(dkey, "L1", detail={"reason": "retry got a better verdict"},
                               store_dir=d)
check("second attempt does NOT record a new decision", r2["recorded_now"] is False)
check("tier remains L2 — cannot be flipped to L1 by a retry", r2["tier"] == "L2")
check("get_tier_decision agrees: still L2", idem.get_tier_decision(dkey, store_dir=d) == "L2")


# ==============================================================================
# 13. Corrupted/unreadable state fails closed
# ==============================================================================

print("\n=== 13. Corrupted record fails CLOSED (raises, never silently proceeds) ===")
d = fresh_dir()
ak = "case5:containment:7.7.7.7"
idem.claim(ak, store_dir=d)
path = idem._store_path(d, ak)
with open(path, "w", encoding="utf-8") as fh:
    fh.write("{not valid json,,,")
raised = False
try:
    idem.get_status(ak, store_dir=d)
except idem.IdempotencyError:
    raised = True
check("corrupted record raises IdempotencyError on read", raised)

raised2 = False
try:
    idem.claim(ak, store_dir=d)   # file exists -> tries to read it -> should raise, not "claim" it fresh
except idem.IdempotencyError:
    raised2 = True
check("corrupted record raises on claim() too (never silently re-claimed)", raised2)


# ==============================================================================
# 14. Policy-version change is recorded without repeating completed destructive actions
# ==============================================================================

print("\n=== 14. Policy-version change gets its OWN key space (no accidental repeat) ===")
d = fresh_dir()
dkey_v1 = idem.decision_key("~a4", "~c4", "l1-policy-v1", "armed")
dkey_v2 = idem.decision_key("~a4", "~c4", "l1-policy-v2", "armed")
check("different policy versions produce different decision keys", dkey_v1 != dkey_v2)

k1 = idem.action_key(dkey_v1, "containment", "8.8.8.8")
idem.claim(k1, store_dir=d)
idem.complete(k1, idem.STATUS_COMPLETED, store_dir=d)

# under the NEW policy version, the same case/IP is a genuinely fresh key —
# it can be independently evaluated (not silently blocked forever by v1's record)
k2 = idem.action_key(dkey_v2, "containment", "8.8.8.8")
r = idem.claim(k2, store_dir=d)
check("new policy version can claim its own action (not blocked by old version's record)",
     r["claimed"] is True)
# but the OLD version's completed record is untouched — not "repeated"/re-run
check("old policy version's completed record is unchanged",
     idem.get_status(k1, store_dir=d)["status"] == idem.STATUS_COMPLETED)


# ==============================================================================
# Summary
# ==============================================================================

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print(f"  IDEMPOTENCY TESTS: {len(PASS)} passed, {len(FAIL)} failed")
    print("=" * 70)
    shutil.rmtree(STORE, ignore_errors=True)
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    sys.exit(0)
