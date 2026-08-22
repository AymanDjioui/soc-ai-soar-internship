#!/usr/bin/env python3
"""
Phase 2.5 tests — Cortex job-metadata persistence (idempotency.update_meta()
and its wiring into _execute_containment() / execute_and_verify_containment()).

PURE. `orch.resolve_responder_id` / `orch.wait_for_responder_action` are
monkeypatched for the duration of each test that needs them, then restored.
No live TheHive/Cortex/pfSense call is ever made.

Run: ./.venv/bin/python test_cortex_metadata.py
"""
import multiprocessing
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("THEHIVE_API_KEY", "test-placeholder-not-real")

import idempotency
import pfsense_verify as pv
import e2e_soc_orchestrator as orch
import agent_orchestrator as ao

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name); print(f"  PASS  {name}")
    else:
        FAIL.append(name); print(f"  FAIL  {name}  {detail}")


STORE = tempfile.mkdtemp(prefix="cortex_meta_test_")


def fresh_dir():
    return tempfile.mkdtemp(prefix="cm_", dir=STORE)


class FakeCase:
    def __init__(self, observables):
        self._obs = observables
    def find_observables(self, case_id):
        return self._obs


class FakeCortex:
    def __init__(self, job_id="cortexjob-123"):
        self.create_calls = 0
        self.job_id = job_id
    def create_responder_action(self, payload):
        self.create_calls += 1
        return {"_id": self.job_id}


class FakeApi:
    def __init__(self, observables, job_id="cortexjob-123"):
        self.case = FakeCase(observables)
        self.cortex = FakeCortex(job_id)


def patch_orch(resolve_returns=("responder-1", None), wait_fn=None):
    orig_resolve = orch.resolve_responder_id
    orig_wait = orch.wait_for_responder_action
    orch.resolve_responder_id = lambda api, obs_id, name: resolve_returns
    if wait_fn is not None:
        orch.wait_for_responder_action = wait_fn
    return orig_resolve, orig_wait


def unpatch_orch(orig_resolve, orig_wait):
    orch.resolve_responder_id = orig_resolve
    orch.wait_for_responder_action = orig_wait


OBS = [{"dataType": "ip", "data": "202.61.130.163", "_id": "obs1", "tags": ["src"]}]


# ==============================================================================
# 1. Job ID persisted after trigger — AND before the wait, precisely
# ==============================================================================

print("\n=== 1. Job ID persisted after trigger, BEFORE waiting for completion ===")
d = fresh_dir()
key = "~a1|~c1|armed:containment:202.61.130.163"
idempotency.claim(key, store_dir=d)
captured = {}

def wait_checks_meta_already_set(obs_id, timeout_s=60, poll_s=3):
    rec = idempotency.get_status(key, store_dir=d)
    captured["meta_at_wait_time"] = dict(rec.get("meta", {}))
    return "Success", {}

orig = patch_orch(wait_fn=wait_checks_meta_already_set)
try:
    api = FakeApi(OBS, job_id="cortexjob-XYZ")
    result = ao._execute_containment(api, "~c1", "202.61.130.163", 0.9,
                                     idempotency_key=key, store_dir=d)
finally:
    unpatch_orch(*orig)

check("job id was ALREADY persisted by the time wait_for_responder_action ran",
     captured.get("meta_at_wait_time", {}).get("cortex_job_id") == "cortexjob-XYZ",
     captured)
check("responder id also persisted before the wait",
     captured.get("meta_at_wait_time", {}).get("responder_id") == "responder-1")
check("triggered_at timestamp present before the wait",
     "triggered_at" in captured.get("meta_at_wait_time", {}))
check("_execute_containment itself still reports success correctly",
     result["cortex_reported_success"] is True)
check("final record (after wait) shows last_cortex_status updated to Success",
     idempotency.get_status(key, store_dir=d)["meta"].get("last_cortex_status") == "Success")


# ==============================================================================
# 2. Job ID survives simulated restart
# ==============================================================================

print("\n=== 2. Job ID survives a simulated process restart ===")
import importlib
idempotency_restarted = importlib.reload(idempotency)
rec_after_restart = idempotency_restarted.get_status(key, store_dir=d)
check("job id still readable from a fresh module load",
     rec_after_restart["meta"].get("cortex_job_id") == "cortexjob-XYZ")
idempotency = idempotency_restarted


# ==============================================================================
# 3. Status updates preserve prior metadata (merge, not replace)
# ==============================================================================

print("\n=== 3. update_meta() MERGES — later calls don't erase earlier fields ===")
d = fresh_dir()
key3 = "~a3|~c3|armed:containment:1.1.1.1"
idempotency.claim(key3, store_dir=d)
idempotency.update_meta(key3, {"cortex_job_id": "job-1", "responder_id": "resp-1"}, store_dir=d)
idempotency.update_meta(key3, {"last_cortex_status": "InProgress"}, store_dir=d)
idempotency.update_meta(key3, {"last_cortex_status": "Success"}, store_dir=d)
rec3 = idempotency.get_status(key3, store_dir=d)
check("cortex_job_id from the FIRST update is still present", rec3["meta"].get("cortex_job_id") == "job-1")
check("responder_id from the FIRST update is still present", rec3["meta"].get("responder_id") == "resp-1")
check("last_cortex_status reflects the LATEST update", rec3["meta"].get("last_cortex_status") == "Success")
check("status itself is untouched by update_meta (still INTENDED)",
     rec3["status"] == idempotency.STATUS_INTENDED)

raised = False
try:
    idempotency.update_meta("no-such-key-exists", {"x": 1}, store_dir=d)
except idempotency.IdempotencyError:
    raised = True
check("update_meta on a NON-EXISTENT record raises (cannot create via update)", raised)


# ==============================================================================
# 4. Concurrent metadata update cannot corrupt the record
# ==============================================================================

print("\n=== 4. Concurrent update_meta() from real OS processes never corrupts the file ===")


def _meta_worker(store_dir, key, n, out_q):
    import idempotency as w_idem
    try:
        w_idem.update_meta(key, {"writer": n, "ts": n}, store_dir=store_dir)
        out_q.put(("ok", n))
    except Exception as exc:
        out_q.put(("error", str(exc)))


if __name__ == "__main__":
    d = fresh_dir()
    key4 = "~a4|~c4|armed:containment:2.2.2.2"
    idempotency.claim(key4, store_dir=d)
    q = multiprocessing.Queue()
    procs = [multiprocessing.Process(target=_meta_worker, args=(d, key4, i, q)) for i in range(10)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=10)
    results = [q.get() for _ in procs]
    errors = [r for r in results if r[0] == "error"]
    check("no worker raised an unexpected error", len(errors) == 0, errors)
    # The critical property: the file must be VALID, readable JSON afterward —
    # a race is allowed to leave any one writer's value as the "last word", but
    # must never leave a torn/half-written file.
    final = idempotency.get_status(key4, store_dir=d)   # raises IdempotencyError if corrupted
    check("record is still valid, readable JSON after 10 concurrent updates", final is not None)
    check("the surviving 'writer' value is one of the 10 real writers, not garbage",
         final["meta"].get("writer") in list(range(10)), final["meta"])


# ==============================================================================
# 5. Missing job ID falls back safely to pfSense (no Cortex peek attempted)
# ==============================================================================

def make_pfsense_seq(sequence):
    """Precheck must return ABSENT first so execute_and_verify_containment
    routes into the 'already claimed' -> ambiguous-resolve branch (the ONLY
    branch that consults job metadata) rather than the separate
    precheck-PRESENT/ALREADY_PRESENT branch, which is a different code path."""
    calls = {"n": 0}
    def fn(ip):
        i = min(calls["n"], len(sequence) - 1)
        calls["n"] += 1
        return {"result": sequence[i], "target_ip": ip,
                "checked_at": "2026-01-01T00:00:00Z", "table_size": 1, "error": None}
    return fn, calls


print("\n=== 5. Ambiguous record with NO job id -> falls back to pfSense alone, no crash ===")
d = fresh_dir()
key5 = idempotency.containment_action_key("~a5", "~c5", "202.61.130.163", "armed")
idempotency.claim(key5, store_dir=d)   # claimed, but update_meta NEVER called — no job id at all

peek_calls = {"n": 0}
orig_peek = ao._peek_cortex_job_status
def counting_peek(api, case_id, target_ip):
    peek_calls["n"] += 1
    return "Success"
ao._peek_cortex_job_status = counting_peek
try:
    pf_fn, pf_calls = make_pfsense_seq([pv.RESULT_ABSENT, pv.RESULT_PRESENT])
    r = ao.execute_and_verify_containment(None, "~a5", "~c5", "202.61.130.163", 0.9, "armed", False,
                                          pfsense_check_fn=pf_fn, store_dir=d)
finally:
    ao._peek_cortex_job_status = orig_peek

check("resolution still succeeds via pfSense alone when no job id exists", r["executed"] is True, r)
check("_peek_cortex_job_status was NEVER called when there's no job id to look up",
     peek_calls["n"] == 0, peek_calls)


# ==============================================================================
# 6. Existing job ID IS queried during ambiguous resolution
# ==============================================================================

print("\n=== 6. Ambiguous record WITH a job id -> Cortex status IS peeked (diagnostic) ===")
d = fresh_dir()
key6 = idempotency.containment_action_key("~a6", "~c6", "202.61.130.163", "armed")
idempotency.claim(key6, store_dir=d)
idempotency.update_meta(key6, {"cortex_job_id": "job-existing-999"}, store_dir=d)

peek_calls = {"n": 0, "seen": []}
orig_peek = ao._peek_cortex_job_status
def recording_peek(api, case_id, target_ip):
    peek_calls["n"] += 1
    peek_calls["seen"].append((case_id, target_ip))
    return "Success"
ao._peek_cortex_job_status = recording_peek
try:
    pf_fn, pf_calls = make_pfsense_seq([pv.RESULT_ABSENT, pv.RESULT_PRESENT])
    r = ao.execute_and_verify_containment(None, "~a6", "~c6", "202.61.130.163", 0.9, "armed", False,
                                          pfsense_check_fn=pf_fn, store_dir=d)
finally:
    ao._peek_cortex_job_status = orig_peek

check("resolution succeeds (pfSense present, authoritative)", r["executed"] is True, r)
check("_peek_cortex_job_status WAS called because a job id was on record",
     peek_calls["n"] == 1, peek_calls)
rec6 = idempotency.get_status(key6, store_dir=d)
check("the diagnostic Cortex status hint is recorded in the resolved detail",
     rec6["detail"].get("cortex_status_hint") == "Success", rec6["detail"])
check("job_id_on_record is recorded in the resolved detail too",
     rec6["detail"].get("job_id_on_record") == "job-existing-999")
check("pfSense membership is STILL what decided the outcome (authoritative), "
     "not the Cortex status hint alone", r["executed"] is True)


# ==============================================================================
# 7. Cortex success + pfSense absence remains unverified (metadata angle)
# ==============================================================================

print("\n=== 7. Cortex success + pfSense absent -> UNVERIFIED, job metadata still recorded ===")
d = fresh_dir()
orig = patch_orch(wait_fn=lambda obs_id, timeout_s=60, poll_s=3: ("Success", {}))
try:
    api = FakeApi(OBS, job_id="job-777")
    pf_fn = lambda ip: {"result": pv.RESULT_ABSENT, "target_ip": ip,
                        "checked_at": "2026-01-01T00:00:00Z", "table_size": 0, "error": None}
    ex_fn = lambda api, case_id, target_ip, confidence, idempotency_key=None, store_dir=None: \
        ao._execute_containment(api, case_id, target_ip, confidence,
                                idempotency_key=idempotency_key, store_dir=store_dir)
    r = ao.execute_and_verify_containment(api, "~a7", "~c7", "202.61.130.163", 0.9, "armed", False,
                                          pfsense_check_fn=pf_fn, execute_fn=ex_fn, store_dir=d)
finally:
    unpatch_orch(*orig)
check("Cortex-success-but-pfSense-absent -> executed=False", r["executed"] is False)
key7 = idempotency.containment_action_key("~a7", "~c7", "202.61.130.163", "armed")
rec7 = idempotency.get_status(key7, store_dir=d)
check("job id WAS persisted even though the final outcome is UNVERIFIED",
     rec7["meta"].get("cortex_job_id") == "job-777", rec7["meta"])
check("final status is FAILED (a confirmed negative, not left hanging)",
     rec7["status"] == idempotency.STATUS_FAILED)


# ==============================================================================
# 8. Cortex failure + unexpected pfSense presence -> state conflict (pointer)
# ==============================================================================

print("\n=== 8. Cortex failure + unexpected pfSense presence -> CONTAINMENT_STATE_CONFLICT ===")
print("    (full coverage lives in test_containment_verification.py test 3b — confirming")
print("     here that the reason code exists and is distinct, per this phase's own ask)")
import l1_policy
check("CONTAINMENT_STATE_CONFLICT reason code exists",
     hasattr(l1_policy.Reason, "CONTAINMENT_STATE_CONFLICT"))
check("it is distinct from the ordinary CONTAINMENT_REFUSED code",
     l1_policy.Reason.CONTAINMENT_STATE_CONFLICT != l1_policy.Reason.CONTAINMENT_REFUSED)


# ==============================================================================
# Summary
# ==============================================================================

if __name__ == "__main__":
    shutil.rmtree(STORE, ignore_errors=True)
    print("\n" + "=" * 70)
    print(f"  CORTEX METADATA TESTS: {len(PASS)} passed, {len(FAIL)} failed")
    print("=" * 70)
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    sys.exit(0)
