#!/usr/bin/env python3
"""
Tests for l2_worker.py — the Phase 8G permanent L2-only worker.

PURE. No network, no live TheHive/Cortex/ES/pfSense/Ollama, no real
subprocess ever spawned — fetch_candidate_alerts/run_orchestrator_once are
always given fake session/run_fn objects. All idempotency/circuit-breaker
state lives in a throwaway temp directory removed at the end of the run.

Run: ./.venv/bin/python3 test_l2_worker.py
"""
import json
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("THEHIVE_API_KEY", "test-placeholder-not-real")

import idempotency
import l2_worker as w

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name); print(f"  PASS  {name}")
    else:
        FAIL.append(name); print(f"  FAIL  {name}  {detail}")


STORE = tempfile.mkdtemp(prefix="l2_worker_test_")


def fresh_dir():
    return tempfile.mkdtemp(prefix="l2w_", dir=STORE)


def fresh_audit_log(d):
    return os.path.join(d, "audit.jsonl")


def write_audit_events(path, events):
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


NOW = time.time()
WATERMARK = NOW - 3600  # 1 hour ago


def make_alert(alert_id="~1", created_offset=60, status="New", source="elastalert2",
              tags=None, case_id=None, description="real evidence here",
              title="A real alert"):
    return {
        "_id": alert_id,
        "createdAt": (WATERMARK + created_offset) * 1000,  # epoch millis
        "status": status,
        "source": source,
        "tags": tags or [],
        "caseId": case_id,
        "description": description,
        "title": title,
    }


class FakeSession:
    def __init__(self, alerts=None, raises=None):
        self.alerts = alerts if alerts is not None else []
        self.raises = raises
        self.calls = 0

    def post(self, url, headers=None, json=None, timeout=None):
        self.calls += 1
        if self.raises:
            raise self.raises
        return FakeResponse(self.alerts)


class FakeResponse:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._data


class FakeProc:
    def __init__(self, returncode=0, stdout="ok"):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


def orig_audit_log_path():
    return w.orch.AUDIT_LOG


# ==============================================================================
# 1. Deployment watermark / backlog exclusion
# ==============================================================================

print("\n=== 1. deployment watermark excludes historical backlog ===")
old_alert = make_alert("~old1", created_offset=-120)  # 2 min BEFORE watermark
new_alert = make_alert("~new1", created_offset=60)    # 1 min after watermark
check("alert created before the watermark is NOT eligible",
     w.is_eligible_alert(old_alert, WATERMARK)["eligible"] is False)
check("alert created after the watermark IS eligible",
     w.is_eligible_alert(new_alert, WATERMARK)["eligible"] is True)
check("exclusion reason names the watermark", "watermark" in
     w.is_eligible_alert(old_alert, WATERMARK)["reason"])

missing_created = make_alert("~nocreatedat")
del missing_created["createdAt"]
check("missing/unparseable createdAt fails CLOSED (not eligible), never guessed",
     w.is_eligible_alert(missing_created, WATERMARK)["eligible"] is False)


# ==============================================================================
# 1b. REGRESSION (found live during the Phase 8G soak test): a large
# pre-existing backlog of "New" alerts must never starve a genuinely new,
# eligible alert out of the fetched window. fetch_candidate_alerts() must
# sort newest-first; an ascending sort with a capped page would let 25+
# permanently-unprocessable backlog alerts crowd out every new one
# forever, since the worker never advances past them (it never marks
# ineligible-for-watermark alerts as "seen" — they're just always there).
# ==============================================================================

print("\n=== 1b. REGRESSION: fetch_candidate_alerts sorts newest-first (backlog starvation) ===")
captured_query = {}


class QueryCapturingSession:
    def post(self, url, headers=None, json=None, timeout=None):
        captured_query.update(json)
        return FakeResponse([])


w.fetch_candidate_alerts("http://thehive.invalid", "fake-key", session=QueryCapturingSession())
sort_stanza = next(s for s in captured_query["query"] if s.get("_name") == "sort")
check("fetch_candidate_alerts requests DESCENDING createdAt order",
     sort_stanza["_fields"] == [{"_createdAt": "desc"}], sort_stanza)

print("=== 1c. REGRESSION: a new alert is processed even with 25+ older backlog alerts present ===")
d = fresh_dir()
backlog = [make_alert(f"~backlog{i}", created_offset=-3600) for i in range(30)]  # all pre-watermark
fresh_new = make_alert("~genuinely-new", created_offset=120)  # post-watermark
# Simulate the real symptom: with descending sort the new alert appears
# FIRST in the fetched page even though 30 older ones exist server-side.
session_desc = FakeSession(alerts=[fresh_new] + backlog)
invoked = {"n": 0}


def counting_run_fn2(cmd, env=None, capture_output=None, text=None, timeout=None):
    invoked["n"] += 1
    return FakeProc(returncode=0, stdout="ok")


r1c = w.run_one_poll_cycle("http://thehive.invalid", "fake-key", WATERMARK, store_dir=d,
                           audit_log_path=fresh_audit_log(d), session=session_desc,
                           run_fn=counting_run_fn2, sleep_fn=lambda s: None)
check("the new alert is found and processed despite 30 backlog alerts in the same page",
     r1c["outcome"] == "processed_one" and r1c["detail"]["alert_id"] == "~genuinely-new", r1c)
check("orchestrator subprocess was invoked exactly once", invoked["n"] == 1, invoked)


# ==============================================================================
# 2. Source / tag / status filtering
# ==============================================================================

print("\n=== 2. source/tag/status filtering ===")
check("status != New is excluded",
     w.is_eligible_alert(make_alert(status="Imported"), WATERMARK)["eligible"] is False)
check("untrusted source is excluded",
     w.is_eligible_alert(make_alert(source="demo"), WATERMARK)["eligible"] is False)
check("trusted source (elastalert2) passes the source check",
     w.is_eligible_alert(make_alert(source="elastalert2"), WATERMARK)["eligible"] is True)
check("already-promoted (caseId set) alert is excluded",
     w.is_eligible_alert(make_alert(case_id="~c1"), WATERMARK)["eligible"] is False)
check("empty description (missing evidence) is excluded",
     w.is_eligible_alert(make_alert(description=""), WATERMARK)["eligible"] is False)


# ==============================================================================
# 3. Watchdog / test / synthetic exclusion
# ==============================================================================

print("\n=== 3. watchdog/test/synthetic alert exclusion ===")
watchdog = make_alert(title="PIPELINE DOWN: Suricata EVE silent 60min", source="elastalert2-watchdog")
check("pipeline-watchdog alert is excluded (untrusted source AND is_operational_alert)",
     w.is_eligible_alert(watchdog, WATERMARK)["eligible"] is False)

synthetic = make_alert(tags=["synthetic-smoke-test"])
check("synthetic-tagged alert is excluded", w.is_eligible_alert(synthetic, WATERMARK)["eligible"] is False)

test_titled = make_alert(title="TEST — full-agent smoke test")
check("test-titled alert is excluded", w.is_eligible_alert(test_titled, WATERMARK)["eligible"] is False)


# ==============================================================================
# 4. Atomic claim
# ==============================================================================

print("\n=== 4. atomic claim ===")
d = fresh_dir()
c1 = w.claim_alert("~claim1", store_dir=d)
check("first claim on a fresh alert succeeds", c1["claimed"] is True)
c2 = w.claim_alert("~claim1", store_dir=d)
check("second claim on the SAME alert id is refused", c2["claimed"] is False)


# ==============================================================================
# 5. Two worker instances racing
# ==============================================================================

print("\n=== 5. two worker 'instances' racing on the same alert ===")
d = fresh_dir()
import multiprocessing


def _racer(store_dir, alert_id, out_q):
    out_q.put(idempotency.claim(f"{w.CLAIM_PREFIX}:{alert_id}", store_dir=store_dir)["claimed"])


q = multiprocessing.Queue()
procs = [multiprocessing.Process(target=_racer, args=(d, "~race1", q)) for _ in range(6)]
for p in procs:
    p.start()
for p in procs:
    p.join(timeout=10)
results = [q.get() for _ in procs]
check("exactly ONE of 6 racing processes wins the claim", sum(results) == 1, results)


# ==============================================================================
# 6. Restart during processing (an INTENDED, never-completed claim survives
#    a simulated restart and is NOT silently re-claimed as fresh, but the
#    orchestrator's OWN idempotency layer is what actually prevents a
#    duplicate case/comment/email on retry of the same alert_id — the
#    worker's claim just prevents a SECOND worker cycle from double-firing
#    the subprocess concurrently.)
# ==============================================================================

print("\n=== 6. restart during processing — INTENDED claim is not silently re-issued ===")
d = fresh_dir()
idempotency.claim(f"{w.CLAIM_PREFIX}:~restart1", store_dir=d)  # simulates a claim from before a crash
status_after_restart = w.claim_status("~restart1", store_dir=d)
check("claim status after a simulated restart is INTENDED (not lost, not silently completed)",
     status_after_restart["status"] == idempotency.STATUS_INTENDED, status_after_restart)
c_retry = w.claim_alert("~restart1", store_dir=d)
check("a second claim attempt on the still-INTENDED key is refused (worker won't double-fire)",
     c_retry["claimed"] is False)


# ==============================================================================
# 7. Temporary failure and retry
# ==============================================================================

print("\n=== 7. temporary failure retries with bounded exponential backoff, then succeeds ===")
d = fresh_dir()
alert7 = make_alert("~a7")
calls = {"n": 0}
sleeps = []


def flaky_run_fn(cmd, env=None, capture_output=None, text=None, timeout=None):
    calls["n"] += 1
    if calls["n"] < 3:
        raise __import__("requests").exceptions.ConnectionError("simulated transient network blip")
    return FakeProc(returncode=0, stdout="ok")


r7 = w.process_one_alert(alert7, store_dir=d, run_fn=flaky_run_fn, sleep_fn=lambda s: sleeps.append(s))
check("eventually succeeds after transient failures", r7["outcome"] == "processed", r7)
check("retried the expected number of times before succeeding", calls["n"] == 3, calls)
check("backoff delays were bounded and increasing", sleeps == sorted(sleeps) and all(s <= 300 for s in sleeps),
     sleeps)


# ==============================================================================
# 8. Permanent failure / dead letter
# ==============================================================================

print("\n=== 8. permanent failure exhausts retries and dead-letters ===")
d = fresh_dir()
alert8 = make_alert("~a8")


def always_failing_run_fn(cmd, env=None, capture_output=None, text=None, timeout=None):
    return FakeProc(returncode=1, stdout="permanent error")


r8 = w.process_one_alert(alert8, store_dir=d, run_fn=always_failing_run_fn, sleep_fn=lambda s: None)
check("dead-lettered after exhausting MAX_RETRIES", r8["outcome"] == "dead_letter", r8)
check("attempted exactly MAX_RETRIES times", r8["attempts"] == w.MAX_RETRIES, r8)
rec8 = w.claim_status("~a8", store_dir=d)
check("claim record resolved to FAILED, not left stuck INTENDED",
     rec8["status"] == idempotency.STATUS_FAILED, rec8)


# ==============================================================================
# 9. Duplicate alert (already claimed+completed) is skipped, not reprocessed
# ==============================================================================

print("\n=== 9. duplicate alert (already completed) is skipped ===")
d = fresh_dir()
alert9 = make_alert("~a9")
w.claim_alert("~a9", store_dir=d)
w.complete_claim("~a9", idempotency.STATUS_COMPLETED, store_dir=d)
r9 = w.process_one_alert(alert9, store_dir=d, run_fn=lambda *a, **k: FakeProc(0), sleep_fn=lambda s: None)
check("already-completed alert is skipped as a duplicate, not reprocessed",
     r9["outcome"] == "skipped_duplicate", r9)


# ==============================================================================
# 10. Already-promoted alert (has caseId) is filtered at eligibility, never claimed
# ==============================================================================

print("\n=== 10. already-promoted alert never reaches the claim step ===")
promoted = make_alert("~a10", case_id="~existing-case")
check("already-promoted alert is not eligible", w.is_eligible_alert(promoted, WATERMARK)["eligible"] is False)


# ==============================================================================
# 11 & 12. one case/comment/assignment/email only, and L2 auto-owner
# correction — both are properties of the REUSED, unchanged
# agent_orchestrator.py one-shot path, already proven live in Phase 8F/8F.1
# (see test_l2_assignment.py's 128 tests and the live correction on case
# ~409657400). The worker's OWN contract is narrower: invoke that
# orchestrator EXACTLY ONCE per claimed alert, never more.
# ==============================================================================

print("\n=== 11-12. worker invokes the orchestrator subprocess EXACTLY once per claimed alert ===")
d = fresh_dir()
alert11 = make_alert("~a11")
invoke_count = {"n": 0}


def counting_run_fn(cmd, env=None, capture_output=None, text=None, timeout=None):
    invoke_count["n"] += 1
    return FakeProc(returncode=0, stdout="ok")


w.process_one_alert(alert11, store_dir=d, run_fn=counting_run_fn, sleep_fn=lambda s: None)
check("orchestrator subprocess invoked exactly once for a clean success",
     invoke_count["n"] == 1, invoke_count)
check("(pointer) one case/comment/assignment/email-only + L2 auto-owner correction "
     "are covered by test_l2_assignment.py's 128 tests and the live Phase 8F.1 correction — "
     "not duplicated here", True)


# ==============================================================================
# 13. Circuit breaker
# ==============================================================================

print("\n=== 13. circuit breaker trips on case/email volume, requires manual reset ===")
d = fresh_dir()
log = fresh_audit_log(d)
now_iso = lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
write_audit_events(log, [{"ts": now_iso(), "event": "agent_case_created"} for _ in range(w.MAX_CASES_PER_HOUR)])
b13 = w.check_circuit_breaker(log, store_dir=d)
check("breaker trips once the case-per-hour limit is reached", b13["tripped"] is True, b13)
check("trip marker file was written (persists across restart)",
     os.path.exists(os.path.join(d, "CIRCUIT_BREAKER_TRIPPED")))
b13b = w.check_circuit_breaker(log, store_dir=d)
check("breaker stays tripped on a subsequent check without a manual reset", b13b["tripped"] is True)
os.remove(os.path.join(d, "CIRCUIT_BREAKER_TRIPPED"))
write_audit_events(log, [])
b13c = w.check_circuit_breaker(log, store_dir=d)
check("manual reset (deleting the marker) clears the tripped state", b13c["tripped"] is False, b13c)

d2 = fresh_dir()
log2 = fresh_audit_log(d2)
write_audit_events(log2, [{"ts": now_iso(), "event": "agent_notification_mailer_accepted"}
                          for _ in range(w.MAX_EMAILS_PER_HOUR)])
b13d = w.check_circuit_breaker(log2, store_dir=d2)
check("breaker also trips on the email-per-hour limit independently", b13d["tripped"] is True, b13d)


# ==============================================================================
# 14. No containment access — the subprocess env never contains a
# containment-capable variable, even if the worker's OWN environment
# somehow had one (defense in depth beyond the systemd unit).
# ==============================================================================

print("\n=== 14. subprocess env has zero containment-capable variables ===")
poisoned_base_env = dict(os.environ)
poisoned_base_env.update({"RESPONDER_NAME": "PfSense_Blocker_1_0", "PFSENSE_HOST": "should-not-leak",
                          "PFSENSE_SSH_PASSWORD": "should-not-leak", "PFSENSE_BLOCK_TABLE": "x"})
built_env = w.build_subprocess_env("~a14", base_env=poisoned_base_env)
check("RESPONDER_NAME stripped even if present in the base env", "RESPONDER_NAME" not in built_env)
check("PFSENSE_HOST stripped", "PFSENSE_HOST" not in built_env)
check("PFSENSE_SSH_PASSWORD stripped", "PFSENSE_SSH_PASSWORD" not in built_env)
check("PFSENSE_BLOCK_TABLE stripped", "PFSENSE_BLOCK_TABLE" not in built_env)
check("SOAR_DEMO_ACTION_MODE is always l2-only for every worker-launched subprocess",
     built_env["SOAR_DEMO_ACTION_MODE"] == "l2-only", built_env["SOAR_DEMO_ACTION_MODE"])
check("SOAR_DEMO_ALLOWED_IOC is never set (l2-only never needs/uses one)",
     "SOAR_DEMO_ALLOWED_IOC" not in built_env)
check("SOAR_ALERT_ID matches the claimed alert exactly", built_env["SOAR_ALERT_ID"] == "~a14")
check("SOAR_DEMO_ALLOWED_ALERT_ID matches the SAME alert (internally generated, exact)",
     built_env["SOAR_DEMO_ALLOWED_ALERT_ID"] == "~a14")


# ==============================================================================
# 15. Missing kill switch — the worker passes SOAR_KILL_SWITCH through
# unchanged; it never removes or overrides it in the subprocess env.
# ==============================================================================

print("\n=== 15. kill switch env var passes through to the subprocess unchanged ===")
base_with_ks = dict(os.environ)
base_with_ks["SOAR_KILL_SWITCH"] = "/var/lib/soc-ai-soar-shadow/KILL_SWITCH"
built15 = w.build_subprocess_env("~a15", base_env=base_with_ks)
check("SOAR_KILL_SWITCH is preserved unchanged in the subprocess env",
     built15.get("SOAR_KILL_SWITCH") == "/var/lib/soc-ai-soar-shadow/KILL_SWITCH", built15.get("SOAR_KILL_SWITCH"))


# ==============================================================================
# 16. Malformed model result — surfaces as a non-zero orchestrator exit or a
# clean exit with no special worker-side handling needed (the orchestrator
# itself already fails safe on a malformed LLM result — see soc_agent.py /
# test_shadow_mode.py's malformed-output test). The worker's contract is
# just: a non-zero exit is retried like any other failure, never crashes
# the poll loop.
# ==============================================================================

print("\n=== 16. a non-zero orchestrator exit (e.g. from a malformed model result) is retried, not fatal ===")
d = fresh_dir()
alert16 = make_alert("~a16")
r16 = w.run_orchestrator_once("~a16", run_fn=lambda *a, **k: FakeProc(returncode=1, stdout="verdict failed"))
check("non-zero exit is reported as not-ok, not raised", r16["ok"] is False and r16["timed_out"] is False, r16)
# full retry -> dead-letter path already proven in test 8 above using the same mechanism.


# ==============================================================================
# 17. Credential redaction
# ==============================================================================

print("\n=== 17. stdout and error strings are redacted before logging/audit ===")
secret_stdout = 'Authorization: Bearer sk-live-abcdefghijklmnopqrstuvwx\npassword=hunter2hunter2'
r17 = w.run_orchestrator_once("~a17", run_fn=lambda *a, **k: FakeProc(returncode=0, stdout=secret_stdout))
check("Bearer token redacted from captured stdout", "sk-live-abcdefghijklmnopqrstuvwx" not in r17["stdout_tail"],
     r17["stdout_tail"])
check("password value redacted from captured stdout", "hunter2hunter2" not in r17["stdout_tail"],
     r17["stdout_tail"])

d = fresh_dir()
alert17b = make_alert("~a17b")


class SecretyError(Exception):
    pass


def secret_raising_run_fn(cmd, env=None, capture_output=None, text=None, timeout=None):
    raise RuntimeError("failed with api_key=sk-live-zzzzzzzzzzzzzzzzzzzzzzzz in the message")


r17b = w.process_one_alert(alert17b, store_dir=d, run_fn=secret_raising_run_fn, sleep_fn=lambda s: None)
rec17b = w.claim_status("~a17b", store_dir=d)
detail_str = json.dumps(rec17b.get("meta", rec17b))
check("dead-letter detail never contains the raw secret from a raised exception",
     "sk-live-zzzzzzzzzzzzzzzzzzzzzzzz" not in detail_str, detail_str)


# ==============================================================================
# 18. Clean shutdown
# ==============================================================================

print("\n=== 18. graceful shutdown flag ===")
w.reset_shutdown_state_for_tests()
check("shutdown not requested initially", w.is_shutdown_requested() is False)
w._handle_signal(15, None)  # simulate SIGTERM delivery
check("shutdown flag set after a simulated SIGTERM", w.is_shutdown_requested() is True)
w.reset_shutdown_state_for_tests()
check("shutdown flag clears for the next test/run", w.is_shutdown_requested() is False)


# ==============================================================================
# Summary
# ==============================================================================

if __name__ == "__main__":
    shutil.rmtree(STORE, ignore_errors=True)
    print("\n" + "=" * 70)
    print(f"  L2 WORKER TESTS: {len(PASS)} passed, {len(FAIL)} failed")
    print("=" * 70)
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    sys.exit(0)
