#!/usr/bin/env python3
"""
Phase 8D.1 shadow-mode side-effect audit — strict mock-based tests.

Proves that with SOAR_AGENT_DRY_RUN=1 / SOAR_AGENT_MODE=shadow / SOAR_DRY_RUN=1,
agent_orchestrator.process_alert_agent() (and the _process_alert_agent_shadow()
choke point it now routes to) NEVER performs an external mutation — not just
"never blocks", the stronger claim this audit was asked to prove.

Strategy: every TheHive/Cortex-mutating method on the fake API client raises
immediately if called (a "mutation trap"), so any code path this audit missed
turns into an immediate, loud test failure rather than a silent real HTTP call.
Reads are served from canned fixtures. The LLM itself is mocked at
soc_agent._call() — this test is about the ORCHESTRATION code's side effects,
not model behavior, and mocking at this boundary means zero network access
(no live Ollama/TheHive/ES/Cortex/pfSense contact) for the whole file, per the
offline-only safety boundary this audit was run under.

PURE. No network. No credentials. No real THEHIVE_API_KEY/ES_PASSWORD needed —
none are read, since every network-touching function is mocked out.

Run: ./.venv/bin/python3 test_shadow_mode.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Must be set BEFORE importing agent_orchestrator — AGENT_DRY_RUN/AGENT_ARMED
# are computed once, at import time, from these.
os.environ["SOAR_AGENT_DRY_RUN"] = "1"
os.environ["SOAR_AGENT_MODE"] = "shadow"
os.environ["SOAR_DRY_RUN"] = "1"
os.environ.setdefault("THEHIVE_URL", "http://unit-test.invalid:9000")
os.environ.setdefault("OLLAMA_BASE_URL", "http://unit-test.invalid:11434")

import agent_orchestrator as ao
import agent_tools as T
import e2e_soc_orchestrator as orch
import soc_agent as sa

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name); print(f"  PASS  {name}")
    else:
        FAIL.append(name); print(f"  FAIL  {name}  {detail}")


# ==============================================================================
# Fixtures — a mutation-trapping fake TheHive/Cortex client
# ==============================================================================

class MutationAttempted(AssertionError):
    pass


def _trap(method_name):
    def _raiser(*a, **kw):
        raise MutationAttempted(f"MUTATION ATTEMPTED IN SHADOW MODE: {method_name}"
                                 f"(args={a!r}, kwargs={kw!r})")
    return _raiser


class _Namespace:
    """Lets us attach arbitrary read/write methods per SDK sub-namespace."""


def make_fake_api(alert_id="~test1", observables=None):
    """
    A fake thehive4py-shaped API. Every mutation-capable method is a trap.
    Every read method returns a canned, clearly-synthetic value.
    """
    observables = observables if observables is not None else []

    api = _Namespace()

    api.alert = _Namespace()
    api.alert.get = lambda aid: {"_id": aid, "title": "SYNTHETIC TEST ALERT",
                                  "description": "unit-test fixture, not a real alert",
                                  "severity": 2, "tags": ["unit-test"]}
    api.alert.find_observables = lambda aid: observables
    api.alert.promote_to_case = _trap("api.alert.promote_to_case")
    api.alert.update = _trap("api.alert.update")

    api.case = _Namespace()
    api.case.get = lambda cid: {"_id": cid, "status": "Open", "tags": []}
    api.case.find_observables = lambda cid: observables
    api.case.update = _trap("api.case.update")

    api.comment = _Namespace()
    api.comment.create_in_case = _trap("api.comment.create_in_case")

    api.cortex = _Namespace()
    api.cortex.list_analyzers = lambda: [{"id": "abuseipdb-1", "name": "AbuseIPDB_1_0"}]
    api.cortex.list_responders = lambda **kw: [{"id": "responder-1", "name": "PfSense_Blocker_1_0"}]
    api.cortex.get_analyzer_job = _trap("api.cortex.get_analyzer_job")
    api.cortex.create_analyzer_job = _trap("api.cortex.create_analyzer_job")
    api.cortex.create_responder_action = _trap("api.cortex.create_responder_action")

    api.observable = _Namespace()
    api.observable.get = _trap("api.observable.get")

    api.user = _Namespace()
    api.user.find = lambda **kw: [{"login": "soc-l2@thehive.local", "status": "Ok"}]
    api.user.get_current = lambda: {"login": "svc-account"}

    return api


def make_fake_dry_run_requests_trap(monkeys):
    """Trap raw requests.post/put/patch/delete used by the fallback HTTP paths
    (post_case_comment's REST fallback, close_case_l1, trigger_mailer_responder)
    so even a bypass of the SDK layer is caught. Ollama calls are mocked at
    soc_agent._call() instead (never reach `requests` at all), so this is safe
    to apply globally for the duration of a test."""
    import requests as _requests

    def _blocked(method):
        def _inner(*a, **kw):
            raise MutationAttempted(f"MUTATION ATTEMPTED VIA RAW requests.{method}("
                                     f"args={a!r}, kwargs={kw!r})")
        return _inner

    originals = {m: getattr(_requests, m) for m in ("post", "put", "patch", "delete")}
    for m in originals:
        setattr(_requests, m, _blocked(m))
    monkeys.append((_requests, originals))


def restore_requests(monkeys):
    import requests as _requests
    for mod, originals in monkeys:
        for name, fn in originals.items():
            setattr(mod, name, fn)


AUDIT_EVENTS = []


def fake_audit(event, **fields):
    """Replaces orch.audit — records events in memory instead of touching disk,
    AND lets us assert a sanitized shadow audit trail was actually produced."""
    AUDIT_EVENTS.append({"event": event, **fields})


def mock_llm_sequence(*turns):
    """turns: list of dicts, each either an ACTION_SCHEMA-shaped step or the
    final VERDICT_SCHEMA-shaped verdict (whichever soc_agent.investigate asks
    for next). Replaces soc_agent._call with a stateful stub — no network."""
    remaining = list(turns)

    def _fake_call(messages, schema):
        if not remaining:
            raise AssertionError("mock LLM sequence exhausted — investigate() asked for "
                                  "more turns than the test provided")
        return json.dumps(remaining.pop(0))
    return _fake_call


# ==============================================================================
# 1. Registry / tool-availability check (requirement 4)
# ==============================================================================

print("\n=== 1. run_analyzer is inert without live case context (api=None) ===")
cortex_trap = make_fake_api()
result = T.run_analyzer("203.0.113.99", "GreyNoise", api=None, observables=None)
check("run_analyzer(api=None) returns not_wired, no exception", result.get("status") == "not_wired")

print("=== 1b. even with observables but api=None, still refuses (both required) ===")
result2 = T.run_analyzer("203.0.113.99", "GreyNoise", api=None,
                         observables=[{"dataType": "ip", "data": "203.0.113.99", "_id": "obs1"}])
check("run_analyzer(api=None, observables=[...]) still not_wired", result2.get("status") == "not_wired")

print("=== 1c. adversarial: LLM 'chooses' run_analyzer with attacker-supplied args — still inert ===")
sa._call = mock_llm_sequence(
    {"thought": "let me enrich this", "action": "run_analyzer",
     "observable": "203.0.113.99", "analyzer_name": "GreyNoise"},
    {"thought": "not_wired, concluding instead", "action": "conclude"},
    {"verdict": "malicious", "confidence": 0.9, "severity": "high",
     "mitre_technique": "T1046", "reason": "test", "key_evidence": "test"},
)
res = sa.investigate({"title": "t", "description": "d", "severity": 2, "tags": []},
                     observables=[], verbose=False, api=None)
check("investigate() with api=None never creates a Cortex job (no MutationAttempted raised, "
     "verdict still produced)", res.get("verdict") is not None, f"res={res}")
check("run_analyzer's not_wired result appears in the trace",
     any(step.get("result", {}).get("status") == "not_wired" for step in res.get("trace", [])))


# ==============================================================================
# 2. AGENT_ARMED / AGENT_DRY_RUN sanity (requirement 5)
# ==============================================================================

print("\n=== 2. module-level safety flags ===")
check("AGENT_DRY_RUN is True", ao.AGENT_DRY_RUN is True)
check("AGENT_ARMED is False", ao.AGENT_ARMED is False)


# ==============================================================================
# 3. Kill switch remains effective (unchanged by this audit's fix)
# ==============================================================================

print("\n=== 3. kill switch mechanism still works ===")
import tempfile
_fd, _ks_path = tempfile.mkstemp(prefix="shadow_test_kill_switch_")
os.close(_fd)
_orig_ks_env = os.environ.get("SOAR_KILL_SWITCH")
_orig_ks_file = orch.KILL_SWITCH_FILE
try:
    orch.KILL_SWITCH_FILE = _ks_path
    check("kill switch detected as active when file exists", orch.kill_switch_active() is True)
    os.remove(_ks_path)
    check("kill switch detected as inactive once removed", orch.kill_switch_active() is False)
finally:
    orch.KILL_SWITCH_FILE = _orig_ks_file
    if os.path.exists(_ks_path):
        os.remove(_ks_path)


# ==============================================================================
# 4. process_alert_agent() routes to shadow mode and performs ZERO mutations,
#    across malicious / benign / inconclusive / malformed-output scenarios.
# ==============================================================================

SCENARIOS = [
    ("malicious, high confidence, external IP",
     [{"thought": "concluding", "action": "conclude"}],
     {"verdict": "malicious", "confidence": 0.95, "severity": "critical",
      "mitre_technique": "T1190", "reason": "sqli", "key_evidence": "' OR 1=1--"},
     [{"dataType": "ip", "data": "203.0.113.50", "_id": "obs1", "tags": []}]),
    ("benign, high confidence",
     [{"thought": "concluding", "action": "conclude"}],
     {"verdict": "benign", "confidence": 0.95, "severity": "low",
      "mitre_technique": "N/A", "reason": "ssdp noise", "key_evidence": "SSDP"},
     []),
    ("inconclusive, low confidence",
     [{"thought": "concluding", "action": "conclude"}],
     {"verdict": "inconclusive", "confidence": 0.3, "severity": "low",
      "mitre_technique": "N/A", "reason": "unclear", "key_evidence": "n/a"},
     []),
]

print("\n=== 4. process_alert_agent() end-to-end — zero mutations across verdict types ===")
for label, action_turns, verdict_turn, obs in SCENARIOS:
    AUDIT_EVENTS.clear()
    api = make_fake_api(observables=obs)
    monkeys = []
    make_fake_dry_run_requests_trap(monkeys)
    orig_audit = orch.audit
    orch.audit = fake_audit
    sa._call = mock_llm_sequence(*action_turns, verdict_turn)
    try:
        ao.process_alert_agent(api, {"_id": "~shadow-test", "title": f"TEST — {label}",
                                     "description": "synthetic", "severity": 2, "tags": []})
        check(f"[{label}] process_alert_agent completes without raising", True)
    except MutationAttempted as exc:
        check(f"[{label}] process_alert_agent completes without raising", False, str(exc))
    finally:
        orch.audit = orig_audit
        restore_requests(monkeys)

    events = [e["event"] for e in AUDIT_EVENTS]
    check(f"[{label}] a shadow verdict audit event was produced", "agent_shadow_verdict" in events,
         f"events={events}")
    check(f"[{label}] a shadow disposition audit event was produced",
         "agent_shadow_disposition" in events, f"events={events}")
    check(f"[{label}] no case-created event (no real case was ever promoted)",
         "agent_case_created" not in events, f"events={events}")
    check(f"[{label}] no armed-path tier-decision event leaked through",
         "agent_tier_decision" not in events, f"events={events}")


# ==============================================================================
# 5. Malformed LLM output — fails safe, still zero mutations
# ==============================================================================

print("\n=== 5. malformed LLM output (not valid JSON) — fails safe ===")
AUDIT_EVENTS.clear()
api = make_fake_api()
monkeys = []
make_fake_dry_run_requests_trap(monkeys)
orig_audit = orch.audit
orch.audit = fake_audit


def _broken_call(messages, schema):
    return "not valid json {{{"


sa._call = _broken_call
try:
    ao.process_alert_agent(api, {"_id": "~shadow-malformed", "title": "TEST — malformed",
                                 "description": "synthetic", "severity": 2, "tags": []})
    check("malformed LLM output does not raise a mutation error", True)
except MutationAttempted as exc:
    check("malformed LLM output does not raise a mutation error", False, str(exc))
finally:
    orch.audit = orig_audit
    restore_requests(monkeys)

events = [e["event"] for e in AUDIT_EVENTS]
check("malformed-output path produces agent_shadow_failed", "agent_shadow_failed" in events,
     f"events={events}")


# ==============================================================================
# 6. Notification / mailer / L2-assignment functions are simply never reached
#    (the audit's core finding: these have NO internal dry-run gate of their
#    own — proven here by confirming shadow mode never calls them, rather than
#    trusting them to refuse if called).
# ==============================================================================

print("\n=== 6. mailer/L2-assignment functions are never invoked in shadow mode ===")
_calls = {"trigger_mailer_responder": 0, "assign_l2_verified": 0,
         "close_l1_verified": 0, "close_l1_idempotent": 0, "post_case_comment": 0}


def _counted_trap(name):
    def _inner(*a, **kw):
        _calls[name] += 1
        raise MutationAttempted(f"{name} was called in shadow mode — should be unreachable")
    return _inner


orig_fns = {
    "trigger_mailer_responder": orch.trigger_mailer_responder,
    "post_case_comment": orch.post_case_comment,
    "assign_l2_verified": ao.assign_l2_verified,
    "close_l1_verified": ao.close_l1_verified,
    "close_l1_idempotent": ao.close_l1_idempotent,
}
orch.trigger_mailer_responder = _counted_trap("trigger_mailer_responder")
orch.post_case_comment = _counted_trap("post_case_comment")
ao.assign_l2_verified = _counted_trap("assign_l2_verified")
ao.close_l1_verified = _counted_trap("close_l1_verified")
ao.close_l1_idempotent = _counted_trap("close_l1_idempotent")

AUDIT_EVENTS.clear()
orig_audit = orch.audit
orch.audit = fake_audit
api = make_fake_api()
sa._call = mock_llm_sequence({"thought": "concluding", "action": "conclude"},
                             {"verdict": "malicious", "confidence": 0.95, "severity": "critical",
                              "mitre_technique": "T1190", "reason": "test", "key_evidence": "test"})
try:
    ao.process_alert_agent(api, {"_id": "~shadow-mailer-check", "title": "TEST — mailer trap",
                                 "description": "synthetic", "severity": 2, "tags": []})
finally:
    orch.audit = orig_audit
    orch.trigger_mailer_responder = orig_fns["trigger_mailer_responder"]
    orch.post_case_comment = orig_fns["post_case_comment"]
    ao.assign_l2_verified = orig_fns["assign_l2_verified"]
    ao.close_l1_verified = orig_fns["close_l1_verified"]
    ao.close_l1_idempotent = orig_fns["close_l1_idempotent"]

check("trigger_mailer_responder never called", _calls["trigger_mailer_responder"] == 0)
check("post_case_comment never called", _calls["post_case_comment"] == 0)
check("assign_l2_verified never called", _calls["assign_l2_verified"] == 0)
check("close_l1_verified never called", _calls["close_l1_verified"] == 0)
check("close_l1_idempotent never called", _calls["close_l1_idempotent"] == 0)


# ==============================================================================
# 7. Idempotency store is never touched in shadow mode
# ==============================================================================

print("\n=== 7. idempotency store sees zero writes in shadow mode ===")
import tempfile as _tempfile

_tmp_store = _tempfile.mkdtemp(prefix="shadow_idem_test_")
_orig_store_env = os.environ.get("SOAR_IDEMPOTENCY_STORE_DIR")
os.environ["SOAR_IDEMPOTENCY_STORE_DIR"] = _tmp_store
try:
    AUDIT_EVENTS.clear()
    orig_audit = orch.audit
    orch.audit = fake_audit
    api = make_fake_api()
    sa._call = mock_llm_sequence({"thought": "concluding", "action": "conclude"},
                                 {"verdict": "malicious", "confidence": 0.95, "severity": "critical",
                                  "mitre_technique": "T1190", "reason": "test", "key_evidence": "test"})
    ao.process_alert_agent(api, {"_id": "~shadow-idem-check", "title": "TEST — idem store",
                                 "description": "synthetic", "severity": 2, "tags": []})
    orch.audit = orig_audit
    written = os.listdir(_tmp_store)
    check("idempotency store directory remains empty", written == [], f"found: {written}")
finally:
    import shutil as _shutil
    _shutil.rmtree(_tmp_store, ignore_errors=True)
    if _orig_store_env is None:
        os.environ.pop("SOAR_IDEMPOTENCY_STORE_DIR", None)
    else:
        os.environ["SOAR_IDEMPOTENCY_STORE_DIR"] = _orig_store_env


# ==============================================================================
# Summary
# ==============================================================================

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print(f"  SHADOW-MODE AUDIT TESTS: {len(PASS)} passed, {len(FAIL)} failed")
    print("=" * 70)
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    sys.exit(0)
