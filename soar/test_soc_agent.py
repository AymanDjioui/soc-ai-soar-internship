#!/usr/bin/env python3
"""
Tests for soc_agent.py's investigate() loop — specifically the Phase 8G.2 Part B
evidence-completeness nudge: for a C2-beacon-shaped alert, "conclude" is deferred
ONCE if the model has not yet called both of l1_policy.REQUIRED_TOOLS_FOR_L1_CONTAIN
(search_past_cases, run_analyzer). This does NOT touch the verdict schema, the
containment guard, or any l1_policy gate — it only nudges evidence-gathering
behavior, and only once, then respects whatever the model does next (fail-closed
to L2 downstream via the unmodified l1_policy gate if evidence is still missing).

PURE. No network, no live Ollama/TheHive/Cortex/pfSense. _call() and every
agent_tools dispatch function are monkeypatched with canned, in-memory responses.

Run: ./.venv/bin/python3 test_soc_agent.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import soc_agent as SA
import agent_tools as T

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name); print(f"  PASS  {name}")
    else:
        FAIL.append(name); print(f"  FAIL  {name}  {detail}")


C2_ALERT = {"title": "Suricata: possible Cobalt Strike C2 beacon to 203.0.113.99:443",
           "description": "outbound TCP beacon", "severity": 2, "tags": ["malicious-ip"]}
C2_OBSERVABLES = [{"dataType": "ip", "data": "203.0.113.99", "tags": ["malicious-ip", "src"]}]

OTHER_ALERT = {"title": "Suricata: possible SQL injection auth bypass",
              "description": "' OR 1=1-- returned HTTP 200", "severity": 3, "tags": []}
OTHER_OBSERVABLES = [{"dataType": "ip", "data": "203.0.113.50", "tags": ["src"]}]

CANNED_VERDICT = {"verdict": "malicious", "confidence": 0.9, "severity": "high",
                  "mitre_technique": "T1071.001", "reason": "C2 beacon to known-bad IP",
                  "key_evidence": "prior TruePositive history"}


class ScriptedCall:
    """Replaces soc_agent._call(). Feeds one ACTION_SCHEMA step per call from a
    fixed script (ignoring conversation content), and CANNED_VERDICT for the
    final VERDICT_SCHEMA call. Records how many ACTION_SCHEMA calls were made."""
    def __init__(self, action_script, verdict=None):
        self.script = list(action_script)
        self.verdict = verdict or CANNED_VERDICT
        self.action_calls = 0

    def __call__(self, messages, schema):
        if schema is SA.VERDICT_SCHEMA:
            return json.dumps(self.verdict)
        self.action_calls += 1
        if not self.script:
            return json.dumps({"thought": "out of script", "action": "conclude"})
        return json.dumps(self.script.pop(0))


def fake_search_past_cases(value, limit=10):
    return {"tool": "search_past_cases", "value": value, "cases_found": 1,
            "dispositions": {"TruePositive": 1},
            "hint": "prior TruePositive history — weigh toward malicious"}


def fake_run_analyzer(value, analyzer_name, api=None, observables=None, **kw):
    return {"tool": "run_analyzer", "status": "Success",
            "taxonomies": [{"level": "malicious", "namespace": analyzer_name}]}


def fake_get_mitre_context(technique):
    return {"technique": technique, "name": "Application Layer Protocol"}


def fake_search_elasticsearch(query, **kw):
    return {"tool": "search_elasticsearch", "total_matches": 3}


def fake_get_playbook(alert_type):
    return {"playbook": "n/a"}


_ORIG = {}


def patch_tools():
    for name, fn in (("search_past_cases", fake_search_past_cases),
                     ("run_analyzer", fake_run_analyzer),
                     ("get_mitre_context", fake_get_mitre_context),
                     ("search_elasticsearch", fake_search_elasticsearch),
                     ("get_playbook", fake_get_playbook)):
        _ORIG[name] = getattr(T, name)
        setattr(T, name, fn)


def restore_tools():
    for name, fn in _ORIG.items():
        setattr(T, name, fn)


def count_deferred(trace):
    return sum(1 for step in trace
              if step.get("action") == "conclude" and
              isinstance(step.get("result"), dict) and
              "deferred" in step.get("result", {}))


patch_tools()

# ==============================================================================
# 1. C2 alert, model calls ONLY search_past_cases, then tries to conclude twice
#    -> first conclude deferred (missing run_analyzer), reminder issued, model
#       calls run_analyzer, second conclude accepted.
# ==============================================================================

print("\n=== 1. C2 candidate: search_past_cases only, then nudged to run_analyzer ===")
script = [
    {"thought": "check history", "action": "search_past_cases", "value": "203.0.113.99"},
    {"thought": "enough", "action": "conclude"},
    {"thought": "ok fetching analyzer", "action": "run_analyzer",
     "observable": "203.0.113.99", "analyzer_name": "AbuseIPDB"},
    {"thought": "now concluding", "action": "conclude"},
]
caller = ScriptedCall(script)
SA._call = caller
res = SA.investigate(C2_ALERT, C2_OBSERVABLES, verbose=False)
check("investigation concluded (not left_for_human)", res.get("verdict") is not None, res)
check("both required tools present in tools_used",
     all(t in res["tools_used"] for t in ["search_past_cases", "run_analyzer"]),
     res.get("tools_used"))
check("exactly one deferred-conclude entry in trace", count_deferred(res["trace"]) == 1,
     res["trace"])
check("verdict is the canned verdict (nudge did not alter the model's own conclusion)",
     res["verdict"]["verdict"] == "malicious" and res["verdict"]["mitre_technique"] == "T1071.001")

# ==============================================================================
# 2. C2 alert, model calls ONLY run_analyzer, then tries to conclude twice
#    -> reminder names the OTHER missing tool (search_past_cases).
# ==============================================================================

print("\n=== 2. C2 candidate: run_analyzer only, then nudged to search_past_cases ===")
script = [
    {"thought": "check reputation", "action": "run_analyzer",
     "observable": "203.0.113.99", "analyzer_name": "AbuseIPDB"},
    {"thought": "enough", "action": "conclude"},
    {"thought": "checking history too", "action": "search_past_cases", "value": "203.0.113.99"},
    {"thought": "now concluding", "action": "conclude"},
]
caller = ScriptedCall(script)
SA._call = caller
res = SA.investigate(C2_ALERT, C2_OBSERVABLES, verbose=False)
check("both required tools present in tools_used (order 2)",
     all(t in res["tools_used"] for t in ["search_past_cases", "run_analyzer"]),
     res.get("tools_used"))
check("exactly one deferred-conclude entry in trace (order 2)", count_deferred(res["trace"]) == 1)

# ==============================================================================
# 3. C2 alert, model ignores the reminder and tries to conclude again while
#    STILL missing evidence -> bounded to ONE nudge only; second attempt is
#    accepted with incomplete evidence (fail-closed is l1_policy's job, not
#    this loop's — this loop must never refuse forever).
# ==============================================================================

print("\n=== 3. C2 candidate: model ignores the nudge -> exactly one nudge, then respected ===")
script = [
    {"thought": "enough already", "action": "conclude"},
    {"thought": "still nothing new", "action": "conclude"},
]
caller = ScriptedCall(script)
SA._call = caller
res = SA.investigate(C2_ALERT, C2_OBSERVABLES, verbose=False)
check("investigation still concludes (loop is not stuck forever)", res.get("verdict") is not None)
check("tools_used remains empty (no fabricated evidence)", res["tools_used"] == [], res["tools_used"])
check("exactly one deferred-conclude entry even when ignored", count_deferred(res["trace"]) == 1)
check("only 2 action-model calls were made (bounded, not looping)", caller.action_calls == 2,
     caller.action_calls)

# ==============================================================================
# 4. Non-C2 alert -> gate must NOT engage at all; immediate conclude preserved
#    exactly like before this change (regression guard on unrelated alert types).
# ==============================================================================

print("\n=== 4. non-C2 alert: immediate conclude is untouched ===")
script = [{"thought": "clear SQLi", "action": "conclude"}]
caller = ScriptedCall(script, verdict={"verdict": "malicious", "confidence": 0.95,
                                       "severity": "critical", "mitre_technique": "T1190",
                                       "reason": "SQLi auth bypass", "key_evidence": "HTTP 200 + token"})
SA._call = caller
res = SA.investigate(OTHER_ALERT, OTHER_OBSERVABLES, verbose=False)
check("no deferral for a non-C2 alert", count_deferred(res["trace"]) == 0, res["trace"])
check("concluded on the very first action call", caller.action_calls == 1)
check("tools_used is empty, exactly as the model chose", res["tools_used"] == [])

# ==============================================================================
# 5. C2 alert where the model already gathered BOTH tools before ever trying to
#    conclude -> gate must be a pure no-op (no reminder needed or issued).
# ==============================================================================

print("\n=== 5. C2 candidate: both tools already used before first conclude -> no-op ===")
script = [
    {"thought": "history", "action": "search_past_cases", "value": "203.0.113.99"},
    {"thought": "enrichment", "action": "run_analyzer",
     "observable": "203.0.113.99", "analyzer_name": "AbuseIPDB"},
    {"thought": "done", "action": "conclude"},
]
caller = ScriptedCall(script)
SA._call = caller
res = SA.investigate(C2_ALERT, C2_OBSERVABLES, verbose=False)
check("no deferral when evidence was already complete", count_deferred(res["trace"]) == 0,
     res["trace"])
check("concluded on the first conclude attempt (3rd action call)", caller.action_calls == 3)

# ==============================================================================
# 6. Alert with a C2 keyword only in tags (not title) -> is_l1_candidate must
#    still engage (matches l1_policy's own title-OR-tags test).
# ==============================================================================

print("\n=== 6. C2 candidate detected via tags, not title ===")
tag_only_alert = {"title": "Suricata: suspicious outbound beacon", "description": "",
                  "severity": 2, "tags": ["cobalt strike", "malicious-ip"]}
script = [
    {"thought": "history", "action": "search_past_cases", "value": "203.0.113.99"},
    {"thought": "enough", "action": "conclude"},
]
caller = ScriptedCall(script)
SA._call = caller
res = SA.investigate(tag_only_alert, C2_OBSERVABLES, verbose=False)
check("gate engages when the keyword is only in tags", count_deferred(res["trace"]) == 1,
     res["trace"])

restore_tools()

# ==============================================================================
# Summary
# ==============================================================================

print("\n" + "=" * 70)
print(f"  SOC AGENT (investigate-loop evidence nudge) TESTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 70)
if FAIL:
    print("FAILED:")
    for f in FAIL:
        print("  -", f)
    sys.exit(1)
sys.exit(0)
