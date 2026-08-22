#!/usr/bin/env python3
"""
Phase 1 tests — l1_policy.evaluate_l1_malicious_eligibility() and the updated
agent_orchestrator.l1_disposition().

PURE UNIT TESTS. No network calls, no live TheHive/Cortex/pfSense/Ollama, no
mutation of any real file except a throwaway temp audit log used for the
idempotency test (created + deleted within the test). Safe to run any time.

Run: ./.venv/bin/python test_l1_policy.py
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import idempotency
import l1_policy
from l1_policy import Reason

# Every eval_case() call in this file uses this ONE throwaway store directory —
# evaluate_l1_malicious_eligibility() is read-only w.r.t. the idempotency store
# (it never calls record_tier_decision itself), so sharing it across tests 1-11/
# 13-16 is safe; only test 12 explicitly records a decision into it.
TEST_STORE_DIR = tempfile.mkdtemp(prefix="l1_policy_test_store_")

PASS = []
FAIL = []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print(f"  PASS  {name}")
    else:
        FAIL.append(name)
        print(f"  FAIL  {name}  {detail}")


# ==============================================================================
# Fixtures — a "golden" fully-eligible malicious C2 case, then mutated variants
# ==============================================================================

def base_verdict():
    return {"verdict": "malicious", "confidence": 0.9, "severity": "high",
            "mitre_technique": "T1071.001", "reason": "known C2 beacon",
            "key_evidence": "ThreatFox 100% confidence C2"}


def base_alert():
    return {"title": "C2 beacon from known-malicious AdaptixC2 server",
            "tags": ["synthetic", "c2", "threatfox"]}


def base_trace_eligible():
    return [
        {"step": 1, "action": "search_past_cases", "arg": "202.61.130.163",
         "result": {"hint": "prior TruePositive history — weigh toward malicious",
                    "cases_found": 3, "dispositions": {"TruePositive": 3}}},
        {"step": 2, "action": "run_analyzer", "arg": "202.61.130.163:AbuseIPDB",
         "result": {"status": "Success",
                    "taxonomies": [{"level": "malicious", "namespace": "AbuseIPDB",
                                    "predicate": "Score", "value": 90}]}},
        {"step": 3, "action": "conclude", "thought": "clear C2"},
    ]


def base_res(trace=None):
    return {
        "verdict": base_verdict(),
        "trace": trace if trace is not None else base_trace_eligible(),
        "tools_used": ["search_past_cases", "run_analyzer"],
        "containment": {"target": "202.61.130.163", "allowed": True,
                        "reason": "all guardrails passed", "disposition": "AUTO-RESPOND"},
    }


def eval_case(res=None, alert=None, alert_id="~alert1", case_id="~test1", armed=True):
    return l1_policy.evaluate_l1_malicious_eligibility(
        verdict=(res or base_res())["verdict"], res=(res or base_res()),
        alert=alert if alert is not None else base_alert(),
        alert_id=alert_id, case_id=case_id, armed=armed, store_dir=TEST_STORE_DIR)


# ==============================================================================
# 1. The golden path — everything correct, must be eligible
# ==============================================================================

print("\n=== 1. Golden eligible case ===")
r = eval_case()
check("golden case is eligible", r["eligible"] is True, r["reason_codes"])
check("golden case has zero reason codes", r["reason_codes"] == [], r["reason_codes"])
check("policy_version is set", r["policy_version"] == l1_policy.POLICY_VERSION)


# ==============================================================================
# 2. Rule / technique not allowlisted
# ==============================================================================

print("\n=== 2. Non-allowlisted technique (SQLi, T1190) ===")
v = base_verdict(); v["mitre_technique"] = "T1190"
res = base_res(); res["verdict"] = v
alert = {"title": "SQL Injection Attempt on Juice Shop", "tags": ["web-attack"]}
r = eval_case(res=res, alert=alert)
check("SQLi not eligible", r["eligible"] is False)
check("SQLi gets RULE_NOT_L1_ELIGIBLE or UNKNOWN_RULE",
     Reason.RULE_NOT_L1_ELIGIBLE in r["reason_codes"] or Reason.UNKNOWN_RULE in r["reason_codes"],
     r["reason_codes"])


# ==============================================================================
# 3. Low confidence
# ==============================================================================

print("\n=== 3. Low confidence (0.6, below 0.85 floor) ===")
v = base_verdict(); v["confidence"] = 0.6
res = base_res(); res["verdict"] = v
r = eval_case(res=res)
check("low confidence not eligible", r["eligible"] is False)
check("low confidence -> LOW_CONFIDENCE", Reason.LOW_CONFIDENCE in r["reason_codes"], r["reason_codes"])


# ==============================================================================
# 4. Missing required tool (run_analyzer never called)
# ==============================================================================

print("\n=== 4. Missing run_analyzer (only search_past_cases called) ===")
res = base_res()
res["tools_used"] = ["search_past_cases"]
res["trace"] = [res["trace"][0], res["trace"][2]]  # drop the run_analyzer step
r = eval_case(res=res)
check("missing tool not eligible", r["eligible"] is False)
check("missing tool -> MISSING_EVIDENCE", Reason.MISSING_EVIDENCE in r["reason_codes"], r["reason_codes"])


# ==============================================================================
# 5. Tool returned an error
# ==============================================================================

print("\n=== 5. A tool call returned an error ===")
res = base_res()
res["trace"] = list(res["trace"])
res["trace"][1] = {"step": 2, "action": "run_analyzer", "arg": "x:GreyNoise",
                   "result": {"error": "job submission failed: timeout"}}
r = eval_case(res=res)
check("tool error not eligible", r["eligible"] is False)
check("tool error -> TOOL_FAILURE", Reason.TOOL_FAILURE in r["reason_codes"], r["reason_codes"])


# ==============================================================================
# 6. No corroboration (analyzer came back clean, no prior TP history)
# ==============================================================================

print("\n=== 6. Fresh IOC, clean analyzer, no history (should escalate, not block) ===")
res = base_res()
res["trace"] = [
    {"step": 1, "action": "search_past_cases", "arg": "1.2.3.4",
     "result": {"hint": "no prior cases for this value", "cases_found": 0}},
    {"step": 2, "action": "run_analyzer", "arg": "1.2.3.4:AbuseIPDB",
     "result": {"status": "Success",
                "taxonomies": [{"level": "safe", "namespace": "AbuseIPDB",
                                "predicate": "Score", "value": 0}]}},
    {"step": 3, "action": "conclude", "thought": "fresh IOC"},
]
r = eval_case(res=res)
check("fresh-IOC-no-corroboration not eligible", r["eligible"] is False)
check("-> INSUFFICIENT_CORROBORATION", Reason.INSUFFICIENT_CORROBORATION in r["reason_codes"],
     r["reason_codes"])


# ==============================================================================
# 7. Conflicting evidence (prior FalsePositive history on a malicious verdict)
# ==============================================================================

print("\n=== 7. Conflicting RAG history (prior FalsePositive, verdict malicious) ===")
res = base_res()
res["trace"] = list(res["trace"])
res["trace"][0] = {"step": 1, "action": "search_past_cases", "arg": "5.5.5.5",
                   "result": {"hint": "prior FalsePositive history — weigh toward benign",
                              "cases_found": 4, "dispositions": {"FalsePositive": 4}}}
r = eval_case(res=res)
check("conflicting evidence not eligible", r["eligible"] is False)
check("-> CONFLICTING_EVIDENCE", Reason.CONFLICTING_EVIDENCE in r["reason_codes"], r["reason_codes"])
check("-> RAG_DISPOSITION_CONFLICT", Reason.RAG_DISPOSITION_CONFLICT in r["reason_codes"], r["reason_codes"])


# ==============================================================================
# 8. Guard refused (internal/protected target — mirrors a real containment_allowed() refusal)
# ==============================================================================

print("\n=== 8. Guard refused (internal/protected target) ===")
res = base_res()
res["containment"] = {"target": "100.99.54.59", "allowed": False,
                      "reason": "policy guard: explicitly protected lab asset",
                      "disposition": "ESCALATE-TO-HUMAN"}
r = eval_case(res=res)
check("guard-refused not eligible", r["eligible"] is False)
check("-> CONTAINMENT_REFUSED", Reason.CONTAINMENT_REFUSED in r["reason_codes"], r["reason_codes"])


# ==============================================================================
# 9. Ambiguous / missing target IP
# ==============================================================================

print("\n=== 9. No target IP resolved ===")
res = base_res()
res["containment"] = {"target": None, "allowed": False, "reason": "no IP-type observable",
                      "disposition": "ESCALATE-TO-HUMAN"}
r = eval_case(res=res)
check("no-target not eligible", r["eligible"] is False)
check("-> AMBIGUOUS_TARGET", Reason.AMBIGUOUS_TARGET in r["reason_codes"], r["reason_codes"])


# ==============================================================================
# 10. Schema invalid (missing confidence field)
# ==============================================================================

print("\n=== 10. Malformed verdict (confidence missing) ===")
v = {"verdict": "malicious", "severity": "high", "mitre_technique": "T1071.001",
     "reason": "x", "key_evidence": "y"}   # no 'confidence' key
res = base_res(); res["verdict"] = v
r = eval_case(res=res)
check("malformed verdict not eligible", r["eligible"] is False)
check("-> SCHEMA_INVALID", Reason.SCHEMA_INVALID in r["reason_codes"], r["reason_codes"])


# ==============================================================================
# 11. Not armed
# ==============================================================================

print("\n=== 11. Not armed (armed=False) ===")
r = eval_case(armed=False)
check("not-armed not eligible", r["eligible"] is False)
check("-> NOT_ARMED", Reason.NOT_ARMED in r["reason_codes"], r["reason_codes"])


# ==============================================================================
# 12. Duplicate processing (idempotency) — now backed by the composite store.
# Corrupted/unreadable-store fail-closed behavior is covered exhaustively in
# test_idempotency.py; this section covers gate 17's INTEGRATION with the store.
# ==============================================================================

print("\n=== 12. Duplicate processing — composite idempotency store integration ===")
dup_store = tempfile.mkdtemp(prefix="l1_dup_test_", dir=TEST_STORE_DIR)
dup_dkey = idempotency.decision_key("~alertDup", "~caseDup", l1_policy.POLICY_VERSION, "armed")
idempotency.record_tier_decision(dup_dkey, "L2", detail={"reason": "prior run"}, store_dir=dup_store)

r = l1_policy.evaluate_l1_malicious_eligibility(
    verdict=base_verdict(), res=base_res(), alert=base_alert(),
    alert_id="~alertDup", case_id="~caseDup", armed=True, store_dir=dup_store)
check("case with an existing tier decision is not eligible", r["eligible"] is False)
check("-> DUPLICATE_PROCESSING", Reason.DUPLICATE_PROCESSING in r["reason_codes"], r["reason_codes"])
check("decision_key matches what was recorded", r["decision_key"] == dup_dkey)

# a DIFFERENT case_id in the same store must NOT be flagged as duplicate
r2 = l1_policy.evaluate_l1_malicious_eligibility(
    verdict=base_verdict(), res=base_res(), alert=base_alert(),
    alert_id="~alertFresh", case_id="~caseFresh", armed=True, store_dir=dup_store)
check("different case_id in the same store is not flagged duplicate",
     Reason.DUPLICATE_PROCESSING not in r2["reason_codes"], r2["reason_codes"])

# armed vs dry_run must be DIFFERENT decision keys (different execution_mode) —
# a dry-run evaluation must not block a later armed evaluation of the same case.
r3 = l1_policy.evaluate_l1_malicious_eligibility(
    verdict=base_verdict(), res=base_res(), alert=base_alert(),
    alert_id="~alertDup", case_id="~caseDup", armed=False, store_dir=dup_store)
check("dry_run mode is a separate decision key from the armed L2 record",
     Reason.DUPLICATE_PROCESSING not in r3["reason_codes"], r3["reason_codes"])
check("dry_run correctly still blocked by NOT_ARMED regardless",
     Reason.NOT_ARMED in r3["reason_codes"])


# ==============================================================================
# 13. l1_disposition() — Phase 6: benign NEVER auto-closes anymore
# ==============================================================================

print("\n=== 13. l1_disposition(): benign verdict always escalates now (Phase 6) ===")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("THEHIVE_API_KEY", "test-placeholder-not-real")
import agent_orchestrator as ao

benign_verdict = {"verdict": "benign", "confidence": 0.99}
d = ao.l1_disposition(benign_verdict, {"executed": False, "allowed": False}, base_alert(), None)
check("benign never closes (even at 0.99 confidence)", d["tier"] == "L2")
check("benign action is escalate, not close_false_positive", d["action"] == "escalate")

# high-confidence benign SSDP noise (the old auto-close case) -> now also L2
ssdp_alert = {"title": "SSDP Amplification Scan (internal)", "tags": ["demo", "ssdp"]}
d2 = ao.l1_disposition({"verdict": "benign", "confidence": 0.95},
                       {"executed": False, "allowed": False}, ssdp_alert, None)
check("SSDP benign case also now escalates (no benign auto-close at all)", d2["tier"] == "L2")


# ==============================================================================
# 14. l1_disposition() — malicious + eligible + executed -> L1 TruePositive
# ==============================================================================

print("\n=== 14. l1_disposition(): malicious + eligible + executed -> L1 close TP ===")
elig_true = {"eligible": True, "reason_codes": [], "policy_version": l1_policy.POLICY_VERSION}
d3 = ao.l1_disposition(base_verdict(),
                       {"executed": True, "allowed": True, "target": "202.61.130.163"},
                       base_alert(), elig_true)
check("eligible+executed -> L1", d3["tier"] == "L1")
check("eligible+executed -> close_true_positive", d3["action"] == "close_true_positive")
check("reason code L1_TRUE_POSITIVE_CONTAINED present",
     Reason.L1_TRUE_POSITIVE_CONTAINED in d3["reason_codes"])


# ==============================================================================
# 15. l1_disposition() — malicious but NOT eligible -> L2 with the eligibility reasons
# ==============================================================================

print("\n=== 15. l1_disposition(): malicious but ineligible -> L2, reasons propagated ===")
elig_false = {"eligible": False, "reason_codes": [Reason.LOW_CONFIDENCE, Reason.MISSING_EVIDENCE],
             "policy_version": l1_policy.POLICY_VERSION}
d4 = ao.l1_disposition(base_verdict(),
                       {"executed": False, "allowed": True, "target": "1.2.3.4"},
                       base_alert(), elig_false)
check("ineligible malicious -> L2", d4["tier"] == "L2")
check("ineligible reason codes propagated",
     set(d4["reason_codes"]) == {Reason.LOW_CONFIDENCE, Reason.MISSING_EVIDENCE}, d4["reason_codes"])


# ==============================================================================
# 16. l1_disposition() — malicious + eligible but never confirmed contained
# ==============================================================================

print("\n=== 16. l1_disposition(): eligible, guard-allowed, but containment unconfirmed ===")
d5 = ao.l1_disposition(base_verdict(),
                       {"executed": False, "allowed": True, "target": "202.61.130.163"},
                       base_alert(), elig_true)
check("unconfirmed containment -> L2, not L1", d5["tier"] == "L2")
check("unconfirmed containment does not close", d5["action"] == "escalate")


# ==============================================================================
# 17-20. close_l1_idempotent() — the ignored-return-value fix, isolated
# ==============================================================================

CLOSE_TEST_STORE = tempfile.mkdtemp(prefix="close_idem_test_", dir=TEST_STORE_DIR)
_orig_close_case_l1 = ao.close_case_l1
_orig_mailer = ao.orch.trigger_mailer_responder


def _patch(close_returns=None, mailer_returns=True):
    calls = {"close": 0, "mailer": 0}
    if close_returns is not None:
        def fake_close(api, case_id, status, summary):
            calls["close"] += 1
            return close_returns
        ao.close_case_l1 = fake_close

    def fake_mailer(api, case_id):
        calls["mailer"] += 1
        return mailer_returns
    ao.orch.trigger_mailer_responder = fake_mailer
    return calls


def _unpatch():
    ao.close_case_l1 = _orig_close_case_l1
    ao.orch.trigger_mailer_responder = _orig_mailer


print("\n=== 17. close_l1_idempotent(): success path ===")
calls = _patch(close_returns=True)
dkey17 = idempotency.decision_key("~a17", "~c17", l1_policy.POLICY_VERSION, "armed")
ok = ao.close_l1_idempotent(None, dkey17, "~c17", {"status": "TruePositive", "reason": "x"},
                            {"tier": "L1"}, store_dir=CLOSE_TEST_STORE)
check("successful close returns True", ok is True)
check("close_case_l1 was called exactly once", calls["close"] == 1)
check("mailer NOT called on success", calls["mailer"] == 0)
rec = idempotency.get_status(idempotency.action_key(dkey17, "closure", "truepositive"),
                             store_dir=CLOSE_TEST_STORE)
check("idempotency store shows COMPLETED", rec["status"] == idempotency.STATUS_COMPLETED)
_unpatch()

print("\n=== 18. close_l1_idempotent(): FAILURE path — the ignored-return-value bug fix ===")
calls = _patch(close_returns=False)
dkey18 = idempotency.decision_key("~a18", "~c18", l1_policy.POLICY_VERSION, "armed")
ok = ao.close_l1_idempotent(None, dkey18, "~c18", {"status": "TruePositive", "reason": "x"},
                            {"tier": "L1"}, store_dir=CLOSE_TEST_STORE)
check("failed close returns False (previously the return value was ignored entirely)",
     ok is False)
check("close_case_l1 was actually called", calls["close"] == 1)
check("mailer IS called as the escalation fallback on failure", calls["mailer"] == 1)
rec = idempotency.get_status(idempotency.action_key(dkey18, "closure", "truepositive"),
                             store_dir=CLOSE_TEST_STORE)
check("idempotency store shows FAILED, not COMPLETED", rec["status"] == idempotency.STATUS_FAILED)
_unpatch()

print("\n=== 19. close_l1_idempotent(): duplicate closure prevented ===")
calls = _patch(close_returns=True)
# dkey17 already has a COMPLETED closure record from test 17 — call again.
ok2 = ao.close_l1_idempotent(None, dkey17, "~c17", {"status": "TruePositive", "reason": "x"},
                             {"tier": "L1"}, store_dir=CLOSE_TEST_STORE)
check("second close attempt on the same decision key returns True (already done)", ok2 is True)
check("close_case_l1 was NOT called again", calls["close"] == 0)
_unpatch()

print("\n=== 20. close_l1_idempotent(): tier-record mismatch refuses to close ===")
calls = _patch(close_returns=True)
dkey20 = idempotency.decision_key("~a20", "~c20", l1_policy.POLICY_VERSION, "armed")
ok3 = ao.close_l1_idempotent(None, dkey20, "~c20", {"status": "TruePositive", "reason": "x"},
                             {"tier": "L2"}, store_dir=CLOSE_TEST_STORE)   # recorded tier says L2!
check("mismatched tier record refuses to close, even if disposition says close",
     ok3 is False)
check("close_case_l1 was NEVER called (refused before attempting)", calls["close"] == 0)
check("mailer called instead (escalation)", calls["mailer"] == 1)
_unpatch()


# ==============================================================================
# 21. notify_l2_idempotent() — duplicate email prevented
# ==============================================================================

print("\n=== 21. notify_l2_idempotent(): duplicate L2 email prevented ===")
calls = _patch(mailer_returns=True)
dkey21 = idempotency.decision_key("~a21", "~c21", l1_policy.POLICY_VERSION, "armed")
sent1 = ao.notify_l2_idempotent(None, dkey21, "~c21", store_dir=CLOSE_TEST_STORE)
check("first L2 notification sends", sent1 is True)
check("mailer called once", calls["mailer"] == 1)
sent2 = ao.notify_l2_idempotent(None, dkey21, "~c21", store_dir=CLOSE_TEST_STORE)
check("second call on the same decision key does not re-send", sent2 is True)
check("mailer NOT called a second time", calls["mailer"] == 1)
_unpatch()


# ==============================================================================
# Summary
# ==============================================================================

shutil.rmtree(TEST_STORE_DIR, ignore_errors=True)
print("\n" + "=" * 70)
print(f"  PHASE 1 TESTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 70)
if FAIL:
    print("FAILED:")
    for f in FAIL:
        print("  -", f)
    sys.exit(1)
sys.exit(0)
