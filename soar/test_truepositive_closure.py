#!/usr/bin/env python3
"""
Phase 3 tests — verified TruePositive closure (l1_policy.evaluate_l1_closure_
eligibility() + agent_orchestrator.close_l1_verified()/build_closure_comment()).

PURE. close_case_l1() (the PATCH), orch.post_case_comment() (the comment), and
orch.trigger_mailer_responder() (the escalation email) are monkeypatched for
the duration of each test that needs them, then restored. case_state_fn is
always an injected fake. No live TheHive/Cortex/pfSense call is ever made.

Run: ./.venv/bin/python test_truepositive_closure.py
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("THEHIVE_API_KEY", "test-placeholder-not-real")

import idempotency
import l1_policy
import agent_orchestrator as ao

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name); print(f"  PASS  {name}")
    else:
        FAIL.append(name); print(f"  FAIL  {name}  {detail}")


STORE = tempfile.mkdtemp(prefix="tp_closure_test_")


def fresh_dir():
    return tempfile.mkdtemp(prefix="tpc_", dir=STORE)


# ==============================================================================
# Fixtures
# ==============================================================================

def make_res(verdict_str="malicious", confidence=0.95, technique="T1071.001",
            target="202.61.130.163"):
    return {
        "verdict": {"verdict": verdict_str, "confidence": confidence, "severity": "high",
                    "mitre_technique": technique, "reason": "C2 beacon to known-bad IP",
                    "key_evidence": "repeated periodic beacon pattern"},
        "trace": [
            {"step": 1, "action": "search_past_cases", "result": {"hint": "prior TruePositive case"}},
            {"step": 2, "action": "run_analyzer",
             "result": {"name": "AbuseIPDB", "taxonomies": [{"level": "malicious"}]}},
        ],
        "tools_used": ["search_past_cases", "run_analyzer"],
        "containment": {"target": target, "allowed": True, "disposition": "block", "reason": "external"},
    }


def setup_verified_containment(alert_id, case_id, target_ip, execution_mode, store_dir,
                               policy_version=None, executed=True):
    policy_version = policy_version or l1_policy.POLICY_VERSION
    c_key = idempotency.containment_action_key(alert_id, case_id, target_ip, execution_mode)
    idempotency.claim(c_key, store_dir=store_dir, meta={"target": target_ip})
    idempotency.complete(
        c_key, idempotency.STATUS_COMPLETED if executed else idempotency.STATUS_FAILED,
        detail={"executed": executed, "target": target_ip, "cortex_status": "Success",
               "job_id": "job-1", "pfsense_verified_at": "2026-01-01T00:00:00Z"},
        store_dir=store_dir)
    containment_result = {
        "executed": executed, "reason_code": l1_policy.Reason.L1_TRUE_POSITIVE_CONTAINED,
        "audit": {"alert_id": alert_id, "case_id": case_id, "policy_version": policy_version,
                  "target_ip": target_ip, "idempotency_key": c_key, "job_id": "job-1",
                  "cortex_status": "Success", "precheck_result": "ABSENT",
                  "postcheck_result": "PRESENT", "verification_timestamp": "2026-01-01T00:00:00Z"}}
    return containment_result, c_key


class FakeCaseState:
    """Injectable case_state_fn. Stateful: .status can be flipped externally
    (e.g. by a fake close_case_l1's side effect) to simulate a PATCH actually
    landing, or internally via flip_to/flip_after to simulate a LIVE change
    happening between two successive queries (a real race window)."""
    def __init__(self, status="Open", raise_exc=False, flip_to=None, flip_after=None):
        self.status = status
        self.raise_exc = raise_exc
        self.flip_to = flip_to
        self.flip_after = flip_after
        self.calls = 0

    def __call__(self, case_id):
        self.calls += 1
        if self.raise_exc:
            raise RuntimeError("simulated TheHive query failure")
        if self.flip_after is not None and self.calls > self.flip_after and self.flip_to is not None:
            self.status = self.flip_to
        return {"status": self.status}


_orig_close_case_l1 = ao.close_case_l1
_orig_post_comment = ao.orch.post_case_comment
_orig_mailer = ao.orch.trigger_mailer_responder


def patch_all(close_returns=True, close_side_effect_status=None, case_state=None,
             comment_returns=True):
    """close_side_effect_status: if given, the fake close_case_l1() also sets
    case_state.status to this value (simulating the PATCH actually landing),
    letting a subsequent case_state_fn() call observe the change."""
    calls = {"close": 0, "comment": 0, "mailer": 0, "comment_bodies": []}

    def fake_close(api, case_id, status, summary):
        calls["close"] += 1
        if close_side_effect_status is not None and case_state is not None:
            case_state.status = close_side_effect_status
        return close_returns
    ao.close_case_l1 = fake_close

    def fake_comment(case_id, body):
        calls["comment"] += 1
        calls["comment_bodies"].append(body)
        return comment_returns
    ao.orch.post_case_comment = fake_comment

    def fake_mailer(api, case_id):
        calls["mailer"] += 1
        return True
    ao.orch.trigger_mailer_responder = fake_mailer

    return calls


def unpatch_all():
    ao.close_case_l1 = _orig_close_case_l1
    ao.orch.post_case_comment = _orig_post_comment
    ao.orch.trigger_mailer_responder = _orig_mailer


# ==============================================================================
# 1. Full happy path — all 10 gates pass -> verified closure
# ==============================================================================

print("\n=== 1. close_l1_verified(): full happy path, all gates pass ===")
d = fresh_dir()
res1 = make_res()
cr1, ckey1 = setup_verified_containment("~a1", "~c1", "202.61.130.163", "armed", d)
cs1 = FakeCaseState(status="Open")
calls = patch_all(close_returns=True, close_side_effect_status="TruePositive", case_state=cs1)
try:
    dkey1 = idempotency.decision_key("~a1", "~c1", l1_policy.POLICY_VERSION, "armed")
    tier1 = idempotency.record_tier_decision(dkey1, "L1", store_dir=d)
    ok1 = ao.close_l1_verified(None, dkey1, "~a1", "~c1", res1["verdict"], res1, cr1, tier1,
                               case_state_fn=cs1, store_dir=d)
finally:
    unpatch_all()
check("closure succeeds end-to-end", ok1 is True)
check("comment was posted exactly once", calls["comment"] == 1)
check("PATCH (close_case_l1) was called exactly once", calls["close"] == 1)
check("mailer NOT called on success", calls["mailer"] == 0)
close_key1 = l1_policy.evaluate_l1_closure_eligibility(
    "~a1", "~c1", dkey1, res1["verdict"], cr1, case_state_fn=cs1, store_dir=d)["close_key"]
rec1 = idempotency.get_status(close_key1, store_dir=d)
check("idempotency store shows COMPLETED", rec1["status"] == idempotency.STATUS_COMPLETED, rec1)


# ==============================================================================
# 2. Tier-record mismatch refuses closure (belt-and-braces)
# ==============================================================================

print("\n=== 2. close_l1_verified(): recorded tier is L2 -> refuses, never touches TheHive ===")
d = fresh_dir()
res2 = make_res()
cr2, _ = setup_verified_containment("~a2", "~c2", "202.61.130.163", "armed", d)
cs2 = FakeCaseState(status="Open")
calls = patch_all(case_state=cs2)
try:
    dkey2 = idempotency.decision_key("~a2", "~c2", l1_policy.POLICY_VERSION, "armed")
    ok2 = ao.close_l1_verified(None, dkey2, "~a2", "~c2", res2["verdict"], res2, cr2,
                               {"tier": "L2"}, case_state_fn=cs2, store_dir=d)
finally:
    unpatch_all()
check("refused (tier record says L2, not L1)", ok2 is False)
check("close_case_l1 NEVER called", calls["close"] == 0)
check("comment NEVER posted", calls["comment"] == 0)
check("mailer called (escalation)", calls["mailer"] == 1)


# ==============================================================================
# 3. Eligibility gate: verdict not malicious -> ineligible
# ==============================================================================

print("\n=== 3. eligibility: verdict not malicious -> RULE_NOT_L1_ELIGIBLE, ineligible ===")
d = fresh_dir()
non_malicious_verdict = {"verdict": "benign", "confidence": 0.9}
cr3, _ = setup_verified_containment("~a3", "~c3", "202.61.130.163", "armed", d)
cs3 = FakeCaseState(status="Open")
dkey3 = idempotency.decision_key("~a3", "~c3", l1_policy.POLICY_VERSION, "armed")
idempotency.record_tier_decision(dkey3, "L1", store_dir=d)
elig3 = l1_policy.evaluate_l1_closure_eligibility(
    "~a3", "~c3", dkey3, non_malicious_verdict, cr3, case_state_fn=cs3, store_dir=d)
check("ineligible", elig3["eligible"] is False)
check("reason includes RULE_NOT_L1_ELIGIBLE", l1_policy.Reason.RULE_NOT_L1_ELIGIBLE in elig3["reason_codes"])


# ==============================================================================
# 4. Eligibility gate: containment record missing
# ==============================================================================

print("\n=== 4. eligibility: no containment record on file -> CONTAINMENT_RECORD_MISSING ===")
d = fresh_dir()
res4 = make_res()
cr4 = {"executed": True, "audit": {"target_ip": "202.61.130.163",
       "idempotency_key": "no-such-key-ever-claimed", "policy_version": l1_policy.POLICY_VERSION}}
cs4 = FakeCaseState(status="Open")
dkey4 = idempotency.decision_key("~a4", "~c4", l1_policy.POLICY_VERSION, "armed")
idempotency.record_tier_decision(dkey4, "L1", store_dir=d)
elig4 = l1_policy.evaluate_l1_closure_eligibility(
    "~a4", "~c4", dkey4, res4["verdict"], cr4, case_state_fn=cs4, store_dir=d)
check("ineligible", elig4["eligible"] is False)
check("reason is CONTAINMENT_RECORD_MISSING", l1_policy.Reason.CONTAINMENT_RECORD_MISSING in elig4["reason_codes"])


# ==============================================================================
# 5. Eligibility gate: containment record exists but not executed/verified
# ==============================================================================

print("\n=== 5. eligibility: containment record exists but executed=False -> CONTAINMENT_UNVERIFIED ===")
d = fresh_dir()
res5 = make_res()
cr5, _ = setup_verified_containment("~a5", "~c5", "202.61.130.163", "armed", d, executed=False)
cs5 = FakeCaseState(status="Open")
dkey5 = idempotency.decision_key("~a5", "~c5", l1_policy.POLICY_VERSION, "armed")
idempotency.record_tier_decision(dkey5, "L1", store_dir=d)
elig5 = l1_policy.evaluate_l1_closure_eligibility(
    "~a5", "~c5", dkey5, res5["verdict"], cr5, case_state_fn=cs5, store_dir=d)
check("ineligible", elig5["eligible"] is False)
check("reason is CONTAINMENT_UNVERIFIED", l1_policy.Reason.CONTAINMENT_UNVERIFIED in elig5["reason_codes"])


# ==============================================================================
# 6. Eligibility gate: target IP mismatch
# ==============================================================================

print("\n=== 6. eligibility: target IP mismatch across records -> CONTAINMENT_TARGET_MISMATCH ===")
d = fresh_dir()
res6 = make_res(target="9.9.9.9")
cr6, _ = setup_verified_containment("~a6", "~c6", "202.61.130.163", "armed", d)
cr6["audit"]["target_ip"] = "9.9.9.9"   # closure requested for a DIFFERENT ip than what's on record
cs6 = FakeCaseState(status="Open")
dkey6 = idempotency.decision_key("~a6", "~c6", l1_policy.POLICY_VERSION, "armed")
idempotency.record_tier_decision(dkey6, "L1", store_dir=d)
elig6 = l1_policy.evaluate_l1_closure_eligibility(
    "~a6", "~c6", dkey6, res6["verdict"], cr6, case_state_fn=cs6, store_dir=d)
check("ineligible", elig6["eligible"] is False)
check("reason is CONTAINMENT_TARGET_MISMATCH", l1_policy.Reason.CONTAINMENT_TARGET_MISMATCH in elig6["reason_codes"])


# ==============================================================================
# 7. Eligibility gate: case-state query fails
# ==============================================================================

print("\n=== 7. eligibility: case-state query raises -> CASE_STATE_QUERY_FAILED ===")
d = fresh_dir()
res7 = make_res()
cr7, _ = setup_verified_containment("~a7", "~c7", "202.61.130.163", "armed", d)
cs7 = FakeCaseState(raise_exc=True)
dkey7 = idempotency.decision_key("~a7", "~c7", l1_policy.POLICY_VERSION, "armed")
idempotency.record_tier_decision(dkey7, "L1", store_dir=d)
elig7 = l1_policy.evaluate_l1_closure_eligibility(
    "~a7", "~c7", dkey7, res7["verdict"], cr7, case_state_fn=cs7, store_dir=d)
check("ineligible", elig7["eligible"] is False)
check("reason is CASE_STATE_QUERY_FAILED", l1_policy.Reason.CASE_STATE_QUERY_FAILED in elig7["reason_codes"])
check("only ONE reason code stacked for this failure (no cascading duplicates)",
     elig7["reason_codes"].count(l1_policy.Reason.CASE_STATE_QUERY_FAILED) == 1)


# ==============================================================================
# 8. Eligibility gate: conflicting disposition already on the live case
# ==============================================================================

print("\n=== 8. eligibility: live case already FalsePositive -> CASE_DISPOSITION_CONFLICT ===")
d = fresh_dir()
res8 = make_res()
cr8, _ = setup_verified_containment("~a8", "~c8", "202.61.130.163", "armed", d)
cs8 = FakeCaseState(status="FalsePositive")
dkey8 = idempotency.decision_key("~a8", "~c8", l1_policy.POLICY_VERSION, "armed")
idempotency.record_tier_decision(dkey8, "L1", store_dir=d)
elig8 = l1_policy.evaluate_l1_closure_eligibility(
    "~a8", "~c8", dkey8, res8["verdict"], cr8, case_state_fn=cs8, store_dir=d)
check("ineligible", elig8["eligible"] is False)
check("reason is CASE_DISPOSITION_CONFLICT", l1_policy.Reason.CASE_DISPOSITION_CONFLICT in elig8["reason_codes"])


# ==============================================================================
# 9. Eligibility gate: policy-version drift since the decision was recorded
# ==============================================================================

print("\n=== 9. eligibility: policy-version drift -> ineligible ===")
d = fresh_dir()
res9 = make_res()
cr9, _ = setup_verified_containment("~a9", "~c9", "202.61.130.163", "armed", d,
                                    policy_version="l1-policy-v0-STALE")
cs9 = FakeCaseState(status="Open")
dkey9 = idempotency.decision_key("~a9", "~c9", l1_policy.POLICY_VERSION, "armed")
idempotency.record_tier_decision(dkey9, "L1", store_dir=d)
elig9 = l1_policy.evaluate_l1_closure_eligibility(
    "~a9", "~c9", dkey9, res9["verdict"], cr9, case_state_fn=cs9, store_dir=d)
check("ineligible", elig9["eligible"] is False)
check("gate policy_version_current is False", elig9["gates"]["policy_version_current"] is False)


# ==============================================================================
# 10. Idempotency short-circuit: already closed BY THIS WORKFLOW
# ==============================================================================

print("\n=== 10. close_l1_verified(): already closed by this workflow -> no-op success ===")
d = fresh_dir()
res10 = make_res()
cr10, _ = setup_verified_containment("~a10", "~c10", "202.61.130.163", "armed", d)
cs10 = FakeCaseState(status="TruePositive")
dkey10 = idempotency.decision_key("~a10", "~c10", l1_policy.POLICY_VERSION, "armed")
tier10 = idempotency.record_tier_decision(dkey10, "L1", store_dir=d)
close_key10 = idempotency.action_key(dkey10, "closure", "verified-true-positive")
idempotency.claim(close_key10, store_dir=d)
idempotency.complete(close_key10, idempotency.STATUS_COMPLETED, detail={"status": "TruePositive"}, store_dir=d)
calls = patch_all(case_state=cs10)
try:
    ok10 = ao.close_l1_verified(None, dkey10, "~a10", "~c10", res10["verdict"], res10, cr10, tier10,
                                case_state_fn=cs10, store_dir=d)
finally:
    unpatch_all()
check("returns True (already done)", ok10 is True)
check("close_case_l1 NOT called again", calls["close"] == 0)
check("comment NOT posted again", calls["comment"] == 0)


# ==============================================================================
# 11. Idempotency short-circuit: already TruePositive BY A HUMAN
# ==============================================================================

print("\n=== 11. close_l1_verified(): already TruePositive by a human -> adopted, no PATCH ===")
d = fresh_dir()
res11 = make_res()
cr11, _ = setup_verified_containment("~a11", "~c11", "202.61.130.163", "armed", d)
cs11 = FakeCaseState(status="TruePositive")   # a human already closed it; OUR key was never claimed
dkey11 = idempotency.decision_key("~a11", "~c11", l1_policy.POLICY_VERSION, "armed")
tier11 = idempotency.record_tier_decision(dkey11, "L1", store_dir=d)
calls = patch_all(case_state=cs11)
try:
    ok11 = ao.close_l1_verified(None, dkey11, "~a11", "~c11", res11["verdict"], res11, cr11, tier11,
                                case_state_fn=cs11, store_dir=d)
finally:
    unpatch_all()
check("returns True (adopted the human's disposition)", ok11 is True)
check("close_case_l1 NEVER called — the human's PATCH is not repeated", calls["close"] == 0)
close_key11 = idempotency.action_key(dkey11, "closure", "verified-true-positive")
rec11 = idempotency.get_status(close_key11, store_dir=d)
check("our own closure record is now COMPLETED (adopted)", rec11 is not None and rec11["status"] == idempotency.STATUS_COMPLETED)
check("adopted_from is recorded for the audit trail",
     rec11["detail"].get("adopted_from") == "human_or_prior_run", rec11["detail"])


# ==============================================================================
# 12. Structured comment content
# ==============================================================================

print("\n=== 12. build_closure_comment(): includes all required structured fields ===")
res12 = make_res()
cr12, _ = setup_verified_containment("~a12", "~c12", "202.61.130.163", "armed", fresh_dir())
elig12 = {"policy_version": l1_policy.POLICY_VERSION, "gates": {"g1": True},
          "reason_codes": [l1_policy.Reason.L1_TRUE_POSITIVE_CONTAINED]}
body12 = ao.build_closure_comment(res12, cr12, elig12)
for needle, label in [
    ("MALICIOUS", "verdict"), ("0.95", "confidence"), ("T1071.001", "MITRE technique"),
    ("202.61.130.163", "target IP"), ("job-1", "Cortex job id"), ("Success", "Cortex status"),
    ("ABSENT", "pfSense precheck"), ("PRESENT", "pfSense postcheck"),
    (l1_policy.POLICY_VERSION, "policy version"), ("L1_TRUE_POSITIVE_CONTAINED", "reason code"),
    ("search_past_cases", "tools used"),
]:
    check(f"comment includes {label}", needle in body12, body12[:200])


# ==============================================================================
# 13. Comment failure aborts closure BEFORE the PATCH
# ==============================================================================

print("\n=== 13. close_l1_verified(): comment post fails -> refuses to close, no PATCH ===")
d = fresh_dir()
res13 = make_res()
cr13, _ = setup_verified_containment("~a13", "~c13", "202.61.130.163", "armed", d)
cs13 = FakeCaseState(status="Open")
dkey13 = idempotency.decision_key("~a13", "~c13", l1_policy.POLICY_VERSION, "armed")
tier13 = idempotency.record_tier_decision(dkey13, "L1", store_dir=d)
calls = patch_all(comment_returns=False, case_state=cs13)
try:
    ok13 = ao.close_l1_verified(None, dkey13, "~a13", "~c13", res13["verdict"], res13, cr13, tier13,
                                case_state_fn=cs13, store_dir=d)
finally:
    unpatch_all()
check("returns False", ok13 is False)
check("close_case_l1 NEVER called (comment gate blocks it)", calls["close"] == 0)
check("mailer called (escalation)", calls["mailer"] == 1)
close_key13 = idempotency.action_key(dkey13, "closure", "verified-true-positive")
rec13 = idempotency.get_status(close_key13, store_dir=d)
check("closure record is FAILED with CASE_COMMENT_FAILED",
     rec13["status"] == idempotency.STATUS_FAILED and
     rec13["detail"].get("reason") == l1_policy.Reason.CASE_COMMENT_FAILED, rec13)


# ==============================================================================
# 14. PATCH itself fails
# ==============================================================================

print("\n=== 14. close_l1_verified(): close_case_l1() reports failure -> escalate, case stays open ===")
d = fresh_dir()
res14 = make_res()
cr14, _ = setup_verified_containment("~a14", "~c14", "202.61.130.163", "armed", d)
cs14 = FakeCaseState(status="Open")
dkey14 = idempotency.decision_key("~a14", "~c14", l1_policy.POLICY_VERSION, "armed")
tier14 = idempotency.record_tier_decision(dkey14, "L1", store_dir=d)
calls = patch_all(close_returns=False, case_state=cs14)
try:
    ok14 = ao.close_l1_verified(None, dkey14, "~a14", "~c14", res14["verdict"], res14, cr14, tier14,
                                case_state_fn=cs14, store_dir=d)
finally:
    unpatch_all()
check("returns False", ok14 is False)
check("comment WAS posted (it's posted before the PATCH is attempted)", calls["comment"] == 1)
check("mailer called (escalation)", calls["mailer"] == 1)
close_key14 = idempotency.action_key(dkey14, "closure", "verified-true-positive")
rec14 = idempotency.get_status(close_key14, store_dir=d)
check("closure record is FAILED with CASE_CLOSE_FAILED",
     rec14["status"] == idempotency.STATUS_FAILED and
     rec14["detail"].get("reason") == l1_policy.Reason.CASE_CLOSE_FAILED, rec14)


# ==============================================================================
# 15. PATCH succeeds + independent verification confirms -> COMPLETED
# ==============================================================================

print("\n=== 15. close_l1_verified(): PATCH succeeds, independent re-query CONFIRMS -> COMPLETED ===")
d = fresh_dir()
res15 = make_res()
cr15, _ = setup_verified_containment("~a15", "~c15", "202.61.130.163", "armed", d)
cs15 = FakeCaseState(status="Open")   # only flips to TruePositive as a SIDE EFFECT of the PATCH
dkey15 = idempotency.decision_key("~a15", "~c15", l1_policy.POLICY_VERSION, "armed")
tier15 = idempotency.record_tier_decision(dkey15, "L1", store_dir=d)
calls = patch_all(close_returns=True, close_side_effect_status="TruePositive", case_state=cs15)
try:
    ok15 = ao.close_l1_verified(None, dkey15, "~a15", "~c15", res15["verdict"], res15, cr15, tier15,
                                case_state_fn=cs15, store_dir=d)
finally:
    unpatch_all()
check("returns True — verification, not just the PATCH's own HTTP success, confirmed it", ok15 is True)
check("case_state_fn was queried AFTER the PATCH (saw the flipped status)", cs15.status == "TruePositive")


# ==============================================================================
# 16. PATCH succeeds but re-query MISMATCHES -> left ambiguous, not COMPLETED
# ==============================================================================

print("\n=== 16. close_l1_verified(): PATCH succeeds but re-query still shows old status -> ambiguous ===")
d = fresh_dir()
res16 = make_res()
cr16, _ = setup_verified_containment("~a16", "~c16", "202.61.130.163", "armed", d)
cs16 = FakeCaseState(status="Open")   # deliberately NEVER flips — simulates a stuck/failed PATCH
dkey16 = idempotency.decision_key("~a16", "~c16", l1_policy.POLICY_VERSION, "armed")
tier16 = idempotency.record_tier_decision(dkey16, "L1", store_dir=d)
calls = patch_all(close_returns=True, close_side_effect_status=None, case_state=cs16)
try:
    ok16 = ao.close_l1_verified(None, dkey16, "~a16", "~c16", res16["verdict"], res16, cr16, tier16,
                                case_state_fn=cs16, store_dir=d)
finally:
    unpatch_all()
check("returns False — HTTP success alone was NOT trusted", ok16 is False)
check("mailer called (escalation)", calls["mailer"] == 1)
close_key16 = idempotency.action_key(dkey16, "closure", "verified-true-positive")
rec16 = idempotency.get_status(close_key16, store_dir=d)
check("closure record LEFT INTENDED, not marked FAILED or COMPLETED — genuinely unknown",
     rec16["status"] == idempotency.STATUS_INTENDED, rec16)


# ==============================================================================
# 17. Duplicate closure attempt short-circuits (no second PATCH)
# ==============================================================================

print("\n=== 17. close_l1_verified(): duplicate attempt after success -> no second PATCH ===")
d = fresh_dir()
res17 = make_res()
cr17, _ = setup_verified_containment("~a17", "~c17", "202.61.130.163", "armed", d)
cs17 = FakeCaseState(status="Open")
dkey17 = idempotency.decision_key("~a17", "~c17", l1_policy.POLICY_VERSION, "armed")
tier17 = idempotency.record_tier_decision(dkey17, "L1", store_dir=d)
calls = patch_all(close_returns=True, close_side_effect_status="TruePositive", case_state=cs17)
try:
    ok17a = ao.close_l1_verified(None, dkey17, "~a17", "~c17", res17["verdict"], res17, cr17, tier17,
                                 case_state_fn=cs17, store_dir=d)
    ok17b = ao.close_l1_verified(None, dkey17, "~a17", "~c17", res17["verdict"], res17, cr17, tier17,
                                 case_state_fn=cs17, store_dir=d)
finally:
    unpatch_all()
check("first call succeeds", ok17a is True)
check("second call also reports success (idempotent)", ok17b is True)
check("close_case_l1 called exactly ONCE across both calls", calls["close"] == 1)
check("comment posted exactly ONCE across both calls", calls["comment"] == 1)


# ==============================================================================
# 18. Ambiguous record (crash after claim, before comment/PATCH) — already TP live
# ==============================================================================

print("\n=== 18. ambiguous closure: live case ALREADY TruePositive -> adopted, no re-PATCH ===")
d = fresh_dir()
res18 = make_res()
cr18, _ = setup_verified_containment("~a18", "~c18", "202.61.130.163", "armed", d)
cs18 = FakeCaseState(status="TruePositive")   # e.g. the PATCH from the crashed run actually landed
dkey18 = idempotency.decision_key("~a18", "~c18", l1_policy.POLICY_VERSION, "armed")
tier18 = idempotency.record_tier_decision(dkey18, "L1", store_dir=d)
close_key18 = idempotency.action_key(dkey18, "closure", "verified-true-positive")
idempotency.claim(close_key18, store_dir=d)   # claimed but never completed — simulates the crash
calls = patch_all(case_state=cs18)
try:
    ok18 = ao.close_l1_verified(None, dkey18, "~a18", "~c18", res18["verdict"], res18, cr18, tier18,
                                case_state_fn=cs18, store_dir=d)
finally:
    unpatch_all()
check("resolves to True", ok18 is True)
check("close_case_l1 was NOT called — the case was already TruePositive live", calls["close"] == 0)
check("comment was NOT posted — the eligibility short-circuit adopts the live fact directly",
     calls["comment"] == 0)
rec18 = idempotency.get_status(close_key18, store_dir=d)
check("closure record now COMPLETED (the stale INTENDED record was resolved, not left stuck)",
     rec18["status"] == idempotency.STATUS_COMPLETED, rec18)
check("adopted_from marks it as adopted from the live/prior-run fact",
     rec18["detail"].get("adopted_from") == "human_or_prior_run", rec18["detail"])


# ==============================================================================
# 19. Ambiguous record — NOT yet TruePositive, no conflict -> safe re-apply (PATCH is idempotent)
# ==============================================================================

print("\n=== 19. ambiguous closure: not yet TruePositive, no conflict -> re-applies the idempotent PATCH ===")
d = fresh_dir()
res19 = make_res()
cr19, _ = setup_verified_containment("~a19", "~c19", "202.61.130.163", "armed", d)
cs19 = FakeCaseState(status="Open")   # the crashed run's PATCH never actually landed
dkey19 = idempotency.decision_key("~a19", "~c19", l1_policy.POLICY_VERSION, "armed")
tier19 = idempotency.record_tier_decision(dkey19, "L1", store_dir=d)
close_key19 = idempotency.action_key(dkey19, "closure", "verified-true-positive")
idempotency.claim(close_key19, store_dir=d)
calls = patch_all(close_returns=True, close_side_effect_status="TruePositive", case_state=cs19)
try:
    ok19 = ao.close_l1_verified(None, dkey19, "~a19", "~c19", res19["verdict"], res19, cr19, tier19,
                                case_state_fn=cs19, store_dir=d)
finally:
    unpatch_all()
check("resolves to True after the safe re-apply", ok19 is True)
check("close_case_l1 WAS called exactly once (the recovery re-apply) — safe, PATCH is idempotent",
     calls["close"] == 1)
check("comment was NOT re-posted (ambiguous recovery re-applies the PATCH, not the pre-closure comment)",
     calls["comment"] == 0)
rec19 = idempotency.get_status(close_key19, store_dir=d)
check("closure record now COMPLETED", rec19["status"] == idempotency.STATUS_COMPLETED)


# ==============================================================================
# 20. Ambiguous record — live case shows a CONFLICTING human disposition
# ==============================================================================

print("\n=== 20. ambiguous closure: live case turns FalsePositive (human) between the two queries ===")
d = fresh_dir()
res20 = make_res()
cr20, _ = setup_verified_containment("~a20", "~c20", "202.61.130.163", "armed", d)
# A genuine race: eligibility's ONE query still sees "Open" (so gates pass and
# closure is attempted), but a human sets FalsePositive in the exact window
# before the ambiguous-record recovery's re-query — the SECOND call flips it.
cs20 = FakeCaseState(status="Open", flip_to="FalsePositive", flip_after=1)
dkey20 = idempotency.decision_key("~a20", "~c20", l1_policy.POLICY_VERSION, "armed")
tier20 = idempotency.record_tier_decision(dkey20, "L1", store_dir=d)
close_key20 = idempotency.action_key(dkey20, "closure", "verified-true-positive")
idempotency.claim(close_key20, store_dir=d)   # simulates a concurrent/crashed attempt already claimed it
calls = patch_all(case_state=cs20)
try:
    ok20 = ao.close_l1_verified(None, dkey20, "~a20", "~c20", res20["verdict"], res20, cr20, tier20,
                                case_state_fn=cs20, store_dir=d)
finally:
    unpatch_all()
check("resolves to False — a human's disposition is never silently overwritten", ok20 is False)
check("close_case_l1 was NEVER called — the conflicting live state blocks any re-apply", calls["close"] == 0)
check("mailer called (escalation)", calls["mailer"] == 1)
check("case_state_fn was queried twice (eligibility, then the ambiguous re-check)", cs20.calls == 2)
rec20 = idempotency.get_status(close_key20, store_dir=d)
check("closure record marked FAILED (a real, resolved failure — not left hanging)",
     rec20["status"] == idempotency.STATUS_FAILED, rec20)
check("resolved via the closure-specific recovery path",
     rec20["detail"].get("resolved_via") == "closure_recovery_reapply", rec20["detail"])


# ==============================================================================
# Summary
# ==============================================================================

if __name__ == "__main__":
    shutil.rmtree(STORE, ignore_errors=True)
    print("\n" + "=" * 70)
    print(f"  TRUEPOSITIVE CLOSURE TESTS: {len(PASS)} passed, {len(FAIL)} failed")
    print("=" * 70)
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    sys.exit(0)
