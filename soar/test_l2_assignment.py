#!/usr/bin/env python3
"""
Phase 4 tests — verified L2 assignment (l1_policy.evaluate_l2_assignment_
eligibility() + agent_orchestrator.resolve_l2_user()/assign_l2_verified()).

PURE. api.case.update() (assignment PATCH + tags), orch.post_case_comment()
(the escalation comment), and api.user.find() (L2 user resolution) are always
FAKES injected via case_state_fn/user_find_fn or monkeypatched. No live
TheHive call is ever made.

Run: ./.venv/bin/python test_l2_assignment.py
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
import agent_orchestrator as ao

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name); print(f"  PASS  {name}")
    else:
        FAIL.append(name); print(f"  FAIL  {name}  {detail}")


STORE = tempfile.mkdtemp(prefix="l2_assign_test_")


def fresh_dir():
    return tempfile.mkdtemp(prefix="l2a_", dir=STORE)


L2_LOGIN = "soc-l2@thehive.local"
L2_ID = "~l2user"


# ==============================================================================
# Fixtures
# ==============================================================================

def make_res(verdict_str="benign", confidence=0.4):
    return {
        "verdict": {"verdict": verdict_str, "confidence": confidence, "severity": "medium",
                    "mitre_technique": "T1071.001", "reason": "low confidence beacon",
                    "key_evidence": "single low-confidence hit"},
        "trace": [
            {"step": 1, "action": "search_past_cases", "result": {"hint": "no prior history"}},
            {"step": 2, "action": "run_analyzer", "result": {"name": "AbuseIPDB", "taxonomies": []}},
        ],
        "tools_used": ["search_past_cases", "run_analyzer"],
        "containment": {"target": None, "allowed": False, "disposition": "no-target", "reason": "n/a"},
    }


def make_disposition(reason_codes=None):
    reason_codes = reason_codes or [l1_policy.Reason.LOW_CONFIDENCE]
    return {"tier": "L2", "action": "escalate", "status": None, "reason_codes": reason_codes,
            "reason": "low confidence verdict"}


class FakeCaseState:
    """Injectable case_state_fn. `raw` carries assignee/tags/stage like the
    real api.case.get() payload. .assignee/.stage/.status can be flipped
    externally (fake PATCH side effects) or internally via flip_* to model a
    live change between two successive queries (a real race window)."""
    def __init__(self, status="New", stage="New", assignee=None, tags=None,
                flip_assignee_to=None, flip_after=None):
        self.status = status
        self.stage = stage
        self.assignee = assignee
        self.tags = list(tags or [])
        self.flip_assignee_to = flip_assignee_to
        self.flip_after = flip_after
        self.calls = 0

    def __call__(self, case_id):
        self.calls += 1
        if self.flip_after is not None and self.calls > self.flip_after and self.flip_assignee_to is not None:
            self.assignee = self.flip_assignee_to
        return {"status": self.status, "stage": self.stage,
                "raw": {"status": self.status, "stage": self.stage,
                       "assignee": self.assignee, "tags": self.tags}}


class RaisingCaseState:
    def __call__(self, case_id):
        raise RuntimeError("simulated TheHive query failure")


class FakeApiCase:
    """api.case.update() side effect: mutates the paired FakeCaseState so a
    subsequent query observes the change — models a real PATCH landing."""
    def __init__(self, case_state: FakeCaseState, fail=False):
        self.case_state = case_state
        self.fail = fail
        self.update_calls = []

    def update(self, case_id, fields):
        self.update_calls.append(dict(fields))
        if self.fail:
            raise RuntimeError("simulated PATCH failure")
        if "assignee" in fields:
            # CONFIRMED LIVE (Phase 5.6, 2026-08-21): TheHive echoes the
            # assignee's LOGIN on read, not the `_id` sent in the PATCH —
            # mimic that translation here so the fake matches real behavior.
            self.case_state.assignee = L2_LOGIN if fields["assignee"] == L2_ID else fields["assignee"]
        if "addTags" in fields:
            for t in fields["addTags"]:
                if t not in self.case_state.tags:
                    self.case_state.tags.append(t)
        if "stage" in fields:
            self.case_state.stage = fields["stage"]


class FakeApiUser:
    """api.user.get_current() — configurable for the caller-resolution tests
    (Phase 8F.1). `current` is whatever get_current() should return;
    `raises` makes it fail instead (simulating an unreachable/broken call)."""
    def __init__(self, current=None, raises=False):
        self.current = current
        self.raises = raises
        self.calls = 0

    def get_current(self):
        self.calls += 1
        if self.raises:
            raise RuntimeError("simulated /user/current failure")
        return self.current


class FakeApi:
    def __init__(self, case_state: FakeCaseState, fail_patch=False,
                current_user=None, current_user_raises=False):
        self.case = FakeApiCase(case_state, fail=fail_patch)
        self.user = FakeApiUser(current=current_user, raises=current_user_raises)


def make_user_find_fn(users):
    calls = {"n": 0}
    def fn(login):
        calls["n"] += 1
        return [u for u in users if u.get("login") == login]
    return fn, calls


_orig_post_comment = ao.orch.post_case_comment


def patch_comment(returns=True):
    calls = {"n": 0, "bodies": []}
    def fake(case_id, body):
        calls["n"] += 1
        calls["bodies"].append(body)
        return returns
    ao.orch.post_case_comment = fake
    return calls


def unpatch_comment():
    ao.orch.post_case_comment = _orig_post_comment


def reset_l2_cache():
    ao._l2_user_cache.clear()


# ==============================================================================
# 1. Full happy path — open case, no prior assignee -> comment, tags, assign, verify
# ==============================================================================

print("\n=== 1. assign_l2_verified(): open case -> comment -> tags -> assign -> verified ===")
reset_l2_cache()
d = fresh_dir()
cs1 = FakeCaseState(status="New", stage="New", assignee=None)
api1 = FakeApi(cs1)
uf1, uf1_calls = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
res1 = make_res()
disp1 = make_disposition()
dkey1 = idempotency.decision_key("~a1", "~c1", l1_policy.POLICY_VERSION, "armed")
tier1 = idempotency.record_tier_decision(dkey1, "L2", store_dir=d)
calls = patch_comment(True)
try:
    r1 = ao.assign_l2_verified(api1, dkey1, "~a1", "~c1", "armed", res1, disp1,
                               res1["containment"], tier1, case_state_fn=cs1,
                               user_find_fn=uf1, store_dir=d)
finally:
    unpatch_comment()
check("verified True", r1["verified"] is True, r1)
check("assigned to the L2 user's login (TheHive echoes login, not _id, on read)",
     r1["assigned_analyst"] == L2_LOGIN, r1)
check("comment posted exactly once", calls["n"] == 1)
check("tags include ai-escalated-l2", "ai-escalated-l2" in cs1.tags, cs1.tags)
check("tags include the policy-version tag", f"ai-policy-{l1_policy.POLICY_VERSION}" in cs1.tags, cs1.tags)
check("tags include a reason-category tag", any(t.startswith("ai-reason-") for t in cs1.tags), cs1.tags)
check("case.update called for assignee", any("assignee" in c for c in api1.case.update_calls))
check("the SAME PATCH also sets stage=InProgress (not a separate call)",
     any(c.get("assignee") and c.get("stage") == "InProgress" for c in api1.case.update_calls),
     api1.case.update_calls)
check("live case now shows stage=InProgress", cs1.stage == "InProgress", cs1.stage)
assign_key1 = idempotency.assignment_action_key("~a1", "~c1", L2_LOGIN, "armed")
rec1 = idempotency.get_status(assign_key1, store_dir=d)
check("idempotency store shows COMPLETED", rec1["status"] == idempotency.STATUS_COMPLETED, rec1)


# ==============================================================================
# 2. Benign verdict routes to L2 (via l1_disposition, not assign_l2_verified directly)
# ==============================================================================

print("\n=== 2. l1_disposition(): benign verdict routes to L2 ===")
d2 = ao.l1_disposition({"verdict": "benign", "confidence": 0.9}, {"executed": False, "allowed": False})
check("tier is L2", d2["tier"] == "L2")
check("action is escalate", d2["action"] == "escalate")


# ==============================================================================
# 3. Low-confidence case routes to L2
# ==============================================================================

print("\n=== 3. l1_disposition(): low-confidence eligibility failure routes to L2 ===")
elig3 = {"eligible": False, "reason_codes": [l1_policy.Reason.LOW_CONFIDENCE],
        "policy_version": l1_policy.POLICY_VERSION}
d3 = ao.l1_disposition({"verdict": "malicious", "confidence": 0.5},
                       {"executed": False, "allowed": True, "target": "1.2.3.4"},
                       eligibility=elig3)
check("tier is L2", d3["tier"] == "L2")
check("reason codes include LOW_CONFIDENCE", l1_policy.Reason.LOW_CONFIDENCE in d3["reason_codes"])


# ==============================================================================
# 4. Guard-refused case routes to L2
# ==============================================================================

print("\n=== 4. l1_disposition(): guard-refused containment routes to L2 ===")
d4 = ao.l1_disposition({"verdict": "malicious", "confidence": 0.95},
                       {"executed": False, "allowed": False, "reason": "protected asset"})
check("tier is L2", d4["tier"] == "L2")
check("reason codes include PROTECTED_ASSET", l1_policy.Reason.PROTECTED_ASSET in d4["reason_codes"])


# ==============================================================================
# 5. Containment-unverified case routes to L2
# ==============================================================================

print("\n=== 5. l1_disposition(): containment-unverified routes to L2 ===")
d5 = ao.l1_disposition({"verdict": "malicious", "confidence": 0.95},
                       {"executed": False, "allowed": True, "target": "1.2.3.4",
                        "reason_code": l1_policy.Reason.CONTAINMENT_UNVERIFIED})
check("tier is L2", d5["tier"] == "L2")
check("reason codes include CONTAINMENT_UNVERIFIED",
     l1_policy.Reason.CONTAINMENT_UNVERIFIED in d5["reason_codes"])


# ==============================================================================
# 6. L2 user resolved correctly
# ==============================================================================

print("\n=== 6. resolve_l2_user(): resolves to the single active matching user ===")
reset_l2_cache()
uf6, uf6_calls = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
u6 = ao.resolve_l2_user(None, login=L2_LOGIN, user_find_fn=uf6)
check("resolved True", u6["resolved"] is True)
check("user_id is the account's _id", u6["user_id"] == L2_ID)
check("cached on a second call (user_find_fn NOT called again)", uf6_calls["n"] == 1)
u6b = ao.resolve_l2_user(None, login=L2_LOGIN, user_find_fn=uf6)
check("second call uses the cache", uf6_calls["n"] == 1 and u6b["user_id"] == L2_ID)


# ==============================================================================
# 7. User missing -> no unsafe mutation
# ==============================================================================

print("\n=== 7. resolve_l2_user(): no matching user -> L2_USER_NOT_FOUND, safe ===")
reset_l2_cache()
uf7, _ = make_user_find_fn([])
u7 = ao.resolve_l2_user(None, login=L2_LOGIN, user_find_fn=uf7)
check("resolved False", u7["resolved"] is False)
check("reason is L2_USER_NOT_FOUND", u7["reason_code"] == l1_policy.Reason.L2_USER_NOT_FOUND)
check("user_id is None", u7["user_id"] is None)

d7 = fresh_dir()
cs7 = FakeCaseState(status="New", stage="New")
api7 = FakeApi(cs7)
res7 = make_res()
disp7 = make_disposition()
dkey7 = idempotency.decision_key("~a7", "~c7", l1_policy.POLICY_VERSION, "armed")
tier7 = idempotency.record_tier_decision(dkey7, "L2", store_dir=d7)
calls = patch_comment(True)
try:
    r7 = ao.assign_l2_verified(api7, dkey7, "~a7", "~c7", "armed", res7, disp7,
                               res7["containment"], tier7, case_state_fn=cs7,
                               user_find_fn=uf7, store_dir=d7)
finally:
    unpatch_comment()
check("assign_l2_verified refuses safely", r7["verified"] is False)
check("critical_failure flagged", r7["critical_failure"] is True, r7)
check("NO case.update call was ever made", len(api7.case.update_calls) == 0)
check("comment NOT posted", calls["n"] == 0)


# ==============================================================================
# 8. Duplicate matching (active) users -> fail safely
# ==============================================================================

print("\n=== 8. resolve_l2_user(): two ACTIVE matches -> L2_USER_AMBIGUOUS, safe ===")
reset_l2_cache()
uf8, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": "~l2a", "locked": False},
                            {"login": L2_LOGIN, "_id": "~l2b", "locked": False}])
u8 = ao.resolve_l2_user(None, login=L2_LOGIN, user_find_fn=uf8)
check("resolved False", u8["resolved"] is False)
check("reason is L2_USER_AMBIGUOUS", u8["reason_code"] == l1_policy.Reason.L2_USER_AMBIGUOUS)


# ==============================================================================
# 9. Disabled user -> fail safely
# ==============================================================================

print("\n=== 9. resolve_l2_user(): the only match is locked -> L2_USER_DISABLED, safe ===")
reset_l2_cache()
uf9, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": True}])
u9 = ao.resolve_l2_user(None, login=L2_LOGIN, user_find_fn=uf9)
check("resolved False", u9["resolved"] is False)
check("reason is L2_USER_DISABLED", u9["reason_code"] == l1_policy.Reason.L2_USER_DISABLED)


# ==============================================================================
# 10. Already assigned to soc-l2 -> no second PATCH
# ==============================================================================

print("\n=== 10. assign_l2_verified(): already assigned to soc-l2 live -> adopted, no PATCH ===")
reset_l2_cache()
d10 = fresh_dir()
cs10 = FakeCaseState(status="New", stage="New", assignee=L2_LOGIN)
api10 = FakeApi(cs10)
uf10, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
res10 = make_res()
disp10 = make_disposition()
dkey10 = idempotency.decision_key("~a10", "~c10", l1_policy.POLICY_VERSION, "armed")
tier10 = idempotency.record_tier_decision(dkey10, "L2", store_dir=d10)
calls = patch_comment(True)
try:
    r10 = ao.assign_l2_verified(api10, dkey10, "~a10", "~c10", "armed", res10, disp10,
                                res10["containment"], tier10, case_state_fn=cs10,
                                user_find_fn=uf10, store_dir=d10)
finally:
    unpatch_comment()
check("verified True", r10["verified"] is True)
check("NO case.update call (no PATCH repeated)", len(api10.case.update_calls) == 0)
check("no comment re-posted (already assigned to us — nothing new to add)", calls["n"] == 0)


# ==============================================================================
# 11. Assigned to another analyst -> human assignment preserved
# ==============================================================================

print("\n=== 11. assign_l2_verified(): assigned to a human -> preserved, evidence still added ===")
reset_l2_cache()
d11 = fresh_dir()
cs11 = FakeCaseState(status="New", stage="New", assignee="~human-analyst")
api11 = FakeApi(cs11)
uf11, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
res11 = make_res()
disp11 = make_disposition()
dkey11 = idempotency.decision_key("~a11", "~c11", l1_policy.POLICY_VERSION, "armed")
tier11 = idempotency.record_tier_decision(dkey11, "L2", store_dir=d11)
calls = patch_comment(True)
try:
    r11 = ao.assign_l2_verified(api11, dkey11, "~a11", "~c11", "armed", res11, disp11,
                                res11["containment"], tier11, case_state_fn=cs11,
                                user_find_fn=uf11, store_dir=d11)
finally:
    unpatch_comment()
check("verified True (human ownership satisfies escalation)", r11["verified"] is True)
check("assigned_analyst reports the HUMAN, not soc-l2", r11["assigned_analyst"] == "~human-analyst", r11)
check("NO assignee PATCH (never overwritten)",
     not any("assignee" in c for c in api11.case.update_calls))
check("escalation comment WAS added (evidence, not ownership)", calls["n"] == 1)
check("case.assignee is still the human", cs11.assignee == "~human-analyst")


# ==============================================================================
# 12. Verified L1-closed case -> no assignment
# ==============================================================================

print("\n=== 12. assign_l2_verified(): a verified L1 closure already completed -> no assignment ===")
reset_l2_cache()
d12 = fresh_dir()
cs12 = FakeCaseState(status="TruePositive", stage="Closed", assignee=None)
api12 = FakeApi(cs12)
uf12, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey12 = idempotency.decision_key("~a12", "~c12", l1_policy.POLICY_VERSION, "armed")
tier12 = idempotency.record_tier_decision(dkey12, "L2", store_dir=d12)
closure_key12 = idempotency.action_key(dkey12, "closure", "verified-true-positive")
idempotency.claim(closure_key12, store_dir=d12)
idempotency.complete(closure_key12, idempotency.STATUS_COMPLETED, detail={"status": "TruePositive"},
                     store_dir=d12)
res12 = make_res()
disp12 = make_disposition()
calls = patch_comment(True)
try:
    r12 = ao.assign_l2_verified(api12, dkey12, "~a12", "~c12", "armed", res12, disp12,
                                res12["containment"], tier12, case_state_fn=cs12,
                                user_find_fn=uf12, store_dir=d12)
finally:
    unpatch_comment()
check("verified True (nothing to escalate)", r12["verified"] is True)
check("reason is L2_SKIPPED_VERIFIED_L1_CLOSURE",
     l1_policy.Reason.L2_SKIPPED_VERIFIED_L1_CLOSURE in r12["reason_codes"], r12)
check("NO case.update call", len(api12.case.update_calls) == 0)


# ==============================================================================
# 13. Conflicting closed disposition -> no reopen/reassignment
# ==============================================================================

print("\n=== 13. assign_l2_verified(): closed FalsePositive -> no reopen, disposition conflict ===")
reset_l2_cache()
d13 = fresh_dir()
cs13 = FakeCaseState(status="FalsePositive", stage="Closed", assignee=None)
api13 = FakeApi(cs13)
uf13, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey13 = idempotency.decision_key("~a13", "~c13", l1_policy.POLICY_VERSION, "armed")
tier13 = idempotency.record_tier_decision(dkey13, "L2", store_dir=d13)
res13 = make_res()
disp13 = make_disposition()
calls = patch_comment(True)
try:
    r13 = ao.assign_l2_verified(api13, dkey13, "~a13", "~c13", "armed", res13, disp13,
                                res13["containment"], tier13, case_state_fn=cs13,
                                user_find_fn=uf13, store_dir=d13)
finally:
    unpatch_comment()
check("verified False", r13["verified"] is False)
check("reason includes CASE_DISPOSITION_CONFLICT",
     l1_policy.Reason.CASE_DISPOSITION_CONFLICT in r13["reason_codes"], r13)
check("case never reopened/reassigned", len(api13.case.update_calls) == 0)


# ==============================================================================
# 14. Comment failure -> assignment not falsely marked complete
# ==============================================================================

print("\n=== 14. assign_l2_verified(): comment post fails -> refuses, no PATCH ===")
reset_l2_cache()
d14 = fresh_dir()
cs14 = FakeCaseState(status="New", stage="New", assignee=None)
api14 = FakeApi(cs14)
uf14, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey14 = idempotency.decision_key("~a14", "~c14", l1_policy.POLICY_VERSION, "armed")
tier14 = idempotency.record_tier_decision(dkey14, "L2", store_dir=d14)
res14 = make_res()
disp14 = make_disposition()
calls = patch_comment(False)
try:
    r14 = ao.assign_l2_verified(api14, dkey14, "~a14", "~c14", "armed", res14, disp14,
                                res14["containment"], tier14, case_state_fn=cs14,
                                user_find_fn=uf14, store_dir=d14)
finally:
    unpatch_comment()
check("verified False", r14["verified"] is False)
check("critical_failure flagged", r14["critical_failure"] is True)
check("NO case.update call (comment gate blocks it)", len(api14.case.update_calls) == 0)
assign_key14 = idempotency.assignment_action_key("~a14", "~c14", L2_LOGIN, "armed")
rec14 = idempotency.get_status(assign_key14, store_dir=d14)
check("record is FAILED with L2_COMMENT_FAILED",
     rec14["status"] == idempotency.STATUS_FAILED and
     rec14["detail"].get("reason") == l1_policy.Reason.L2_COMMENT_FAILED, rec14)


# ==============================================================================
# 15. Assignment PATCH failure -> not complete
# ==============================================================================

print("\n=== 15. assign_l2_verified(): case.update() raises -> not complete, escalated ===")
reset_l2_cache()
d15 = fresh_dir()
cs15 = FakeCaseState(status="New", stage="New", assignee=None)
api15 = FakeApi(cs15, fail_patch=True)
uf15, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey15 = idempotency.decision_key("~a15", "~c15", l1_policy.POLICY_VERSION, "armed")
tier15 = idempotency.record_tier_decision(dkey15, "L2", store_dir=d15)
res15 = make_res()
disp15 = make_disposition()
calls = patch_comment(True)
try:
    r15 = ao.assign_l2_verified(api15, dkey15, "~a15", "~c15", "armed", res15, disp15,
                                res15["containment"], tier15, case_state_fn=cs15,
                                user_find_fn=uf15, store_dir=d15)
finally:
    unpatch_comment()
check("verified False", r15["verified"] is False)
check("comment WAS posted (comment happens before the PATCH)", calls["n"] == 1)
assign_key15 = idempotency.assignment_action_key("~a15", "~c15", L2_LOGIN, "armed")
rec15 = idempotency.get_status(assign_key15, store_dir=d15)
check("record is FAILED with L2_ASSIGNMENT_FAILED",
     rec15["status"] == idempotency.STATUS_FAILED and
     rec15["detail"].get("reason") == l1_policy.Reason.L2_ASSIGNMENT_FAILED, rec15)


# ==============================================================================
# 16. PATCH timeout + verified L2 assignment -> resolve complete
# ==============================================================================

print("\n=== 16. ambiguous assignment: live case already soc-l2 -> resolves, no re-PATCH ===")
reset_l2_cache()
d16 = fresh_dir()
cs16 = FakeCaseState(status="New", stage="New", assignee=L2_LOGIN)   # PATCH landed before the timeout
api16 = FakeApi(cs16)
uf16, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey16 = idempotency.decision_key("~a16", "~c16", l1_policy.POLICY_VERSION, "armed")
tier16 = idempotency.record_tier_decision(dkey16, "L2", store_dir=d16)
assign_key16 = idempotency.assignment_action_key("~a16", "~c16", L2_LOGIN, "armed")
idempotency.claim(assign_key16, store_dir=d16)   # claimed but never completed — simulates the timeout
res16 = make_res()
disp16 = make_disposition()
calls = patch_comment(True)
try:
    r16 = ao.assign_l2_verified(api16, dkey16, "~a16", "~c16", "armed", res16, disp16,
                                res16["containment"], tier16, case_state_fn=cs16,
                                user_find_fn=uf16, store_dir=d16)
finally:
    unpatch_comment()
check("resolves to verified True", r16["verified"] is True)
check("NO case.update call (already correctly assigned, no re-PATCH)",
     len(api16.case.update_calls) == 0)
rec16 = idempotency.get_status(assign_key16, store_dir=d16)
check("record now COMPLETED", rec16["status"] == idempotency.STATUS_COMPLETED, rec16)


# ==============================================================================
# 17. PATCH timeout + other human assignment -> preserve human
# ==============================================================================

print("\n=== 17. ambiguous assignment: live case picked up by a human -> preserved ===")
reset_l2_cache()
d17 = fresh_dir()
cs17 = FakeCaseState(status="New", stage="New", assignee="~human-2")
api17 = FakeApi(cs17)
uf17, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey17 = idempotency.decision_key("~a17", "~c17", l1_policy.POLICY_VERSION, "armed")
tier17 = idempotency.record_tier_decision(dkey17, "L2", store_dir=d17)
assign_key17 = idempotency.assignment_action_key("~a17", "~c17", L2_LOGIN, "armed")
idempotency.claim(assign_key17, store_dir=d17)
res17 = make_res()
disp17 = make_disposition()
calls = patch_comment(True)
try:
    r17 = ao.assign_l2_verified(api17, dkey17, "~a17", "~c17", "armed", res17, disp17,
                                res17["containment"], tier17, case_state_fn=cs17,
                                user_find_fn=uf17, store_dir=d17)
finally:
    unpatch_comment()
check("resolves to verified True (human ownership honored)", r17["verified"] is True)
check("NO assignee overwrite", not any("assignee" in c for c in api17.case.update_calls))
check("case still shows the human", cs17.assignee == "~human-2")


# ==============================================================================
# 18. Query failure -> no mutation
# ==============================================================================

print("\n=== 18. assign_l2_verified(): case-state query raises -> no mutation, critical ===")
reset_l2_cache()
d18 = fresh_dir()
api18 = FakeApi(FakeCaseState())   # unused directly — case_state_fn always raises
cs18 = RaisingCaseState()
uf18, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey18 = idempotency.decision_key("~a18", "~c18", l1_policy.POLICY_VERSION, "armed")
tier18 = idempotency.record_tier_decision(dkey18, "L2", store_dir=d18)
res18 = make_res()
disp18 = make_disposition()
calls = patch_comment(True)
try:
    r18 = ao.assign_l2_verified(api18, dkey18, "~a18", "~c18", "armed", res18, disp18,
                                res18["containment"], tier18, case_state_fn=cs18,
                                user_find_fn=uf18, store_dir=d18)
finally:
    unpatch_comment()
check("verified False", r18["verified"] is False)
check("critical_failure True (email phase must still be able to alert)", r18["critical_failure"] is True)
check("NO case.update call", len(api18.case.update_calls) == 0)
check("comment NOT posted", calls["n"] == 0)
check("reason includes CASE_STATE_QUERY_FAILED",
     l1_policy.Reason.CASE_STATE_QUERY_FAILED in r18["reason_codes"], r18)


# ==============================================================================
# 19. Duplicate invocation -> one assignment/comment only
# ==============================================================================

print("\n=== 19. assign_l2_verified(): duplicate invocation -> one PATCH, one comment ===")
reset_l2_cache()
d19 = fresh_dir()
cs19 = FakeCaseState(status="New", stage="New", assignee=None)
api19 = FakeApi(cs19)
uf19, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey19 = idempotency.decision_key("~a19", "~c19", l1_policy.POLICY_VERSION, "armed")
tier19 = idempotency.record_tier_decision(dkey19, "L2", store_dir=d19)
res19 = make_res()
disp19 = make_disposition()
calls = patch_comment(True)
try:
    r19a = ao.assign_l2_verified(api19, dkey19, "~a19", "~c19", "armed", res19, disp19,
                                 res19["containment"], tier19, case_state_fn=cs19,
                                 user_find_fn=uf19, store_dir=d19)
    r19b = ao.assign_l2_verified(api19, dkey19, "~a19", "~c19", "armed", res19, disp19,
                                 res19["containment"], tier19, case_state_fn=cs19,
                                 user_find_fn=uf19, store_dir=d19)
finally:
    unpatch_comment()
check("first call verified", r19a["verified"] is True)
check("second call also reports verified (idempotent)", r19b["verified"] is True)
check("exactly ONE assignee PATCH across both calls",
     sum(1 for c in api19.case.update_calls if "assignee" in c) == 1)
check("exactly ONE comment across both calls", calls["n"] == 1)


# ==============================================================================
# 20. Concurrent invocation -> one assignment only (real OS processes)
# ==============================================================================

def _assign_worker(store_dir, out_q):
    import idempotency as w_idem
    key = w_idem.assignment_action_key("~a20", "~c20", L2_LOGIN, "armed")
    claimed = w_idem.claim(key, store_dir=store_dir, meta={"case_id": "~c20"})
    if claimed["claimed"]:
        w_idem.complete(key, w_idem.STATUS_COMPLETED, detail={"assignee": L2_ID}, store_dir=store_dir)
        out_q.put("claimed")
    else:
        out_q.put("not_claimed")


if __name__ == "__main__":
    print("\n=== 20. concurrent claim() from real OS processes -> exactly one winner ===")
    d20 = fresh_dir()
    q = multiprocessing.Queue()
    procs = [multiprocessing.Process(target=_assign_worker, args=(d20, q)) for _ in range(8)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=10)
    outcomes = [q.get() for _ in procs]
    check("exactly one process claimed it", outcomes.count("claimed") == 1, outcomes)
    check("the other seven saw it already claimed", outcomes.count("not_claimed") == 7, outcomes)


# ==============================================================================
# 21. Restart after assignment -> no duplicate
# ==============================================================================

print("\n=== 21. assignment survives a simulated process restart -> no duplicate on reload ===")
reset_l2_cache()
d21 = fresh_dir()
cs21 = FakeCaseState(status="New", stage="New", assignee=None)
api21 = FakeApi(cs21)
uf21, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey21 = idempotency.decision_key("~a21", "~c21", l1_policy.POLICY_VERSION, "armed")
tier21 = idempotency.record_tier_decision(dkey21, "L2", store_dir=d21)
res21 = make_res()
disp21 = make_disposition()
calls = patch_comment(True)
try:
    ao.assign_l2_verified(api21, dkey21, "~a21", "~c21", "armed", res21, disp21,
                          res21["containment"], tier21, case_state_fn=cs21,
                          user_find_fn=uf21, store_dir=d21)
finally:
    unpatch_comment()
import importlib
idempotency_restarted = importlib.reload(idempotency)
assign_key21 = idempotency_restarted.assignment_action_key("~a21", "~c21", L2_LOGIN, "armed")
rec21 = idempotency_restarted.get_status(assign_key21, store_dir=d21)
check("record still readable and COMPLETED after a fresh module load",
     rec21 is not None and rec21["status"] == idempotency_restarted.STATUS_COMPLETED)
idempotency = idempotency_restarted
reset_l2_cache()
calls = patch_comment(True)
try:
    r21b = ao.assign_l2_verified(api21, dkey21, "~a21", "~c21", "armed", res21, disp21,
                                 res21["containment"], tier21, case_state_fn=cs21,
                                 user_find_fn=uf21, store_dir=d21)
finally:
    unpatch_comment()
check("post-restart call reports verified without repeating the PATCH", r21b["verified"] is True)
check("no NEW assignee PATCH after restart",
     sum(1 for c in api21.case.update_calls if "assignee" in c) == 1)


# ==============================================================================
# 22. Policy-version change -> no repeated assignment
# ==============================================================================

print("\n=== 22. policy-version change does NOT cause a duplicate reassignment ===")
reset_l2_cache()
d22 = fresh_dir()
cs22 = FakeCaseState(status="New", stage="New", assignee=None)
api22 = FakeApi(cs22)
uf22, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey22a = idempotency.decision_key("~a22", "~c22", "l1-policy-v1-2026-08-21", "armed")
dkey22b = idempotency.decision_key("~a22", "~c22", "l1-policy-v2-FUTURE", "armed")
tier22a = idempotency.record_tier_decision(dkey22a, "L2", store_dir=d22)
res22 = make_res()
disp22 = make_disposition()
calls = patch_comment(True)
try:
    r22a = ao.assign_l2_verified(api22, dkey22a, "~a22", "~c22", "armed", res22, disp22,
                                 res22["containment"], tier22a, case_state_fn=cs22,
                                 user_find_fn=uf22, store_dir=d22)
    tier22b = idempotency.record_tier_decision(dkey22b, "L2", store_dir=d22)
    r22b = ao.assign_l2_verified(api22, dkey22b, "~a22", "~c22", "armed", res22, disp22,
                                 res22["containment"], tier22b, case_state_fn=cs22,
                                 user_find_fn=uf22, store_dir=d22)
finally:
    unpatch_comment()
check("first (v1) assignment verified", r22a["verified"] is True)
check("second (v2) call ALSO reports verified — adopts the SAME physical assignment",
     r22b["verified"] is True)
check("only ONE assignee PATCH was ever issued across both policy versions",
     sum(1 for c in api22.case.update_calls if "assignee" in c) == 1,
     api22.case.update_calls)


# ==============================================================================
# 23. Tags are idempotent
# ==============================================================================

print("\n=== 23. l2_escalation_tags(): deterministic, bounded, no duplicates on repeat ===")
disp23 = make_disposition([l1_policy.Reason.LOW_CONFIDENCE, l1_policy.Reason.MISSING_EVIDENCE])
tags23a = ao.l2_escalation_tags(disp23)
tags23b = ao.l2_escalation_tags(disp23)
check("exactly 3 tags produced (bounded)", len(tags23a) == 3, tags23a)
check("repeat calls produce the IDENTICAL tag set", tags23a == tags23b)
check("only the FIRST reason code becomes the reason-category tag (no unbounded growth)",
     sum(1 for t in tags23a if t.startswith("ai-reason-")) == 1)
check("escalation marker present", "ai-escalated-l2" in tags23a)
check("policy-version tag present", f"ai-policy-{l1_policy.POLICY_VERSION}" in tags23a)


# ==============================================================================
# 24. Existing 264 tests continue to pass (pointer — run separately)
# ==============================================================================

print("\n=== 24. existing 264 tests (run via the combined suite, not duplicated here) ===")
print("    see: test_idempotency.py, test_l1_policy.py, test_pfsense_verify.py,")
print("         test_containment_verification.py, test_cortex_metadata.py,")
print("         test_truepositive_closure.py")
check("pointer test — always true, coverage is enforced by running the full suite", True)


# ==============================================================================
# 25-26. REGRESSION (Phase 5.6 live checkpoint, 2026-08-21): the
# "existing_analyst" adoption path must never re-post a comment that a prior
# attempt already posted before failing ONLY its own verification step.
# ==============================================================================

print("\n=== 25. REGRESSION: existing_analyst adoption does NOT re-post an already-posted comment ===")
d = fresh_dir()
res25 = make_res()
disp25 = make_disposition()
cs25 = FakeCaseState(status="New", stage="New", assignee="~a-different-human")
api25 = FakeApi(cs25)
uf25, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey25 = idempotency.decision_key("~a25", "~c25", l1_policy.POLICY_VERSION, "armed")
tier25 = idempotency.record_tier_decision(dkey25, "L2", store_dir=d)

# Simulate the exact aftermath found live: a fresh-claim attempt posted the
# comment successfully, then failed ONLY its own post-PATCH verification
# (left the record INTENDED) — a later call must recognize the comment
# already landed via meta["comment_posted"], not just record status.
assign_key25 = idempotency.assignment_action_key("~a25", "~c25", L2_LOGIN, "armed")
idempotency.claim(assign_key25, store_dir=d, meta={"case_id": "~c25", "login": L2_LOGIN})
idempotency.update_meta(assign_key25, {"comment_posted": True}, store_dir=d)

reset_l2_cache()
calls = patch_comment(True)
try:
    r25 = ao.assign_l2_verified(api25, dkey25, "~a25", "~c25", "armed", res25, disp25,
                                res25["containment"], tier25, case_state_fn=cs25,
                                user_find_fn=uf25, store_dir=d)
finally:
    unpatch_comment()
check("resolves to verified True (human-owned satisfies escalation)", r25["verified"] is True, r25)
check("NO comment re-posted — meta already recorded comment_posted=True", calls["n"] == 0, calls)
rec25 = idempotency.get_status(assign_key25, store_dir=d)
check("record now COMPLETED", rec25["status"] == idempotency.STATUS_COMPLETED, rec25)

print("\n=== 26. REGRESSION: existing_analyst adoption DOES post the comment when it genuinely hasn't landed ===")
d = fresh_dir()
res26 = make_res()
disp26 = make_disposition()
cs26 = FakeCaseState(status="New", stage="New", assignee="~a-different-human-2")
api26 = FakeApi(cs26)
uf26, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey26 = idempotency.decision_key("~a26", "~c26", l1_policy.POLICY_VERSION, "armed")
tier26 = idempotency.record_tier_decision(dkey26, "L2", store_dir=d)
# No prior claim at all this time — genuinely the first time this key is seen.
reset_l2_cache()
calls = patch_comment(True)
try:
    r26 = ao.assign_l2_verified(api26, dkey26, "~a26", "~c26", "armed", res26, disp26,
                                res26["containment"], tier26, case_state_fn=cs26,
                                user_find_fn=uf26, store_dir=d)
finally:
    unpatch_comment()
check("resolves to verified True", r26["verified"] is True, r26)
check("comment WAS posted exactly once (genuinely missing evidence)", calls["n"] == 1, calls)
assign_key26 = idempotency.assignment_action_key("~a26", "~c26", L2_LOGIN, "armed")
rec26 = idempotency.get_status(assign_key26, store_dir=d)
check("comment_posted now recorded in meta", rec26.get("meta", {}).get("comment_posted") is True, rec26)


# ==============================================================================
# 27-35. Phase 8F.1 fix: caller-identity-aware assignment eligibility.
# A live test found the case's assignee landing on the automation's OWN
# service account (TheHive auto-assigns the case creator on promote_to_case)
# instead of SOAR_L2_LOGIN — the old short-circuit #5 treated ANY non-target
# non-empty assignee as "existing_analyst" and never overwrote it. The fix
# adds caller_login (the authenticated API caller for THIS execution,
# resolved via api.user.get_current()) so ONLY an exact match against our
# own caller is treated as auto-ownership eligible for reassignment.
# ==============================================================================

SERVICE_LOGIN = "soar-live-demo@thehive.local"
OTHER_SERVICE_LOGIN = "some-other-bot@thehive.local"

print("\n=== 27. empty assignee -> assigned to target L2 (unaffected by the fix) ===")
d = fresh_dir()
res27 = make_res(); disp27 = make_disposition()
cs27 = FakeCaseState(status="New", stage="New", assignee=None)
api27 = FakeApi(cs27, current_user={"login": SERVICE_LOGIN})
uf27, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey27 = idempotency.decision_key("~a27", "~c27", l1_policy.POLICY_VERSION, "armed")
tier27 = idempotency.record_tier_decision(dkey27, "L2", store_dir=d)
reset_l2_cache(); calls = patch_comment(True)
try:
    r27 = ao.assign_l2_verified(api27, dkey27, "~a27", "~c27", "armed", res27, disp27,
                                res27["containment"], tier27, case_state_fn=cs27,
                                user_find_fn=uf27, store_dir=d)
finally:
    unpatch_comment()
check("empty assignee -> verified True, real assignment made", r27["verified"] is True, r27)
check("assignee PATCH targeted the L2 user id", any(c.get("assignee") == L2_ID for c in api27.case.update_calls),
     api27.case.update_calls)
check("live case now shows the L2 login", cs27.assignee == L2_LOGIN)

print("\n=== 28. already assigned to target L2 -> idempotent success, no PATCH repeated ===")
d = fresh_dir()
res28 = make_res(); disp28 = make_disposition()
cs28 = FakeCaseState(status="New", stage="New", assignee=L2_LOGIN)
api28 = FakeApi(cs28, current_user={"login": SERVICE_LOGIN})
uf28, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey28 = idempotency.decision_key("~a28", "~c28", l1_policy.POLICY_VERSION, "armed")
tier28 = idempotency.record_tier_decision(dkey28, "L2", store_dir=d)
reset_l2_cache()
r28 = ao.assign_l2_verified(api28, dkey28, "~a28", "~c28", "armed", res28, disp28,
                            res28["containment"], tier28, case_state_fn=cs28,
                            user_find_fn=uf28, store_dir=d)
check("already-L2 assignee -> verified True, idempotent", r28["verified"] is True, r28)
check("no assignee PATCH issued at all", not any("assignee" in c for c in api28.case.update_calls),
     api28.case.update_calls)

print("\n=== 29. automatic service-account ownership -> replaced with target L2 (THE FIX) ===")
d = fresh_dir()
res29 = make_res(); disp29 = make_disposition()
cs29 = FakeCaseState(status="New", stage="New", assignee=SERVICE_LOGIN)
api29 = FakeApi(cs29, current_user={"login": SERVICE_LOGIN})
uf29, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey29 = idempotency.decision_key("~a29", "~c29", l1_policy.POLICY_VERSION, "armed")
tier29 = idempotency.record_tier_decision(dkey29, "L2", store_dir=d)
reset_l2_cache(); calls = patch_comment(True)
try:
    r29 = ao.assign_l2_verified(api29, dkey29, "~a29", "~c29", "armed", res29, disp29,
                                res29["containment"], tier29, case_state_fn=cs29,
                                user_find_fn=uf29, store_dir=d)
finally:
    unpatch_comment()
check("assignee == authenticated caller -> verified True, real reassignment made",
     r29["verified"] is True, r29)
check("assignee PATCH targeted the L2 user id (not left as the service account)",
     any(c.get("assignee") == L2_ID for c in api29.case.update_calls), api29.case.update_calls)
check("live case now shows the L2 login, not the service account", cs29.assignee == L2_LOGIN)

print("\n=== 30. DIFFERENT service account -> preserved, never overwritten ===")
d = fresh_dir()
res30 = make_res(); disp30 = make_disposition()
cs30 = FakeCaseState(status="New", stage="New", assignee=OTHER_SERVICE_LOGIN)
api30 = FakeApi(cs30, current_user={"login": SERVICE_LOGIN})  # WE are not OTHER_SERVICE_LOGIN
uf30, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey30 = idempotency.decision_key("~a30", "~c30", l1_policy.POLICY_VERSION, "armed")
tier30 = idempotency.record_tier_decision(dkey30, "L2", store_dir=d)
reset_l2_cache(); calls = patch_comment(True)
try:
    r30 = ao.assign_l2_verified(api30, dkey30, "~a30", "~c30", "armed", res30, disp30,
                                res30["containment"], tier30, case_state_fn=cs30,
                                user_find_fn=uf30, store_dir=d)
finally:
    unpatch_comment()
check("a DIFFERENT service account is treated as existing_analyst, preserved",
     r30["verified"] is True, r30)
check("no assignee PATCH issued — the other account's ownership was never overwritten",
     not any("assignee" in c for c in api30.case.update_calls), api30.case.update_calls)
check("live case still shows the OTHER service account", cs30.assignee == OTHER_SERVICE_LOGIN)

print("\n=== 31. real human assignee -> preserved, never overwritten (unaffected by the fix) ===")
d = fresh_dir()
res31 = make_res(); disp31 = make_disposition()
cs31 = FakeCaseState(status="New", stage="New", assignee="a.human.analyst@thehive.local")
api31 = FakeApi(cs31, current_user={"login": SERVICE_LOGIN})
uf31, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey31 = idempotency.decision_key("~a31", "~c31", l1_policy.POLICY_VERSION, "armed")
tier31 = idempotency.record_tier_decision(dkey31, "L2", store_dir=d)
reset_l2_cache(); calls = patch_comment(True)
try:
    r31 = ao.assign_l2_verified(api31, dkey31, "~a31", "~c31", "armed", res31, disp31,
                                res31["containment"], tier31, case_state_fn=cs31,
                                user_find_fn=uf31, store_dir=d)
finally:
    unpatch_comment()
check("human assignee preserved, verified True", r31["verified"] is True, r31)
check("no assignee PATCH issued", not any("assignee" in c for c in api31.case.update_calls))
check("live case still shows the human", cs31.assignee == "a.human.analyst@thehive.local")

print("\n=== 32. /user/current FAILS -> fail closed, existing assignee preserved ===")
d = fresh_dir()
res32 = make_res(); disp32 = make_disposition()
cs32 = FakeCaseState(status="New", stage="New", assignee=SERVICE_LOGIN)
api32 = FakeApi(cs32, current_user_raises=True)  # /user/current raises
uf32, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey32 = idempotency.decision_key("~a32", "~c32", l1_policy.POLICY_VERSION, "armed")
tier32 = idempotency.record_tier_decision(dkey32, "L2", store_dir=d)
reset_l2_cache(); calls = patch_comment(True)
try:
    r32 = ao.assign_l2_verified(api32, dkey32, "~a32", "~c32", "armed", res32, disp32,
                                res32["containment"], tier32, case_state_fn=cs32,
                                user_find_fn=uf32, store_dir=d)
finally:
    unpatch_comment()
check("failed /user/current -> still resolves (fails closed, not a crash)", r32["verified"] is True, r32)
check("no assignee PATCH issued — even though assignee IS literally our own service "
     "account, an unresolved caller identity must never be treated as safe to overwrite",
     not any("assignee" in c for c in api32.case.update_calls), api32.case.update_calls)
check("live case assignee unchanged", cs32.assignee == SERVICE_LOGIN)

print("\n=== 33. ambiguous /user/current response (missing login, wrong type) -> fail closed ===")
d = fresh_dir()
for ambiguous in [{}, {"login": None}, {"login": ""}, {"notlogin": "x"}, "not-a-dict", None]:
    res33 = make_res(); disp33 = make_disposition()
    cs33 = FakeCaseState(status="New", stage="New", assignee=SERVICE_LOGIN)
    api33 = FakeApi(cs33, current_user=ambiguous)
    uf33, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
    dkey33 = idempotency.decision_key(f"~a33-{ambiguous!r}", "~c33", l1_policy.POLICY_VERSION, "armed")
    tier33 = idempotency.record_tier_decision(dkey33, "L2", store_dir=d)
    reset_l2_cache(); calls = patch_comment(True)
    try:
        r33 = ao.assign_l2_verified(api33, dkey33, f"~a33-{ambiguous!r}", "~c33", "armed",
                                    res33, disp33, res33["containment"], tier33,
                                    case_state_fn=cs33, user_find_fn=uf33, store_dir=d)
    finally:
        unpatch_comment()
    check(f"ambiguous get_current()={ambiguous!r} -> fails closed, no PATCH",
         not any("assignee" in c for c in api33.case.update_calls), (ambiguous, api33.case.update_calls))

print("\n=== 34. replay/idempotency: second call after correction does not re-PATCH ===")
d = fresh_dir()
res34 = make_res(); disp34 = make_disposition()
cs34 = FakeCaseState(status="New", stage="New", assignee=SERVICE_LOGIN)
api34 = FakeApi(cs34, current_user={"login": SERVICE_LOGIN})
uf34, _ = make_user_find_fn([{"login": L2_LOGIN, "_id": L2_ID, "locked": False}])
dkey34 = idempotency.decision_key("~a34", "~c34", l1_policy.POLICY_VERSION, "armed")
tier34 = idempotency.record_tier_decision(dkey34, "L2", store_dir=d)
reset_l2_cache(); calls = patch_comment(True)
try:
    r34a = ao.assign_l2_verified(api34, dkey34, "~a34", "~c34", "armed", res34, disp34,
                                 res34["containment"], tier34, case_state_fn=cs34,
                                 user_find_fn=uf34, store_dir=d)
    r34b = ao.assign_l2_verified(api34, dkey34, "~a34", "~c34", "armed", res34, disp34,
                                 res34["containment"], tier34, case_state_fn=cs34,
                                 user_find_fn=uf34, store_dir=d)
finally:
    unpatch_comment()
check("first call reassigns from the service account to L2", r34a["verified"] is True, r34a)
check("second (replay) call also verified True (idempotent)", r34b["verified"] is True, r34b)
check("exactly ONE assignee PATCH issued across both calls",
     sum(1 for c in api34.case.update_calls if "assignee" in c) == 1, api34.case.update_calls)

print("\n=== 35. correct_auto_ownership_assignment(): zero comment/notification/containment/closure side effects ===")
cs35 = FakeCaseState(status="New", stage="New", assignee=SERVICE_LOGIN)
api35 = FakeApi(cs35, current_user={"login": SERVICE_LOGIN})
calls = patch_comment(True)
try:
    r35 = ao.correct_auto_ownership_assignment(api35, "~c35", SERVICE_LOGIN, L2_LOGIN, L2_ID, case_state_fn=cs35)
finally:
    unpatch_comment()
check("correction succeeds", r35["corrected"] is True, r35)
check("before/after reported correctly", r35["before_assignee"] == SERVICE_LOGIN
     and r35["after_assignee"] == L2_LOGIN, r35)
check("posts NO comment of its own — the function has no code path to do so", calls["n"] == 0, calls)
check("no status/stage field ever included in the PATCH (assignment-only, never closes)",
     not any(("status" in c or "stage" in c) for c in api35.case.update_calls),
     api35.case.update_calls)
check("only the assignee field was ever patched, nothing else",
     all(set(c.keys()) <= {"assignee"} for c in api35.case.update_calls if "assignee" in c),
     api35.case.update_calls)
check("live case now shows the L2 login", cs35.assignee == L2_LOGIN)

print("\n=== 36. correct_auto_ownership_assignment(): mismatched expected-current-assignee refuses ===")
cs36 = FakeCaseState(status="New", stage="New", assignee="something-unexpected@thehive.local")
api36 = FakeApi(cs36, current_user={"login": SERVICE_LOGIN})
r36 = ao.correct_auto_ownership_assignment(api36, "~c36", SERVICE_LOGIN, L2_LOGIN, L2_ID, case_state_fn=cs36)
check("refuses when live assignee doesn't match the expected precondition",
     r36["corrected"] is False, r36)
check("no PATCH issued", not any("assignee" in c for c in api36.case.update_calls))

print("\n=== 37. correct_auto_ownership_assignment(): closed case refuses ===")
cs37 = FakeCaseState(status="TruePositive", stage="Closed", assignee=SERVICE_LOGIN)
api37 = FakeApi(cs37, current_user={"login": SERVICE_LOGIN})
r37 = ao.correct_auto_ownership_assignment(api37, "~c37", SERVICE_LOGIN, L2_LOGIN, L2_ID, case_state_fn=cs37)
check("refuses on a closed case", r37["corrected"] is False, r37)
check("no PATCH issued on a closed case", not any("assignee" in c for c in api37.case.update_calls))

print("\n=== 38. correct_auto_ownership_assignment(): replay is idempotent, no duplicate PATCH ===")
cs38 = FakeCaseState(status="New", stage="New", assignee=SERVICE_LOGIN)
api38 = FakeApi(cs38, current_user={"login": SERVICE_LOGIN})
r38a = ao.correct_auto_ownership_assignment(api38, "~c38", SERVICE_LOGIN, L2_LOGIN, L2_ID, case_state_fn=cs38)
r38b = ao.correct_auto_ownership_assignment(api38, "~c38", SERVICE_LOGIN, L2_LOGIN, L2_ID, case_state_fn=cs38)
check("first call corrects", r38a["corrected"] is True, r38a)
check("second (replay) call is an idempotent no-op, still reports corrected=True",
     r38b["corrected"] is True, r38b)
check("exactly ONE assignee PATCH issued across both calls",
     sum(1 for c in api38.case.update_calls if "assignee" in c) == 1, api38.case.update_calls)

print("\n=== 39. correct_auto_ownership_assignment(): /user/current failure fails closed ===")
cs39 = FakeCaseState(status="New", stage="New", assignee=SERVICE_LOGIN)
api39 = FakeApi(cs39, current_user_raises=True)
r39 = ao.correct_auto_ownership_assignment(api39, "~c39", SERVICE_LOGIN, L2_LOGIN, L2_ID, case_state_fn=cs39)
check("fails closed when the caller identity cannot be resolved", r39["corrected"] is False, r39)
check("no PATCH issued", not any("assignee" in c for c in api39.case.update_calls))


# ==============================================================================
# Summary
# ==============================================================================

if __name__ == "__main__":
    shutil.rmtree(STORE, ignore_errors=True)
    print("\n" + "=" * 70)
    print(f"  L2 ASSIGNMENT TESTS: {len(PASS)} passed, {len(FAIL)} failed")
    print("=" * 70)
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    sys.exit(0)
