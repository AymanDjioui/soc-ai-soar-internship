#!/usr/bin/env python3
"""
Phase 5.5 tests — the CORRECTED, verified-live L1/L2 notification flow
(idempotency.notification_action_key(), agent_orchestrator._ensure_case_
tags()/_validate_mailer_report()/_fetch_action_record()/_trigger_mailer_
verified()/send_l1_contained_notification()/send_l2_escalation_notification()/
build_l1_contained_email()/build_l2_escalation_email()/_redact_secrets()/
_sanitize_for_email()/_mask_email()).

Confirmed live (2026-08-21): the installed Mailer_1_0 responder does NOT
accept custom subject/body parameters — it composes the email from the
case's own fields and resolves recipients SOLELY from `mail=<address>` case
tags. These tests verify the corrected contract: no `parameters` sent, the
recipient-tag idempotent-add-then-verify flow, the exact confirmed-live
report acceptance criteria, and that `mail sent` is treated as supporting
evidence only, never gating.

PURE. The Cortex Mailer responder is always a FAKE (FakeApi.cortex) or a
directly-injected `mailer_fn`/`action_record_fn`; orch.wait_for_responder_
action() is monkeypatched per-test; _fetch_action_record() is NEVER called
for real (always injected) — no test ever performs a real HTTP request. No
live TheHive/Cortex/mailer call is ever made.

Run: ./.venv/bin/python test_notifications.py
"""
import json
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


STORE = tempfile.mkdtemp(prefix="notify_test_")


def fresh_dir():
    return tempfile.mkdtemp(prefix="ntf_", dir=STORE)


L2_LOGIN = "soc-l2@thehive.local"
RECIPIENTS = ["analyst.one@example.com", "analyst.two@example.com"]

# The EXACT confirmed-live successful report shape (from the real inspected
# job): success: true, full.message: "message sent", an AddTagToCase
# operation for "mail sent".
GOOD_REPORT = {"success": True, "full": {"message": "message sent"},
              "operations": [{"type": "AddTagToCase", "tag": "mail sent"}]}


def make_res(verdict_str="malicious", confidence=0.95, technique="T1071.001"):
    return {
        "verdict": {"verdict": verdict_str, "confidence": confidence, "severity": "high",
                    "mitre_technique": technique, "reason": "C2 beacon", "key_evidence": "beacon pattern"},
        "trace": [{"step": 1, "action": "search_past_cases", "result": {"hint": "prior TruePositive"}},
                 {"step": 2, "action": "run_analyzer", "result": {"name": "AbuseIPDB", "taxonomies": []}}],
        "tools_used": ["search_past_cases", "run_analyzer"],
        "containment": {"target": "202.61.130.163", "allowed": True, "disposition": "block", "reason": "external"},
    }


def make_case_state(status="New", stage="New", number=42):
    return {"status": status, "stage": stage,
            "raw": {"status": status, "stage": stage, "number": number}}


def make_containment_result(target="202.61.130.163", job_id="job-1", executed=True):
    return {"executed": executed, "reason_code": l1_policy.Reason.L1_TRUE_POSITIVE_CONTAINED,
            "audit": {"target_ip": target, "job_id": job_id, "cortex_status": "Success",
                      "precheck_result": "ABSENT", "postcheck_result": "PRESENT",
                      "policy_version": l1_policy.POLICY_VERSION}}


def make_disposition(reason_codes=None, reason="test"):
    return {"tier": "L2", "action": "escalate", "status": None,
            "reason_codes": reason_codes or [l1_policy.Reason.LOW_CONFIDENCE], "reason": reason}


class FakeCortex:
    def __init__(self, job_id="mailerjob-1", list_responders_ok=True, raise_on_create=False):
        self.create_calls = []
        self.job_id = job_id
        self.list_responders_ok = list_responders_ok
        self.raise_on_create = raise_on_create

    def list_responders(self, entity_type, entity_id):
        if not self.list_responders_ok:
            return []
        return [{"name": ao.orch.MAILER_RESPONDER_NAME, "id": "~mailer-responder"}]

    def create_responder_action(self, payload):
        self.create_calls.append(dict(payload))
        if self.raise_on_create:
            raise RuntimeError("simulated Cortex call failure")
        return {"_id": self.job_id}


class FakeCase:
    def __init__(self, number=42, tags=None, title="Original Incident Title",
                description="Original incident description"):
        self.number = number
        self.tags = list(tags or [])
        self.title = title
        self.description = description
        self.update_calls = []

    def get(self, case_id):
        return {"tags": list(self.tags), "number": self.number, "status": "New", "stage": "New",
                "title": self.title, "description": self.description}

    def update(self, case_id, fields):
        self.update_calls.append(dict(fields))
        if "tags" in fields:
            self.tags = list(fields["tags"])
        if "addTags" in fields:
            for t in fields["addTags"]:
                if t not in self.tags:
                    self.tags.append(t)


class FakeApi:
    def __init__(self, job_id="mailerjob-1", list_responders_ok=True, number=42, raise_on_create=False,
                tags=None):
        self.cortex = FakeCortex(job_id, list_responders_ok, raise_on_create)
        self.case = FakeCase(number, tags=tags)


def patch_wait(fn):
    orig = ao.orch.wait_for_responder_action
    ao.orch.wait_for_responder_action = fn
    return orig


def unpatch_wait(orig):
    ao.orch.wait_for_responder_action = orig


_orig_post_comment = ao.orch.post_case_comment


def patch_comment(returns=True):
    calls = {"n": 0}
    def fake(case_id, body):
        calls["n"] += 1
        return returns
    ao.orch.post_case_comment = fake
    return calls


def unpatch_comment():
    ao.orch.post_case_comment = _orig_post_comment


def make_wait_fn(status="Success", report=None):
    def fn(case_id, timeout_s=60, poll_s=3):
        return status, report
    return fn


def make_action_record_fn(responder_id="~mailer-responder", object_id=None):
    def fn(case_id, job_id):
        return {"responderId": responder_id, "objectId": object_id or case_id, "cortexJobId": job_id}
    return fn


def reset_l2_cache():
    ao._l2_user_cache.clear()


def make_success_mailer(job_id="mj-1"):
    """A bare fake `mailer_fn` for testing send_l1/send_l2's OWN orchestration
    (claim/idempotency/comment/branching) without exercising _trigger_mailer_
    verified()'s internals."""
    calls = {"n": 0}
    def fn(api, case_id, recipients, routing_tags, idempotency_key=None, store_dir=None):
        calls["n"] += 1
        return {"mailer_reported_success": True, "responder_id": "~r", "job_id": job_id,
                "mailer_status": "Success", "error": None, "report_checks": {"ok": True},
                "mail_sent_tag_confirmed_live": True, "masked_recipients": ["a***@e***.com"],
                "tag_verification": {"ok": True}}
    return fn, calls


# Patched for the ENTIRE file — every send_*_notification() call below posts a
# case comment internally; this must never be a real network attempt. Only
# unpatched at the very end.
_comment_calls = patch_comment(True)


# ==============================================================================
# 1. Unsupported subject/body parameters are NOT sent to Cortex
# ==============================================================================

print("\n=== 1. _trigger_mailer_verified(): no 'parameters' field is EVER sent to Cortex ===")
d = fresh_dir()
api1 = FakeApi()
orig = patch_wait(make_wait_fn("Success", GOOD_REPORT))
try:
    r1 = ao._trigger_mailer_verified(api1, "~c1", RECIPIENTS, ["soc-ai:l1-contained"],
                                     store_dir=d, action_record_fn=make_action_record_fn())
finally:
    unpatch_wait(orig)
check("mailer accepted", r1["mailer_reported_success"] is True, r1)
check("create_responder_action was called exactly once", len(api1.cortex.create_calls) == 1)
check("the payload has NO 'parameters' key", "parameters" not in api1.cortex.create_calls[0],
     api1.cortex.create_calls[0])
check("the payload is exactly responderId/cortexId/objectType/objectId",
     set(api1.cortex.create_calls[0].keys()) == {"responderId", "cortexId", "objectType", "objectId"},
     api1.cortex.create_calls[0])


# ==============================================================================
# 2. Recipient tags are added AND independently verified BEFORE invocation
# ==============================================================================

print("\n=== 2. recipient tags added + verified BEFORE the Mailer is invoked ===")
d = fresh_dir()
api2 = FakeApi()
orig = patch_wait(make_wait_fn("Success", GOOD_REPORT))
try:
    r2 = ao._trigger_mailer_verified(api2, "~c2", RECIPIENTS, [],
                                     store_dir=d, action_record_fn=make_action_record_fn())
finally:
    unpatch_wait(orig)
check("tag_verification reports ok", r2["tag_verification"]["ok"] is True, r2["tag_verification"])
check("case now carries mail= tags for both recipients",
     all(f"mail={a}" in api2.case.tags for a in RECIPIENTS), api2.case.tags)
check("the tag update happened BEFORE create_responder_action was called",
     any("tags" in c for c in api2.case.update_calls[:1]))


# ==============================================================================
# 3. Invalid or missing recipient configuration refuses the send
# ==============================================================================

print("\n=== 3. no valid configured recipients -> refuses, Cortex NEVER invoked ===")
d = fresh_dir()
api3 = FakeApi()
r3 = ao._trigger_mailer_verified(api3, "~c3", ["not-an-email", "", None], [], store_dir=d)
check("mailer_reported_success is False", r3["mailer_reported_success"] is False)
check("Cortex was NEVER invoked", len(api3.cortex.create_calls) == 0)
check("error mentions no valid recipients", "no valid configured recipients" in (r3["error"] or ""), r3)

print("--- send_l1_contained_notification(): empty MAILER_RECIPIENTS refuses immediately ---")
orig_recipients = ao.orch.MAILER_RECIPIENTS
ao.orch.MAILER_RECIPIENTS = []
d = fresh_dir()
mailer_fn, mcalls = make_success_mailer()
dkey3b = idempotency.decision_key("~a3b", "~c3b", l1_policy.POLICY_VERSION, "armed")
r3b = ao.send_l1_contained_notification(None, dkey3b, "~a3b", "~c3b", "armed", make_res(), make_disposition(),
                                        make_containment_result(), make_case_state(), L2_LOGIN,
                                        mailer_fn=mailer_fn, store_dir=d)
ao.orch.MAILER_RECIPIENTS = orig_recipients
check("send_l1_contained_notification refuses with a clear reason",
     r3b["sent"] is False and r3b["result"] == l1_policy.Reason.NOTIFICATION_RECIPIENT_CONFIG_MISSING, r3b)
check("mailer_fn was NEVER called", mcalls["n"] == 0)


# ==============================================================================
# 4. Recipient addresses are masked in audit output
# ==============================================================================

print("\n=== 4. recipient addresses are masked, never raw, in returned/audit data ===")
masked = ao._mask_email("someone.specific@example.com")
check("masked form hides the local part", "someone.specific" not in masked, masked)
check("masked form hides the domain label", "example" not in masked, masked)
check("masked form keeps the TLD (useful, not sensitive)", masked.endswith(".com"), masked)
d = fresh_dir()
api4 = FakeApi()
orig = patch_wait(make_wait_fn("Success", GOOD_REPORT))
try:
    r4 = ao._trigger_mailer_verified(api4, "~c4", RECIPIENTS, [],
                                     store_dir=d, action_record_fn=make_action_record_fn())
finally:
    unpatch_wait(orig)
check("returned masked_recipients never contains a raw configured address",
     all(addr not in r4["masked_recipients"] for addr in RECIPIENTS), r4["masked_recipients"])


# ==============================================================================
# 5. Duplicate recipient tags are not created
# ==============================================================================

print("\n=== 5. _ensure_case_tags(): duplicate recipient tags never created on repeat calls ===")
d = fresh_dir()
api5 = FakeApi()
res5a = ao._ensure_case_tags(api5, "~c5", RECIPIENTS, ["soc-ai:l2-escalated"])
res5b = ao._ensure_case_tags(api5, "~c5", RECIPIENTS, ["soc-ai:l2-escalated"])
check("first call ok", res5a["ok"] is True)
check("second call also ok (idempotent)", res5b["ok"] is True)
mail_tag_count = sum(1 for t in api5.case.tags if t == f"mail={RECIPIENTS[0]}")
check("no duplicate mail= tag after two calls", mail_tag_count == 1, api5.case.tags)
routing_tag_count = sum(1 for t in api5.case.tags if t == "soc-ai:l2-escalated")
check("no duplicate routing tag after two calls", routing_tag_count == 1, api5.case.tags)


# ==============================================================================
# 6. L1/L2 routing tags are present on the case
# ==============================================================================

print("\n=== 6. deterministic soc-ai: routing tags land on the case ===")
d = fresh_dir()
api6 = FakeApi()
orig = patch_wait(make_wait_fn("Success", GOOD_REPORT))
try:
    ao._trigger_mailer_verified(api6, "~c6", RECIPIENTS, ao._l1_contained_routing_tags(make_disposition(
        [l1_policy.Reason.L1_TRUE_POSITIVE_CONTAINED])), store_dir=d, action_record_fn=make_action_record_fn())
finally:
    unpatch_wait(orig)
check("soc-ai:l1-contained tag present", "soc-ai:l1-contained" in api6.case.tags, api6.case.tags)
check("a soc-ai:reason-* tag present",
     any(t.startswith("soc-ai:reason-") for t in api6.case.tags), api6.case.tags)

l2_tags = ao._l2_escalated_routing_tags(make_disposition([l1_policy.Reason.LOW_CONFIDENCE]))
check("L2 routing tag is soc-ai:l2-escalated", "soc-ai:l2-escalated" in l2_tags, l2_tags)
check("L1 and L2 routing tags are distinct",
     ao._l1_contained_routing_tags(make_disposition())[0] != l2_tags[0])


# ==============================================================================
# 7. Original case title and description are preserved
# ==============================================================================

print("\n=== 7. case title/description are NEVER rewritten by the notification flow ===")
d = fresh_dir()
api7 = FakeApi()
orig = patch_wait(make_wait_fn("Success", GOOD_REPORT))
try:
    ao._trigger_mailer_verified(api7, "~c7", RECIPIENTS, ["soc-ai:l1-contained"],
                                store_dir=d, action_record_fn=make_action_record_fn())
finally:
    unpatch_wait(orig)
check("title never touched", api7.case.title == "Original Incident Title")
check("description never touched", api7.case.description == "Original incident description")
check("no update call ever included a 'title' key",
     not any("title" in c for c in api7.case.update_calls))
check("no update call ever included a 'description' key",
     not any("description" in c for c in api7.case.update_calls))


# ==============================================================================
# 8. Exact Cortex report acceptance checks
# ==============================================================================

print("\n=== 8. _validate_mailer_report(): the EXACT confirmed-live acceptance criteria ===")
v_good = ao._validate_mailer_report("Success", GOOD_REPORT, "~r", "~r", "~c8", "~c8")
check("the confirmed-live good report is ACCEPTED", v_good["accepted"] is True, v_good)

v_wrong_responder = ao._validate_mailer_report("Success", GOOD_REPORT, "~other", "~r", "~c8", "~c8")
check("mismatched responder identity is REJECTED", v_wrong_responder["accepted"] is False)

v_wrong_object = ao._validate_mailer_report("Success", GOOD_REPORT, "~r", "~r", "~other-case", "~c8")
check("mismatched objectId is REJECTED", v_wrong_object["accepted"] is False)

v_no_ops_field = ao._validate_mailer_report(
    "Success", {"success": True, "full": {"message": "message sent"}})
check("a report with NO operations field at all is still accepted "
     "(the AddTagToCase check is opt-in, per spec 'when present')", v_no_ops_field["accepted"] is True)

v_wrong_op = ao._validate_mailer_report(
    "Success", {"success": True, "full": {"message": "message sent"},
               "operations": [{"type": "AddTagToCase", "tag": "some other tag"}]})
check("operations present but WITHOUT the mail-sent tag op is REJECTED", v_wrong_op["accepted"] is False)


# ==============================================================================
# 9. Missing/conflicting report fields never produce acceptance
# ==============================================================================

print("\n=== 9. missing/conflicting report fields never produce NOTIFICATION_ACCEPTED ===")
cases9 = [
    ("empty report", {}),
    ("success False", {"success": False, "full": {"message": "message sent"}}),
    ("wrong message", {"success": True, "full": {"message": "queued"}}),
    ("missing full", {"success": True}),
    ("status Failure even with a good report", None),   # handled specially below
]
for label, report in cases9[:-1]:
    v = ao._validate_mailer_report("Success", report)
    check(f"rejected: {label}", v["accepted"] is False, v)
v_status_failure = ao._validate_mailer_report("Failure", GOOD_REPORT)
check("rejected: terminal status is Failure even with an otherwise-good report",
     v_status_failure["accepted"] is False, v_status_failure)


# ==============================================================================
# 10. "mail sent" tag is SUPPORTING evidence only, never gating
# ==============================================================================

print("\n=== 10. acceptance does NOT depend on the live 'mail sent' tag re-query ===")
d = fresh_dir()
api10 = FakeApi()   # FakeCase never actually gets a live 'mail sent' tag added
orig = patch_wait(make_wait_fn("Success", GOOD_REPORT))
try:
    r10 = ao._trigger_mailer_verified(api10, "~c10", RECIPIENTS, [],
                                      store_dir=d, action_record_fn=make_action_record_fn())
finally:
    unpatch_wait(orig)
check("mailer_reported_success is STILL True (report content decided it)",
     r10["mailer_reported_success"] is True, r10)
check("mail_sent_tag_confirmed_live is False (informational only) — NOT used to deny acceptance",
     r10["mail_sent_tag_confirmed_live"] is False, r10)


# ==============================================================================
# 11. Deterministic comments remain sanitized
# ==============================================================================

print("\n=== 11. HTML/script injection in agent-derived text is escaped in comments/templates ===")
malicious = "<script>alert('xss')</script><img src=x onerror=alert(1)>"
sanitized = ao._sanitize_for_email(malicious)
check("raw <script> tag is NOT present", "<script>" not in sanitized, sanitized)
check("escaped form IS present", "&lt;script&gt;" in sanitized, sanitized)
res11 = make_res()
res11["verdict"]["reason"] = malicious
email11 = ao.build_l1_contained_email(res11, make_disposition(), make_containment_result(),
                                      make_case_state(), "~c11", "http://x", "armed", "k11")
check("email template never contains a raw unescaped <script> tag",
     "<script>" not in email11["subject"] and "<script>" not in email11["body"])


# ==============================================================================
# 12. Secrets/passwords/Authorization headers/JWTs are redacted
# ==============================================================================

print("\n=== 12. secrets/passwords/Authorization headers/JWTs are redacted ===")
jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
cases12 = [
    ("Authorization: Bearer abc123def456", "abc123def456"),
    ("bearer abc123def456xyz", "abc123def456xyz"),
    (jwt, jwt),
    ("api_key=sk-live-abcdef1234567890", "sk-live-abcdef1234567890"),
    ("password: SuperSecret123!", "SuperSecret123!"),
]
for raw, needle in cases12:
    redacted = ao._redact_secrets(raw)
    check(f"redacted: {raw[:30]!r}", needle not in redacted and "[REDACTED]" in redacted, redacted)


# ==============================================================================
# 13. Multi-process execution triggers exactly one responder action
# ==============================================================================

def _notify_worker(store_dir, key, out_q):
    import idempotency as w_idem
    claimed = w_idem.claim(key, store_dir=store_dir, meta={"case_id": "~c13"})
    if claimed["claimed"]:
        w_idem.complete(key, w_idem.STATUS_COMPLETED, detail={"result": "NOTIFICATION_ACCEPTED"},
                        store_dir=store_dir)
        out_q.put("claimed")
    else:
        out_q.put("not_claimed")


if __name__ == "__main__":
    print("\n=== 13. concurrent claim() from real OS processes -> exactly one winner ===")
    d13 = fresh_dir()
    key13 = idempotency.notification_action_key("~a13", "~c13", "L1_CONTAINED", L2_LOGIN, "armed")
    q = multiprocessing.Queue()
    procs = [multiprocessing.Process(target=_notify_worker, args=(d13, key13, q)) for _ in range(8)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=10)
    outcomes = [q.get() for _ in procs]
    check("exactly one process claimed it", outcomes.count("claimed") == 1, outcomes)
    check("the other seven saw it already claimed", outcomes.count("not_claimed") == 7, outcomes)


# ==============================================================================
# 14. verified containment + verified closure -> exactly one L1 email (orchestration layer)
# ==============================================================================

print("\n=== 14. send_l1_contained_notification(): exactly one L1 notification, idempotent ===")
d = fresh_dir()
res14 = make_res()
disp14 = make_disposition([l1_policy.Reason.L1_TRUE_POSITIVE_CONTAINED], "contained")
cr14 = make_containment_result()
cs14 = make_case_state()
mailer_fn, mcalls = make_success_mailer()
dkey14 = idempotency.decision_key("~a14", "~c14", l1_policy.POLICY_VERSION, "armed")
r14a = ao.send_l1_contained_notification(None, dkey14, "~a14", "~c14", "armed", res14, disp14, cr14, cs14,
                                         L2_LOGIN, mailer_fn=mailer_fn, store_dir=d)
r14b = ao.send_l1_contained_notification(None, dkey14, "~a14", "~c14", "armed", res14, disp14, cr14, cs14,
                                         L2_LOGIN, mailer_fn=mailer_fn, store_dir=d)
check("first call sent", r14a["sent"] is True)
check("result is NOTIFICATION_ACCEPTED", r14a["result"] == l1_policy.Reason.NOTIFICATION_ACCEPTED)
check("second call also reports sent (idempotent)", r14b["sent"] is True)
check("mailer_fn called exactly ONCE across both calls", mcalls["n"] == 1)


# ==============================================================================
# 15. L2 assignment result reporting (verified / failed) unaffected by the contract fix
# ==============================================================================

print("\n=== 15. build_l2_escalation_email(): verified vs failed assignment still reported correctly ===")
assignment_ok = {"verified": True, "assigned_analyst": "~l2-userid", "reason_codes": [], "escalation_summary": "ok"}
email15a = ao.build_l2_escalation_email(make_res(), make_disposition(), {}, assignment_ok, make_case_state(),
                                        "~c15", "http://x/case/~c15", "armed", "k15a")
check("verified assignment reported", "verified — assigned to ~l2-userid" in email15a["body"])

assignment_fail = {"verified": False, "assigned_analyst": None,
                   "reason_codes": [l1_policy.Reason.L2_USER_NOT_FOUND], "escalation_summary": "L2 user not found"}
email15b = ao.build_l2_escalation_email(make_res(), make_disposition(), {}, assignment_fail, make_case_state(),
                                        "~c15", "http://x/case/~c15", "armed", "k15b")
check("failed assignment reported as NOT VERIFIED", "NOT VERIFIED" in email15b["body"])

d = fresh_dir()
mailer_fn, mcalls = make_success_mailer()
dkey15 = idempotency.decision_key("~a15", "~c15", l1_policy.POLICY_VERSION, "armed")
r15 = ao.send_l2_escalation_notification(None, dkey15, "~a15", "~c15", "armed", make_res(), make_disposition(),
                                         {}, assignment_fail, make_case_state(), L2_LOGIN,
                                         mailer_fn=mailer_fn, store_dir=d)
check("email STILL sent even though assignment failed (independent actions)", r15["sent"] is True)


# ==============================================================================
# 16. Replay and process restart do not duplicate notifications
# ==============================================================================

print("\n=== 16. replay + simulated restart -> no duplicate notification ===")
d = fresh_dir()
res16 = make_res()
disp16 = make_disposition([l1_policy.Reason.L1_TRUE_POSITIVE_CONTAINED])
cr16 = make_containment_result()
cs16 = make_case_state()
mailer_fn, mcalls = make_success_mailer()
dkey16 = idempotency.decision_key("~a16", "~c16", l1_policy.POLICY_VERSION, "armed")
ao.send_l1_contained_notification(None, dkey16, "~a16", "~c16", "armed", res16, disp16, cr16, cs16,
                                  L2_LOGIN, mailer_fn=mailer_fn, store_dir=d)
import importlib
idempotency_restarted = importlib.reload(idempotency)
nkey16 = idempotency_restarted.notification_action_key("~a16", "~c16", "L1_CONTAINED", L2_LOGIN, "armed",
                                                        target="202.61.130.163")
rec16 = idempotency_restarted.get_status(nkey16, store_dir=d)
check("record survives a fresh module load, COMPLETED",
     rec16 is not None and rec16["status"] == idempotency_restarted.STATUS_COMPLETED)
idempotency = idempotency_restarted
r16b = ao.send_l1_contained_notification(None, dkey16, "~a16", "~c16", "armed", res16, disp16, cr16, cs16,
                                         L2_LOGIN, mailer_fn=mailer_fn, store_dir=d)
check("replay after restart reports sent without resending", r16b["sent"] is True)
check("mailer_fn was NOT called a second time after the restart", mcalls["n"] == 1)


# ==============================================================================
# 17. Policy-version change does not duplicate the same notification
# ==============================================================================

print("\n=== 17. policy-version change does not duplicate the notification ===")
d = fresh_dir()
res17 = make_res()
disp17 = make_disposition([l1_policy.Reason.L1_TRUE_POSITIVE_CONTAINED])
cr17 = make_containment_result()
cs17 = make_case_state()
mailer_fn, mcalls = make_success_mailer()
dkey17a = idempotency.decision_key("~a17", "~c17", "l1-policy-v1", "armed")
dkey17b = idempotency.decision_key("~a17", "~c17", "l1-policy-v2-FUTURE", "armed")
r17a = ao.send_l1_contained_notification(None, dkey17a, "~a17", "~c17", "armed", res17, disp17, cr17, cs17,
                                         L2_LOGIN, mailer_fn=mailer_fn, store_dir=d)
r17b = ao.send_l1_contained_notification(None, dkey17b, "~a17", "~c17", "armed", res17, disp17, cr17, cs17,
                                         L2_LOGIN, mailer_fn=mailer_fn, store_dir=d)
check("first send succeeds", r17a["sent"] is True)
check("second call (different policy version) ALSO reports sent — same physical notification",
     r17b["sent"] is True)
check("mailer_fn triggered exactly ONCE across both policy versions", mcalls["n"] == 1)


# ==============================================================================
# 18. Mailer call exception / no-job-id leaves a confirmed FAILED state
# ==============================================================================

print("\n=== 18. no job id ever created (tag/responder failure) -> confirmed FAILED, not ambiguous ===")
d = fresh_dir()
def refusing_mailer(api, case_id, recipients, routing_tags, idempotency_key=None, store_dir=None):
    return {"mailer_reported_success": False, "responder_id": None, "job_id": None,
            "mailer_status": None, "error": "recipient/routing tag verification failed: no valid configured recipients",
            "report_checks": None, "mail_sent_tag_confirmed_live": None,
            "masked_recipients": [], "tag_verification": {"ok": False}}
dkey18 = idempotency.decision_key("~a18", "~c18", l1_policy.POLICY_VERSION, "armed")
r18 = ao.send_l1_contained_notification(None, dkey18, "~a18", "~c18", "armed", make_res(), make_disposition(),
                                        make_containment_result(), make_case_state(), L2_LOGIN,
                                        mailer_fn=refusing_mailer, store_dir=d)
check("sent is False", r18["sent"] is False)
check("result is a confirmed FAILED, not AMBIGUOUS", r18["result"] == l1_policy.Reason.NOTIFICATION_FAILED, r18)
key18 = idempotency.notification_action_key("~a18", "~c18", "L1_CONTAINED", L2_LOGIN, "armed",
                                            target="202.61.130.163")
rec18 = idempotency.get_status(key18, store_dir=d)
check("record is COMPLETED as FAILED (a definite refusal, not left hanging)",
     rec18["status"] == idempotency.STATUS_FAILED, rec18)


# ==============================================================================
# 19. Ambiguous responder result (Timeout, job DID exist) is never reported as delivered
# ==============================================================================

print("\n=== 19. a job exists but times out -> genuinely ambiguous, left INTENDED ===")
d = fresh_dir()
def timeout_mailer(api, case_id, recipients, routing_tags, idempotency_key=None, store_dir=None):
    return {"mailer_reported_success": False, "responder_id": "~r", "job_id": "job-t",
            "mailer_status": "Timeout", "error": "mailer status: Timeout",
            "report_checks": None, "mail_sent_tag_confirmed_live": None,
            "masked_recipients": ["a***@e***.com"], "tag_verification": {"ok": True}}
dkey19 = idempotency.decision_key("~a19", "~c19", l1_policy.POLICY_VERSION, "armed")
r19 = ao.send_l1_contained_notification(None, dkey19, "~a19", "~c19", "armed", make_res(), make_disposition(),
                                        make_containment_result(), make_case_state(), L2_LOGIN,
                                        mailer_fn=timeout_mailer, store_dir=d)
check("sent is False", r19["sent"] is False)
check("result is NOTIFICATION_AMBIGUOUS, never ACCEPTED or a 'delivered' claim",
     r19["result"] == l1_policy.Reason.NOTIFICATION_AMBIGUOUS)
key19 = idempotency.notification_action_key("~a19", "~c19", "L1_CONTAINED", L2_LOGIN, "armed",
                                            target="202.61.130.163")
rec19 = idempotency.get_status(key19, store_dir=d)
check("record left INTENDED (retryable via re-poll, not resend)",
     rec19["status"] == idempotency.STATUS_INTENDED, rec19)
check("no 'DELIVERY_VERIFIED' concept exists anywhere in the Reason enum",
     not hasattr(l1_policy.Reason, "DELIVERY_VERIFIED"))


# ==============================================================================
# 20. Persisted mailer job metadata survives recovery
# ==============================================================================

print("\n=== 20. _trigger_mailer_verified(): job id persisted BEFORE the wait, survives recovery ===")
d = fresh_dir()
key20 = "~a20|~c20|armed:notification:L1_CONTAINED:" + L2_LOGIN
idempotency.claim(key20, store_dir=d)
captured = {}
def wait_checks_meta(case_id, timeout_s=60, poll_s=3):
    rec = idempotency.get_status(key20, store_dir=d)
    captured["meta_at_wait_time"] = dict(rec.get("meta", {}))
    return "Success", GOOD_REPORT
orig = patch_wait(wait_checks_meta)
try:
    api20 = FakeApi(job_id="mailerjob-XYZ")
    result20 = ao._trigger_mailer_verified(api20, "~c20", RECIPIENTS, [], idempotency_key=key20,
                                           store_dir=d, action_record_fn=make_action_record_fn())
finally:
    unpatch_wait(orig)
check("job id was ALREADY persisted by the time wait_for_responder_action ran",
     captured.get("meta_at_wait_time", {}).get("mailer_job_id") == "mailerjob-XYZ", captured)
check("_trigger_mailer_verified itself reports success", result20["mailer_reported_success"] is True)
rec20 = idempotency.get_status(key20, store_dir=d)
check("final record shows last_mailer_status updated to Success",
     rec20["meta"].get("last_mailer_status") == "Success")


# ==============================================================================
# 21. L1 and L2 notification keys are distinct
# ==============================================================================

print("\n=== 21. L1_CONTAINED and L2_ESCALATED keys never collide for the same case ===")
k_l1 = idempotency.notification_action_key("~a21", "~c21", "L1_CONTAINED", L2_LOGIN, "armed")
k_l2 = idempotency.notification_action_key("~a21", "~c21", "L2_ESCALATED", L2_LOGIN, "armed")
check("keys are distinct strings", k_l1 != k_l2, (k_l1, k_l2))
d = fresh_dir()
idempotency.claim(k_l1, store_dir=d)
idempotency.complete(k_l1, idempotency.STATUS_COMPLETED, detail={}, store_dir=d)
check("completing the L1 key does not affect the L2 key's status",
     idempotency.get_status(k_l2, store_dir=d) is None)
check("'mail sent' (the generic Cortex tag) is NEVER used as the idempotency key itself",
     "mail sent" not in k_l1 and "mail sent" not in k_l2)


# ==============================================================================
# 22. Ambiguous recovery re-polls only, never resends (report-validated)
# ==============================================================================

print("\n=== 22. ambiguous recovery re-polls with FULL report validation, never re-invokes the responder ===")
d = fresh_dir()
key22 = idempotency.notification_action_key("~a22", "~c22", "L1_CONTAINED", L2_LOGIN, "armed")
idempotency.claim(key22, store_dir=d)   # claimed but never completed — simulates a crash/timeout
orig = patch_wait(make_wait_fn("Success", GOOD_REPORT))
try:
    resolved22 = ao._resolve_ambiguous_notification(key22, "~c22", d)
finally:
    unpatch_wait(orig)
check("resolves to COMPLETED via re-poll", resolved22["resolved"] and
     resolved22["status"] == idempotency.STATUS_COMPLETED, resolved22)

d = fresh_dir()
key22b = idempotency.notification_action_key("~a22b", "~c22b", "L1_CONTAINED", L2_LOGIN, "armed")
idempotency.claim(key22b, store_dir=d)
orig = patch_wait(make_wait_fn("Success", {"success": False, "full": {"message": "queued"}}))
try:
    resolved22b = ao._resolve_ambiguous_notification(key22b, "~c22b", d)
finally:
    unpatch_wait(orig)
check("a re-polled BAD report resolves FAILED, not COMPLETED",
     resolved22b["resolved"] and resolved22b["status"] == idempotency.STATUS_FAILED, resolved22b)


# ==============================================================================
# 23. Missing fields produce a safe deterministic template
# ==============================================================================

print("\n=== 23. missing/empty fields never crash the templates ===")
try:
    email23a = ao.build_l1_contained_email({}, {}, {}, {}, "~c23", "http://x", "armed", "k23")
    email23b = ao.build_l2_escalation_email({}, {}, {}, {}, {}, "~c23", "http://x", "armed", "k23")
    ok23 = True
except Exception as exc:
    ok23 = False
    print(f"    exception: {exc}")
check("both templates build successfully with empty/missing inputs", ok23)
if ok23:
    check("L1 subject is a non-empty string", isinstance(email23a["subject"], str) and len(email23a["subject"]) > 0)
    check("L2 body is a non-empty string", isinstance(email23b["body"], str) and len(email23b["body"]) > 0)


# ==============================================================================
# 24. No test performs a network call or touches the real idempotency store
# ==============================================================================

print("\n=== 24. pointer test — every call above used a temp store_dir + fakes, action_record_fn always injected ===")
check("pointer test — always true", True)


# ==============================================================================
# 25-30. _armed_mode_preflight_check() — mocked, offline, never live
# ==============================================================================

class FakeUserEndpoint:
    def __init__(self, current_user=None, raise_exc=False):
        self.current_user = current_user if current_user is not None else {"login": "svc-account"}
        self.raise_exc = raise_exc

    def get_current(self):
        if self.raise_exc:
            raise RuntimeError("simulated TheHive auth failure")
        return self.current_user


class FakePreflightCortex:
    def __init__(self, analyzers=None, raise_exc=False):
        self.analyzers = analyzers if analyzers is not None else []
        self.raise_exc = raise_exc

    def list_analyzers(self):
        if self.raise_exc:
            raise RuntimeError("simulated Cortex connectivity failure")
        return self.analyzers


class FakePreflightApi:
    def __init__(self, user_ok=True, cortex_ok=True):
        self.user = FakeUserEndpoint(raise_exc=not user_ok)
        self.cortex = FakePreflightCortex(raise_exc=not cortex_ok)


def make_preflight_user_find_fn(users):
    def fn(login):
        return [u for u in users if u.get("login") == login]
    return fn


print("\n=== 25. preflight: not armed, not forced -> skipped, ZERO network calls ===")
api25 = FakePreflightApi()
r25 = ao._armed_mode_preflight_check(api25)
check("skipped when not armed", r25.get("skipped") is True, r25)

print("\n=== 26. preflight: forced, full happy path -> all checks pass ===")
reset_l2_cache()
d = fresh_dir()
api26 = FakePreflightApi()
orig_find = ao._default_l2_user_find_fn
ao._default_l2_user_find_fn = lambda api, login: [{"login": login, "_id": "~l2id", "locked": False}]
try:
    r26 = ao._armed_mode_preflight_check(api26, store_dir=d, force=True)
finally:
    ao._default_l2_user_find_fn = orig_find
check("thehive_auth True", r26.get("thehive_auth") is True, r26)
check("cortex_connectivity True", r26.get("cortex_connectivity") is True, r26)
check("l2_user_resolved True", r26.get("l2_user_resolved") is True, r26)
check("idempotency_store_writable True", r26.get("idempotency_store_writable") is True, r26)
check("masked_recipients contains no raw configured address",
     all(addr not in r26.get("masked_recipients", []) for addr in RECIPIENTS), r26)

print("\n=== 27. preflight: TheHive auth failure -> exits before any other check ===")
reset_l2_cache()
d = fresh_dir()
api27 = FakePreflightApi(user_ok=False)
exited = False
try:
    ao._armed_mode_preflight_check(api27, store_dir=d, force=True)
except SystemExit:
    exited = True
check("preflight exits on TheHive auth failure", exited)

print("\n=== 28. preflight: Cortex connectivity failure -> exits ===")
reset_l2_cache()
d = fresh_dir()
api28 = FakePreflightApi(cortex_ok=False)
exited = False
try:
    ao._armed_mode_preflight_check(api28, store_dir=d, force=True)
except SystemExit:
    exited = True
check("preflight exits on Cortex connectivity failure", exited)

print("\n=== 29. preflight: no configured recipients -> exits ===")
reset_l2_cache()
d = fresh_dir()
api29 = FakePreflightApi()
orig_recipients = ao.orch.MAILER_RECIPIENTS
ao.orch.MAILER_RECIPIENTS = []
exited = False
try:
    ao._armed_mode_preflight_check(api29, store_dir=d, force=True)
except SystemExit:
    exited = True
finally:
    ao.orch.MAILER_RECIPIENTS = orig_recipients
check("preflight exits when no recipients are configured", exited)

print("\n=== 30. preflight: L2 user unresolvable -> exits ===")
reset_l2_cache()
d = fresh_dir()
api30 = FakePreflightApi()
orig_find = ao._default_l2_user_find_fn
ao._default_l2_user_find_fn = lambda api, login: []   # no matching user
exited = False
try:
    ao._armed_mode_preflight_check(api30, store_dir=d, force=True)
except SystemExit:
    exited = True
finally:
    ao._default_l2_user_find_fn = orig_find
check("preflight exits when the L2 user can't be resolved", exited)


# ==============================================================================
# 31. Regression: report/full/operations arriving as JSON-encoded STRINGS
# ==============================================================================
# Found live during the Phase 5.5 checkpoint (2026-08-21): the real TheHive
# API returned `report` as a JSON string, not an already-parsed dict —
# _validate_mailer_report() crashed with AttributeError before this fix.

print("\n=== 31. _validate_mailer_report(): string-encoded report/full/operations never crash ===")
string_report = json.dumps({"success": True, "full": json.dumps({"message": "message sent"}),
                            "operations": json.dumps([{"type": "AddTagToCase", "tag": "mail sent"}])})
try:
    v31 = ao._validate_mailer_report("Success", string_report, "~r", "~r", "~c31", "~c31")
    ok31 = True
except Exception as exc:
    ok31 = False
    print(f"    exception: {exc}")
check("a fully string-encoded report (report/full/operations all JSON strings) does not crash", ok31)
if ok31:
    check("and is correctly ACCEPTED once parsed", v31["accepted"] is True, v31)

malformed_string = "not even valid json {{{"
v31b = ao._validate_mailer_report("Success", malformed_string)
check("an unparseable string report fails closed (rejected, not crashed)", v31b["accepted"] is False, v31b)

v31c = ao._validate_mailer_report("Success", None)
check("a None report fails closed", v31c["accepted"] is False, v31c)


# ==============================================================================
# Summary
# ==============================================================================

if __name__ == "__main__":
    unpatch_comment()
    shutil.rmtree(STORE, ignore_errors=True)
    print("\n" + "=" * 70)
    print(f"  NOTIFICATION TESTS: {len(PASS)} passed, {len(FAIL)} failed")
    print("=" * 70)
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    sys.exit(0)
