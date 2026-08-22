#!/usr/bin/env python3
"""
Phase 7C tests — review_rubric.py, review_dataset.py, and the v2 sample-
selection correction in export_dataset_b_candidates.py.

PURE / OFFLINE. Fixture-based candidates for isolated unit tests; a handful
of integration checks run against the REAL exported ai/testset/
dataset_b_candidates/ files (reading them is offline/safe — no network
call). No test ever writes to the real candidate directory or its
manifests; every write-testing test uses a temp directory.

Run: ./.venv/bin/python test_review_dataset.py
"""
import copy
import json
import os
import shutil
import socket
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("THEHIVE_API_KEY", "test-placeholder-not-real")

import dataset_schema as ds
import export_dataset_b_candidates as edb
import rag_snapshot as rs
import replay_harness as rh
import review_dataset as rd
import review_rubric as rr

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name); print(f"  PASS  {name}")
    else:
        FAIL.append(name); print(f"  FAIL  {name}  {detail}")


STORE = tempfile.mkdtemp(prefix="review_dataset_test_")


def fresh_dir():
    return tempfile.mkdtemp(prefix="rdt_", dir=STORE)


REAL_CANDIDATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "..", "ai", "testset", "dataset_b_candidates")


def make_candidate(**overrides):
    case = {
        "schema_version": ds.SCHEMA_VERSION,
        "case_uid": "dsb-c-testfixture01",
        "incident_group_id": "grp-test1",
        "event_time": "2026-01-01T00:00:00Z",
        "closure_time": "2026-01-02T00:00:00Z",
        "source": "thehive:case:abc123",
        "alert": {"title": "Suricata alert", "description": "test description", "severity": 2},
        "observables": [{"dataType": "ip", "data": "203.0.113.10", "tags": ["src"]}],
        "fixtures": {},
        "rag_snapshot_ref": None,
        "dataset_version": "test-v0",
        "policy_version_frozen_against": "test-policy-v1",
        "label_source": "human_historical_disposition",
        "label_confidence": "medium",
        "review_status": "pending",
        "reviewed_by": None,
        "reviewed_at": None,
        "label_notes": "draft export — historical disposition 'TruePositive' is a CANDIDATE label, "
                      "not yet human-reviewed/approved",
        "expected_tier": None,
        "expected_primary_reason": None,
        "required_reason_codes": [],
        "forbidden_reason_codes": [],
        "must_not_auto_contain": False,
        "must_remain_open": True,
    }
    case.update(overrides)
    return case


def write_candidate_set(dirpath, cases):
    for c in cases:
        with open(os.path.join(dirpath, f"{c['case_uid']}.json"), "w", encoding="utf-8") as fh:
            json.dump(c, fh, indent=2, sort_keys=True)
    manifest = rs.write_manifest(cases, dataset_name="test", dataset_version="v0",
                                 policy_version_frozen_against="test-policy-v1")
    with open(os.path.join(dirpath, "MANIFEST.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    return manifest


# ==============================================================================
# 1-2. Network isolation
# ==============================================================================

print("\n=== 1. network_guard() actually blocks a real socket connection attempt ===")
# review_dataset.py transitively imports rag_snapshot.py, which imports
# thehive4py/requests at module level (Phase 7B live-export code lives in
# the same module as the offline replay helpers) — importing a
# network-CAPABLE library is not itself a network call, so that is not the
# property to test. The property that matters is: while network_guard() is
# active (as it is for the whole of review_dataset.py's main()), an actual
# socket-level connection attempt is refused, regardless of which library
# tries to make it.
blocked = False
try:
    with rh.network_guard():
        socket.socket().connect(("127.0.0.1", 1))
except rh.NetworkAccessError:
    blocked = True
except Exception as exc:
    print(f"    unexpected exception type: {exc!r}")
check("a real socket.connect() call is refused while network_guard() is active", blocked)

blocked_create = False
try:
    with rh.network_guard():
        socket.create_connection(("127.0.0.1", 1))
except rh.NetworkAccessError:
    blocked_create = True
except Exception as exc:
    print(f"    unexpected exception type: {exc!r}")
check("socket.create_connection() is also refused (the urllib3/requests entry point)", blocked_create)

connect_restored = socket.socket.connect is not None and "blocked_connect" not in repr(socket.socket.connect)
check("the guard fully restores the real socket.connect after exiting (no permanent breakage)",
     connect_restored)

print("\n=== 2. every review_dataset.py pure function runs fine inside network_guard() ===")
d = fresh_dir()
cases = [make_candidate(case_uid=f"dsb-c-t{i}", incident_group_id=f"grp-t{i}") for i in range(3)]
write_candidate_set(d, cases)
ok = False
try:
    with rh.network_guard():
        by_uid = rd.load_and_verify_candidates(candidates_dir=d)
        rd.record_decision("rev-x", by_uid["dsb-c-t0"],
                           {"review_status": "approved", "expected_tier": "L2",
                            "label_confidence": "high"}, overlay_dir=fresh_dir())
        ok = True
except Exception as exc:
    print(f"    unexpected: {exc}")
check("full offline review flow works inside the network guard", ok)


# ==============================================================================
# 3-4. Manifest/tamper protection
# ==============================================================================

print("\n=== 3. load_and_verify_candidates(): tampering blocks review ===")
d = fresh_dir()
cases = [make_candidate(case_uid="dsb-c-t1", incident_group_id="grp-t1")]
write_candidate_set(d, cases)
# tamper AFTER writing the manifest
tampered = copy.deepcopy(cases[0])
tampered["alert"]["title"] = "TAMPERED"
with open(os.path.join(d, "dsb-c-t1.json"), "w", encoding="utf-8") as fh:
    json.dump(tampered, fh, indent=2, sort_keys=True)
raised = False
try:
    rd.load_and_verify_candidates(candidates_dir=d)
except RuntimeError:
    raised = True
check("tampered candidate set refuses to load for review", raised)

print("\n=== 4. verify_sample_against_candidates(): sample-level tamper detection ===")
d = fresh_dir()
cases = [make_candidate(case_uid=f"dsb-c-t{i}", incident_group_id=f"grp-t{i}") for i in range(2)]
write_candidate_set(d, cases)
by_uid = rd.load_and_verify_candidates(candidates_dir=d)
fake_sample = {"case_content_hashes": {"dsb-c-t0": "0" * 64}}  # deliberately wrong hash
errs = rd.verify_sample_against_candidates(fake_sample, by_uid)
check("wrong sample hash detected", len(errs) > 0, errs)
real_sample = {"case_content_hashes": {uid: ds.case_content_hash(c) for uid, c in by_uid.items()}}
check("correct sample hashes verify clean", rd.verify_sample_against_candidates(real_sample, by_uid) == [])


# ==============================================================================
# 5-7. Atomic append / resume / original files untouched
# ==============================================================================

print("\n=== 5. atomic_append_jsonl(): appends without truncating existing content ===")
d = fresh_dir()
path = os.path.join(d, "reviewer.jsonl")
rd.atomic_append_jsonl(path, {"case_uid": "a", "n": 1})
rd.atomic_append_jsonl(path, {"case_uid": "b", "n": 2})
lines = open(path).read().splitlines()
check("exactly 2 lines after 2 appends", len(lines) == 2, lines)
check("first line still has the FIRST record (never overwritten)",
     json.loads(lines[0])["case_uid"] == "a")
check("second line has the SECOND record", json.loads(lines[1])["case_uid"] == "b")

print("\n=== 6. resume: read_overlay() shows the LATEST decision per case_uid ===")
d = fresh_dir()
overlay_path = rd._overlay_path("rev-y", overlay_dir=d)
rd.atomic_append_jsonl(overlay_path, {"case_uid": "x", "review_status": "pending_first_pass"})
rd.atomic_append_jsonl(overlay_path, {"case_uid": "x", "review_status": "approved"})  # revision
overlay = rd.read_overlay("rev-y", overlay_dir=d)
check("latest decision wins on resume", overlay["x"]["review_status"] == "approved", overlay)

print("\n=== 7. original candidate files remain BYTE-IDENTICAL after a full review pass ===")
d = fresh_dir()
cases = [make_candidate(case_uid=f"dsb-c-t{i}", incident_group_id=f"grp-t{i}",
                        fixtures={"verdict": {"verdict": "malicious"}}) for i in range(3)]
write_candidate_set(d, cases)
before = {}
for c in cases:
    p = os.path.join(d, f"{c['case_uid']}.json")
    before[p] = open(p, "rb").read()

by_uid = rd.load_and_verify_candidates(candidates_dir=d)
overlay_dir = fresh_dir()
for uid, case in by_uid.items():
    rd.record_decision("rev-z", case, {"review_status": "approved", "expected_tier": "L2",
                                       "label_confidence": "high"}, overlay_dir=overlay_dir)

after_ok = all(open(p, "rb").read() == content for p, content in before.items())
check("every original candidate file is byte-identical before/after a review pass", after_ok)


# ==============================================================================
# 8-10. Rubric enforcement
# ==============================================================================

print("\n=== 8. invalid reason codes are rejected ===")
case = make_candidate()
raised = False
try:
    rr_errs = rr.validate_decision(case, {
        "review_status": "approved", "expected_tier": "L2", "label_confidence": "high",
        "required_reason_codes": ["NOT_A_REAL_CODE"]})
    raised = len(rr_errs) > 0
except Exception:
    raised = True
check("unknown/non-externally-evaluable reason code rejected", raised)

internal_code_errs = rr.validate_decision(case, {
    "review_status": "approved", "expected_tier": "L2", "label_confidence": "high",
    "expected_primary_reason": "CASE_COMMENT_FAILED"})  # a real code, but internal_not_reachable
check("a REAL but non-externally-evaluable code (internal_not_reachable) is also rejected",
     len(internal_code_errs) > 0, internal_code_errs)

print("\n=== 9. incomplete L1 approval is rejected (no fixtures, no unambiguous target) ===")
no_evidence_case = make_candidate(fixtures={}, observables=[])
errs9 = rr.validate_decision(no_evidence_case, {
    "review_status": "approved", "expected_tier": "L1", "label_confidence": "high",
    "reviewer_id": "reviewer-a"})
check("L1 approval with zero evidence is rejected", len(errs9) > 0, errs9)
check("rejection message names the rubric rule", any("uncertainty must default to L2" in e for e in errs9), errs9)

print("\n=== 10. incomplete evidence CAN be approved with an L2 expectation ===")
errs10 = rr.validate_decision(no_evidence_case, {
    "review_status": "approved", "expected_tier": "L2", "label_confidence": "medium",
    "reviewer_id": "reviewer-a"})
check("L2 approval with missing evidence is accepted", errs10 == [], errs10)

print("\n=== 11. L1 approval succeeds WHEN evidence genuinely exists ===")
has_evidence_case = make_candidate(fixtures={"verdict": {"verdict": "malicious"}},
                                   observables=[{"dataType": "ip", "data": "203.0.113.5", "tags": ["src"]}])
errs11 = rr.validate_decision(has_evidence_case, {
    "review_status": "approved", "expected_tier": "L1", "label_confidence": "high",
    "expected_primary_reason": "L1_TRUE_POSITIVE_CONTAINED", "reviewer_id": "reviewer-a"})
check("L1 approval with real evidence present is accepted", errs11 == [], errs11)

print("\n=== 12. disputed case forced to L2/null (never L1) ===")
errs12 = rr.validate_decision(case, {"review_status": "disputed", "expected_tier": "L1",
                                     "label_confidence": "low", "reviewer_id": "reviewer-a"})
check("disputed + L1 rejected", len(errs12) > 0, errs12)

print("\n=== 13. reviewer identifier is required ===")
errs13 = rr.validate_decision(case, {"review_status": "excluded", "expected_tier": None,
                                     "label_confidence": "low", "reviewer_id": ""})
check("empty reviewer_id rejected", any("reviewer identifier" in e for e in errs13), errs13)


# ==============================================================================
# 14. No review record contains a secret
# ==============================================================================

print("\n=== 14. record_decision(): refuses to save a decision containing a secret ===")
case14 = make_candidate(fixtures={"verdict": {"verdict": "malicious"}},
                        observables=[{"dataType": "ip", "data": "203.0.113.5", "tags": ["src"]}])
d14 = fresh_dir()
raised14 = False
try:
    rd.record_decision("rev-secret", case14, {
        "review_status": "approved", "expected_tier": "L1", "label_confidence": "high",
        "expected_primary_reason": "L1_TRUE_POSITIVE_CONTAINED",
        "label_notes": "password: hunter2 was involved"}, overlay_dir=d14)
except ValueError:
    raised14 = True
check("a decision record with an embedded secret is refused, not saved", raised14)
check("no overlay file was created (or is empty) as a result",
     not os.path.exists(rd._overlay_path("rev-secret", overlay_dir=d14)) or
     open(rd._overlay_path("rev-secret", overlay_dir=d14)).read() == "")


# ==============================================================================
# 15. Conflict / adjudication
# ==============================================================================

print("\n=== 15. compute_conflicts(): disagreement between reviewers enters adjudication ===")
d15 = fresh_dir()
case15 = make_candidate(case_uid="dsb-c-dual1", fixtures={"verdict": {"verdict": "malicious"}},
                        observables=[{"dataType": "ip", "data": "203.0.113.9", "tags": ["src"]}])
assignments = {"queues": {"reviewer-a": ["dsb-c-dual1"], "reviewer-b": ["dsb-c-dual1"]},
              "dual_review": {"dsb-c-dual1": ["must_not_auto_contain"]}}
rd.record_decision("reviewer-a", case15, {"review_status": "approved", "expected_tier": "L1",
                                          "expected_primary_reason": "L1_TRUE_POSITIVE_CONTAINED",
                                          "label_confidence": "high"}, overlay_dir=d15)
rd.record_decision("reviewer-b", case15, {"review_status": "approved", "expected_tier": "L2",
                                          "label_confidence": "medium"}, overlay_dir=d15)
conflicts = rd.compute_conflicts(assignments, overlay_dir=d15)
check("a real tier disagreement is detected as a conflict", len(conflicts) == 1, conflicts)
check("the conflict names the case", conflicts[0]["case_uid"] == "dsb-c-dual1" if conflicts else False)

path = rd.write_adjudication_queue(conflicts, overlay_dir=d15)
check("adjudication queue file written", os.path.exists(path))

print("\n=== 16. compute_conflicts(): agreement produces NO conflict ===")
d16 = fresh_dir()
case16 = make_candidate(case_uid="dsb-c-dual2")
rd.record_decision("reviewer-a", case16, {"review_status": "approved", "expected_tier": "L2",
                                          "label_confidence": "high"}, overlay_dir=d16)
rd.record_decision("reviewer-b", case16, {"review_status": "approved", "expected_tier": "L2",
                                          "label_confidence": "medium"}, overlay_dir=d16)
assignments16 = {"queues": {"reviewer-a": ["dsb-c-dual2"], "reviewer-b": ["dsb-c-dual2"]},
                "dual_review": {"dsb-c-dual2": ["must_not_auto_contain"]}}
check("agreement -> zero conflicts", rd.compute_conflicts(assignments16, overlay_dir=d16) == [])


# ==============================================================================
# 17-19. v2 sample selection: determinism + incident-group cap
# ==============================================================================

print("\n=== 17. select_review_subset_v2(): incident-group cap is enforced ===")
big_group_cases = [make_candidate(case_uid=f"dsb-c-big{i}", incident_group_id="grp-big",
                                  event_time=f"2026-01-0{(i % 9) + 1}T00:00:00Z")
                   for i in range(10)]
other_cases = [make_candidate(case_uid=f"dsb-c-solo{i}", incident_group_id=f"grp-solo{i}",
                              must_not_auto_contain=True, label_notes="historical disposition "
                              "'FalsePositive' is a CANDIDATE label")
              for i in range(10)]
all_fixture_cases = big_group_cases + other_cases
dispositions = {c["case_uid"]: ds.extract_historical_disposition_hint(c) for c in all_fixture_cases}
selected, strata, group_rep, exceptions = edb.select_review_subset_v2(
    all_fixture_cases, dispositions, target=15, seed=42, max_per_group=3, exception_max_per_group=5)
check("no group exceeds the base cap except a documented exception",
     all(v <= 5 for v in group_rep.values()), group_rep)
check("the big group is capped, not dominant",
     group_rep.get("grp-big", 0) <= 5, group_rep)

print("\n=== 18. select_review_subset_v2(): deterministic — same input+seed -> same output ===")
sel_a, _, _, _ = edb.select_review_subset_v2(all_fixture_cases, dispositions, target=15, seed=42)
sel_b, _, _, _ = edb.select_review_subset_v2(all_fixture_cases, dispositions, target=15, seed=42)
check("identical selection across two independent calls",
     sorted(r["case_uid"] for r in sel_a) == sorted(r["case_uid"] for r in sel_b))

print("\n=== 19. select_review_subset_v2(): order-independent (the v1 gap, fixed) ===")
reversed_cases = list(reversed(all_fixture_cases))
sel_c, _, _, _ = edb.select_review_subset_v2(reversed_cases, dispositions, target=15, seed=42)
check("selection is the SAME even if the input list order is reversed",
     sorted(r["case_uid"] for r in sel_a) == sorted(r["case_uid"] for r in sel_c),
     (sorted(r["case_uid"] for r in sel_a), sorted(r["case_uid"] for r in sel_c)))


# ==============================================================================
# 20. Integration: the REAL v2 sample respects the cap
# ==============================================================================

print("\n=== 20. INTEGRATION: the real, already-written v2 sample respects the incident-group cap ===")
if os.path.isdir(REAL_CANDIDATES_DIR):
    v2_path = os.path.join(REAL_CANDIDATES_DIR, "REVIEW_SAMPLE_v2_MANIFEST.json")
    if os.path.exists(v2_path):
        v2 = json.load(open(v2_path, encoding="utf-8"))
        by_uid_real = {}
        for uid in v2["case_uids"]:
            by_uid_real[uid] = json.load(open(os.path.join(REAL_CANDIDATES_DIR, f"{uid}.json"), encoding="utf-8"))
        from collections import Counter
        real_group_counts = Counter(by_uid_real[uid]["incident_group_id"] for uid in v2["case_uids"])
        max_count = max(real_group_counts.values())
        check("the real v2 sample's largest incident-group representation is <= 5 (documented exception cap)",
             max_count <= 5, dict(real_group_counts))
        check("the real v2 sample size is 60", len(v2["case_uids"]) == 60, len(v2["case_uids"]))
    else:
        print("    (v2 manifest not found — skipping integration check)")
else:
    print("    (real candidates dir not found — skipping integration check)")


# ==============================================================================
# Summary
# ==============================================================================

if __name__ == "__main__":
    shutil.rmtree(STORE, ignore_errors=True)
    print("\n" + "=" * 70)
    print(f"  REVIEW DATASET TESTS: {len(PASS)} passed, {len(FAIL)} failed")
    print("=" * 70)
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    sys.exit(0)
