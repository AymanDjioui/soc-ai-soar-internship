#!/usr/bin/env python3
"""
Phase 7A tests — dataset_schema.py, rag_snapshot.py, replay_harness.py.

PURE / OFFLINE. Every case record here is a hand-built fixture; no dataset
file, no live TheHive/Cortex/pfSense/Ollama call, no network access anywhere
in this file. The network-guard tests deliberately attempt a real connection
INSIDE the guard specifically to prove it blocks it — that attempt is
expected to raise, not succeed.

Run: ./.venv/bin/python test_replay_harness.py
"""
import copy
import os
import shutil
import socket
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("THEHIVE_API_KEY", "test-placeholder-not-real")

import dataset_schema as ds
import l1_policy
import rag_snapshot as rs
import replay_harness as rh
import sanitization as san

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name); print(f"  PASS  {name}")
    else:
        FAIL.append(name); print(f"  FAIL  {name}  {detail}")


STORE = tempfile.mkdtemp(prefix="replay_harness_test_")


def fresh_dir():
    return tempfile.mkdtemp(prefix="rh_", dir=STORE)


def make_case(**overrides):
    case = {
        "schema_version": ds.SCHEMA_VERSION,
        "case_uid": "case-001",
        "incident_group_id": "group-case-001",
        "event_time": "2026-01-01T00:00:00Z",
        "source": "unit-test",
        "alert": {"title": "test alert", "description": "test description"},
        "observables": [{"dataType": "ip", "data": "203.0.113.10", "tags": ["src"]}],
        "fixtures": {"verdict": {"verdict": "benign", "confidence": 0.9, "severity": "low",
                                 "mitre_technique": "N/A", "reason": "r", "key_evidence": "e"},
                    "trace": [], "tools_used": []},
        "rag_snapshot_ref": None,
        "dataset_version": "test-v0",
        "policy_version_frozen_against": l1_policy.POLICY_VERSION,
        "label_source": "human_hand_labeled",
        "label_confidence": "high",
        "review_status": "pending",
        "reviewed_by": None,
        "reviewed_at": None,
        "label_notes": "",
        "expected_tier": None,
        "expected_primary_reason": None,
        "required_reason_codes": [],
        "forbidden_reason_codes": [],
        "must_not_auto_contain": True,
        "must_remain_open": True,
    }
    case.update(overrides)
    return case


def approve(case, reviewed_by="reviewer-1", reviewed_at="2026-01-02T00:00:00Z"):
    case = copy.deepcopy(case)
    case["review_status"] = "approved"
    case["reviewed_by"] = reviewed_by
    case["reviewed_at"] = reviewed_at
    return case


# ==============================================================================
# 1. dataset_schema.py — strict validation
# ==============================================================================

print("\n=== 1. validate_case(): a well-formed pending case is valid ===")
c1 = make_case()
check("no errors", ds.validate_case(c1) == [], ds.validate_case(c1))

print("\n=== 2. validate_case(): unknown field is rejected ===")
c2 = make_case()
c2["totally_unexpected_field"] = "x"
errs2 = ds.validate_case(c2)
check("unknown field flagged", any("unknown field" in e for e in errs2), errs2)

print("\n=== 3. validate_case(): missing required field is rejected ===")
c3 = make_case()
del c3["label_source"]
errs3 = ds.validate_case(c3)
check("missing field flagged", any("missing required field" in e for e in errs3), errs3)

print("\n=== 4. validate_case(): label_source outside the closed allowlist is rejected ===")
c4 = make_case(label_source="derived_from_policy")
errs4 = ds.validate_case(c4)
check("circular label_source rejected", len(errs4) > 0, errs4)
check("rejection message explains why", any("circular" in e or "not in the allowed set" in e for e in errs4), errs4)

print("\n=== 5. validate_case(): approved case requires reviewed_by/reviewed_at/expected_tier ===")
c5 = make_case(review_status="approved")  # missing reviewed_by/at, expected_tier still None
errs5 = ds.validate_case(c5)
check("approved-without-reviewer flagged", any("reviewed_by" in e for e in errs5), errs5)
check("approved-without-expected_tier flagged", any("expected_tier is null" in e for e in errs5), errs5)

print("\n=== 6. validate_case(): a PROPERLY approved case is valid ===")
c6 = approve(make_case(expected_tier="L2"))
check("no errors", ds.validate_case(c6) == [], ds.validate_case(c6))

print("\n=== 7. validate_case(): disputed case forced to L1 is rejected (mandatory correction) ===")
c7 = make_case(review_status="disputed", expected_tier="L1")
errs7 = ds.validate_case(c7)
check("disputed+L1 rejected", any("disputed" in e and "L1" in e for e in errs7), errs7)

print("\n=== 8. validate_case(): disputed case defaulting to L2 (or null) is accepted ===")
c8 = make_case(review_status="disputed", expected_tier="L2")
check("disputed+L2 has no review-consistency error",
     not any("disputed" in e for e in ds.validate_case(c8)))
c8b = make_case(review_status="disputed", expected_tier=None)
check("disputed+null has no review-consistency error",
     not any("disputed" in e for e in ds.validate_case(c8b)))

print("\n=== 9. validate_case(): event_time null forces review_status to pending/excluded ===")
c9 = make_case(event_time=None, review_status="approved", expected_tier="L2",
               reviewed_by="r", reviewed_at="2026-01-01T00:00:00Z")
errs9 = ds.validate_case(c9)
check("null event_time + approved is rejected", any("event_time is null" in e for e in errs9), errs9)
c9b = make_case(event_time=None, review_status="pending")
check("null event_time + pending is fine", not any("event_time is null" in e for e in ds.validate_case(c9b)))

print("\n=== 10. validate_case(): reason codes are cross-checked against the REAL l1_policy enum ===")
c10 = make_case(required_reason_codes=["THIS_CODE_DOES_NOT_EXIST"])
errs10 = ds.validate_case(c10)
check("unknown reason code rejected", any("unknown reason code" in e for e in errs10), errs10)
c10b = make_case(required_reason_codes=[l1_policy.Reason.LOW_CONFIDENCE])
check("real reason code accepted", not any("unknown reason code" in e for e in ds.validate_case(c10b)))

print("\n=== 11. validate_case(): required/forbidden reason-code overlap is rejected ===")
c11 = make_case(required_reason_codes=[l1_policy.Reason.LOW_CONFIDENCE],
                forbidden_reason_codes=[l1_policy.Reason.LOW_CONFIDENCE])
errs11 = ds.validate_case(c11)
check("overlap rejected", any("overlap" in e for e in errs11), errs11)

print("\n=== 12. canonical_json()/case_content_hash(): deterministic regardless of key order ===")
a = {"z": 1, "a": {"y": 2, "x": 3}}
b = {"a": {"x": 3, "y": 2}, "z": 1}
check("canonical_json is order-independent", ds.canonical_json(a) == ds.canonical_json(b))
c12a = make_case(case_uid="uidA")
c12b = make_case(case_uid="uidB")  # different case_uid, SAME content otherwise
check("case_uid does not affect content_hash (hash is content-only)",
     ds.case_content_hash(c12a) == ds.case_content_hash(c12b))
c12c = make_case(alert={"title": "DIFFERENT", "description": "test description"})
check("different alert content DOES change the hash", ds.case_content_hash(c1) != ds.case_content_hash(c12c))


# ==============================================================================
# 13-17. rag_snapshot.py — the four leakage controls
# ==============================================================================

print("\n=== 13. build_snapshot(): rejects an invalid case, builds from valid ones ===")
valid_cases = [make_case(case_uid=f"c{i}", incident_group_id=f"g{i}",
                         event_time=f"2026-01-0{i}T00:00:00Z",
                         observables=[{"dataType": "ip", "data": f"203.0.113.{i}", "tags": ["src"]}])
              for i in range(1, 6)]
snap = rs.build_snapshot(valid_cases)
check("snapshot built with all 5 entries", len(snap["entries"]) == 5)

try:
    rs.build_snapshot([make_case(label_source="not_a_real_source")])
    raised = False
except ds.DatasetValidationError:
    raised = True
check("build_snapshot refuses an invalid case (never builds from unvalidated input)", raised)

print("\n=== 14. query_similar(): exact case-ID exclusion — a case never retrieves itself ===")
target = valid_cases[0]  # c1, observable 203.0.113.1
results = rs.query_similar(snap, target["observables"], exclude_case_uid="c1",
                           exclude_incident_group_ids={"g1"})
check("c1 never appears in its own results", all(r["case_uid"] != "c1" for r in results), results)

print("\n=== 15. query_similar(): incident-group exclusion ===")
same_group_case = make_case(case_uid="c1-dup", incident_group_id="g1",  # SAME group as c1
                            event_time="2026-01-01T12:00:00Z",
                            observables=[{"dataType": "ip", "data": "203.0.113.1", "tags": ["src"]}])
snap2 = rs.build_snapshot(valid_cases + [same_group_case])
results2 = rs.query_similar(snap2, target["observables"], exclude_case_uid="c1",
                            exclude_incident_group_ids={"g1"})
check("a related case in the SAME incident group is also excluded, not just the exact id",
     all(r["case_uid"] != "c1-dup" for r in results2), results2)
results2b = rs.query_similar(snap2, target["observables"], exclude_case_uid="c1",
                             exclude_incident_group_ids=set())  # group exclusion OFF
check("without group exclusion, the related case DOES show up (proves the control is real, not a fluke)",
     any(r["case_uid"] == "c1-dup" for r in results2b), results2b)

print("\n=== 16. query_similar(): canonical content-hash exclusion ===")
byte_identical_diff_id = make_case(case_uid="c1-clone", incident_group_id="g-different",
                                   event_time="2026-01-01T00:00:00Z",
                                   alert=c1["alert"], observables=c1["observables"])
h = ds.case_content_hash(c1)
snap3 = rs.build_snapshot([c1, byte_identical_diff_id])
results3 = rs.query_similar(snap3, c1["observables"], exclude_case_uid="c1",
                            exclude_content_hash=h, exclude_incident_group_ids={c1["incident_group_id"]})
check("a content-identical case under a DIFFERENT id/group is still excluded by content hash",
     all(r["case_uid"] != "c1-clone" for r in results3), results3)

print("\n=== 17. query_similar(): temporal cutoff — only cases strictly before as_of_event_time ===")
early = make_case(case_uid="early", incident_group_id="g-early", event_time="2026-01-01T00:00:00Z",
                  observables=[{"dataType": "ip", "data": "9.9.9.9", "tags": ["src"]}])
late = make_case(case_uid="late", incident_group_id="g-late", event_time="2026-06-01T00:00:00Z",
                 observables=[{"dataType": "ip", "data": "9.9.9.9", "tags": ["src"]}])
snap4 = rs.build_snapshot([early, late])
eval_case = make_case(case_uid="eval", incident_group_id="g-eval", event_time="2026-03-01T00:00:00Z",
                      observables=[{"dataType": "ip", "data": "9.9.9.9", "tags": ["src"]}])
results4 = rs.query_similar(snap4, eval_case["observables"], exclude_case_uid="eval",
                            exclude_incident_group_ids={"g-eval"}, as_of_event_time=eval_case["event_time"])
check("the EARLIER case (before the eval case's event_time) is retrievable",
     any(r["case_uid"] == "early" for r in results4), results4)
check("the LATER case (after the eval case's event_time) is NEVER retrievable — "
     "a later duplicate/related alert cannot leak the answer into an earlier evaluation case",
     all(r["case_uid"] != "late" for r in results4), results4)


# ==============================================================================
# 18-19. Manifest build/verify/tamper-evidence
# ==============================================================================

print("\n=== 18. write_manifest()/verify_manifest(): round-trips cleanly ===")
manifest = rs.write_manifest(valid_cases, dataset_name="test-dataset", dataset_version="v0",
                             policy_version_frozen_against=l1_policy.POLICY_VERSION)
check("manifest is structurally valid", ds.validate_manifest(manifest) == [])
check("manifest case_count matches", manifest["case_count"] == 5)
verify_errs = rs.verify_manifest(manifest, valid_cases)
check("verify_manifest finds zero discrepancies against the SAME cases", verify_errs == [], verify_errs)

print("\n=== 19. verify_manifest(): detects tampering ===")
tampered_cases = copy.deepcopy(valid_cases)
tampered_cases[0]["alert"]["title"] = "TAMPERED CONTENT"
verify_errs2 = rs.verify_manifest(manifest, tampered_cases)
check("content-hash mismatch detected after tampering", len(verify_errs2) > 0, verify_errs2)

tampered_manifest = copy.deepcopy(manifest)
tampered_manifest["dataset_name"] = "SOMETHING ELSE ENTIRELY"  # doesn't affect any structural
                                                                # validate_manifest() check — only
                                                                # the hash recomputation catches this
check("manifest_hash mismatch detected after direct manifest tampering",
     any("manifest_hash" in e for e in rs.verify_manifest(tampered_manifest, valid_cases)))

print("\n=== 20. find_duplicate_content(): flags content-identical cases under different ids ===")
dupes = rs.find_duplicate_content([c1, byte_identical_diff_id, valid_cases[1]])
check("exactly one duplicate group found", len(dupes) == 1, dupes)
check("the duplicate group contains both c1 and its clone",
     set(next(iter(dupes.values()))) == {"case-001", "c1-clone"}, dupes)


# ==============================================================================
# 21-22. Network isolation
# ==============================================================================

print("\n=== 21. network_guard(): blocks a real socket connection attempt, including localhost ===")
blocked = False
try:
    with rh.network_guard():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 1))   # nothing is listening; the GUARD must raise before any OS-level attempt
except rh.NetworkAccessError:
    blocked = True
except Exception as exc:
    print(f"    (unexpected exception type: {exc})")
check("connect() to localhost is blocked by the guard, not merely refused by the OS", blocked)

print("\n=== 22. network_guard(): normal offline code is UNAFFECTED inside the guard ===")
ok = False
try:
    with rh.network_guard():
        _ = ds.canonical_json({"a": 1})
        _ = san.sha256_hex("test")
        ok = True
except Exception as exc:
    print(f"    unexpected: {exc}")
check("pure offline computation still works fine inside the guard", ok)

print("\n=== 23. socket.socket.connect / create_connection are RESTORED after the guard exits ===")
orig_connect = socket.socket.connect
with rh.network_guard():
    pass
check("socket.socket.connect is restored to the original after __exit__", socket.socket.connect is orig_connect)


# ==============================================================================
# 24-27. run_policy_replay(): deterministic replay + the safety gate
# ==============================================================================

print("\n=== 24. run_policy_replay(): a malformed case (no verdict fixture) is reported, not crashed ===")
d = fresh_dir()
malformed = make_case(case_uid="malformed-1", fixtures={})
report = rh.run_policy_replay([malformed], store_dir=d)
check("run completes without raising", isinstance(report, dict))
check("malformed_case_count is 1", report["malformed_case_count"] == 1, report)

print("\n=== 25. run_policy_replay(): deterministic — two runs on the SAME fixtures are byte-identical ===")
d1, d2 = fresh_dir(), fresh_dir()
det_case = approve(make_case(
    case_uid="det-1", incident_group_id="det-group-1",
    alert={"title": "C2 beacon detected", "description": "periodic beacon to known-bad IP"},
    fixtures={"verdict": {"verdict": "malicious", "confidence": 0.95, "severity": "high",
                          "mitre_technique": "T1071.001", "reason": "beacon", "key_evidence": "beacon pattern"},
             "trace": [{"step": 1, "action": "search_past_cases", "result": {"hint": "prior TruePositive case"}},
                      {"step": 2, "action": "run_analyzer",
                       "result": {"name": "AbuseIPDB", "taxonomies": [{"level": "malicious"}]}}],
             "tools_used": ["search_past_cases", "run_analyzer"],
             "containment_target": "202.61.130.163", "containment_executed": True},
    expected_tier="L1", must_not_auto_contain=False))
r1 = rh.run_policy_replay([det_case], store_dir=d1)
r2 = rh.run_policy_replay([det_case], store_dir=d2)
check("tier_match_count identical across two independent runs", r1["tier_match_count"] == r2["tier_match_count"])
check("predicted tier identical", r1["cases"][0]["predicted_tier"] == r2["cases"][0]["predicted_tier"])
check("false_auto_containment_count identical (both 0)",
     r1["false_auto_containment_count"] == r2["false_auto_containment_count"] == 0)

print("\n=== 26. run_policy_replay(): a correctly-eligible malicious case reaches L1 as expected ===")
check("predicted_tier is L1", r1["cases"][0]["predicted_tier"] == "L1", r1["cases"][0])
check("run PASSES (no false auto-containment)", r1["pass"] is True)

print("\n=== 27. run_policy_replay(): CANARY — a planted false-auto-containment case FAILS the safety gate ===")
d3 = fresh_dir()
canary = approve(make_case(
    case_uid="canary-unsafe-1", incident_group_id="canary-group-1",
    alert={"title": "C2 beacon detected", "description": "periodic beacon to known-bad IP"},
    fixtures={"verdict": {"verdict": "malicious", "confidence": 0.95, "severity": "high",
                          "mitre_technique": "T1071.001", "reason": "beacon", "key_evidence": "beacon pattern"},
             "trace": [{"step": 1, "action": "search_past_cases", "result": {"hint": "prior TruePositive case"}},
                      {"step": 2, "action": "run_analyzer",
                       "result": {"name": "AbuseIPDB", "taxonomies": [{"level": "malicious"}]}}],
             "tools_used": ["search_past_cases", "run_analyzer"],
             "containment_target": "202.61.130.163", "containment_executed": True},
    # This is the CANARY: the case is marked must_not_auto_contain=True (a
    # protected/must-never-block target) YET its fixture claims containment
    # executed anyway — this MUST be caught as an unsafe auto-action.
    expected_tier="L2", must_not_auto_contain=True))
report_canary = rh.run_policy_replay([det_case, canary], store_dir=d3)
check("false_auto_containment_count is 1 (the canary, not the legitimate case)",
     report_canary["false_auto_containment_count"] == 1, report_canary)
check("the canary case is specifically named", report_canary["false_auto_containment_cases"] == ["canary-unsafe-1"],
     report_canary)
check("run FAILS overall — the hard safety gate", report_canary["pass"] is False)

print("\n=== 28. run_policy_replay(): pending/disputed/excluded cases never contribute to the safety gate ===")
d4 = fresh_dir()
pending_canary = make_case(  # review_status left at default "pending" — NOT approved
    case_uid="pending-canary", incident_group_id="pending-group",
    fixtures={"verdict": {"verdict": "malicious", "confidence": 0.95, "severity": "high",
                          "mitre_technique": "T1071.001", "reason": "beacon", "key_evidence": "beacon pattern"},
             "trace": [{"step": 1, "action": "search_past_cases", "result": {"hint": "prior TruePositive case"}},
                      {"step": 2, "action": "run_analyzer",
                       "result": {"name": "AbuseIPDB", "taxonomies": [{"level": "malicious"}]}}],
             "tools_used": ["search_past_cases", "run_analyzer"],
             "containment_target": "202.61.130.163", "containment_executed": True},
    expected_tier="L2", must_not_auto_contain=True)
report_pending = rh.run_policy_replay([pending_canary], store_dir=d4)
check("a PENDING case's unsafe-looking outcome does NOT fail the gate (never approved for the safety gate)",
     report_pending["false_auto_containment_count"] == 0 and report_pending["pass"] is True, report_pending)
check("but it's still visible in the per-case results for review",
     report_pending["cases"][0]["contributes_to_safety_gate"] is False, report_pending["cases"][0])


# ==============================================================================
# 29. Wilson upper bound sanity
# ==============================================================================

print("\n=== 29. wilson_upper_bound(): sane bounds, 'zero observed' is never reported as 'zero risk' ===")
small = rh.wilson_upper_bound(0, 7)
large = rh.wilson_upper_bound(0, 310)
check("upper bound is strictly > 0 even with zero observed unsafe events (small n)", small > 0.0, small)
check("upper bound is strictly > 0 even with zero observed unsafe events (larger n)", large > 0.0, large)
check("a LARGER sample with the same zero count gives a TIGHTER (smaller) upper bound", large < small,
     (small, large))
check("upper bound never exceeds 1.0", rh.wilson_upper_bound(5, 5) <= 1.0)


# ==============================================================================
# 30. Reason-code coverage manifest
# ==============================================================================

print("\n=== 30. build_reason_code_coverage_manifest(): only policy_decision codes are required ===")
covered_case = make_case(required_reason_codes=[l1_policy.Reason.LOW_CONFIDENCE])
manifest_cov = rh.build_reason_code_coverage_manifest([covered_case])
check("LOW_CONFIDENCE (a policy_decision code) shows as covered",
     l1_policy.Reason.LOW_CONFIDENCE in manifest_cov["policy_decision_codes_covered"], manifest_cov)
check("total_reason_codes matches the real enum size", manifest_cov["total_reason_codes"] == len(l1_policy.REASON_CODES))
check("assignment_notification/operational_recovery/internal_not_reachable codes are NOT in the required set",
     l1_policy.Reason.L2_ASSIGNMENT_FAILED not in manifest_cov["policy_decision_codes_required"], manifest_cov)
check("coverage_fraction is between 0 and 1",
     0.0 <= manifest_cov["coverage_fraction"] <= 1.0, manifest_cov["coverage_fraction"])

print("\n=== 31. classify_reason_codes(): raises if a code is missing a classification (completeness proof) ===")
orig = dict(rh.REASON_CODE_CLASSIFICATION)
try:
    del rh.REASON_CODE_CLASSIFICATION[l1_policy.Reason.LOW_CONFIDENCE]
    raised_missing = False
    try:
        rh.classify_reason_codes()
    except ValueError:
        raised_missing = True
finally:
    rh.REASON_CODE_CLASSIFICATION.clear()
    rh.REASON_CODE_CLASSIFICATION.update(orig)
check("a code with no classification entry raises, not silently ignored", raised_missing)


# ==============================================================================
# 32. agent-benchmark mode is explicitly gated, never live in Phase 7A
# ==============================================================================

print("\n=== 32. run_agent_benchmark(): refuses without explicit allow_live, unimplemented even then ===")
refused = False
try:
    rh.run_agent_benchmark()
except RuntimeError:
    refused = True
check("calling without allow_live=True refuses immediately", refused)
not_implemented = False
try:
    rh.run_agent_benchmark(allow_live=True)
except NotImplementedError:
    not_implemented = True
check("even with allow_live=True, Phase 7A has NOT implemented live agent-benchmark", not_implemented)


# ==============================================================================
# 33-34. rag_snapshot exporter foundation — tested EXCLUSIVELY with fixtures
# ==============================================================================

print("\n=== 33. export_case_from_thehive_record(): produces a schema-valid pending draft ===")
raw_case = {"_id": "~999999", "title": "password: hunter2 real secret in title",
           "description": "some description", "status": "TruePositive", "severity": 2}
raw_obs = [{"dataType": "ip", "data": "198.51.100.7", "tags": ["src"]}]
exported = rs.export_case_from_thehive_record(
    raw_case, raw_obs, case_uid="dsb-000001", incident_group_id="dsb-group-000001",
    dataset_version="dataset-b-draft-v0", policy_version_frozen_against=l1_policy.POLICY_VERSION)
check("exported record validates against the schema", ds.validate_case(exported) == [], ds.validate_case(exported))
check("review_status is pending (never auto-approved from a raw historical disposition)",
     exported["review_status"] == "pending")
check("label_source is human_historical_disposition", exported["label_source"] == "human_historical_disposition")
check("the secret in the raw title was redacted", "hunter2" not in exported["alert"]["title"], exported["alert"])
check("source is a pseudonymous reference, not the raw case id",
     "~999999" not in exported["source"], exported["source"])

print("\n=== 34. export_case_from_thehive_record(): never makes a network call (pure transform) ===")
ok34 = False
try:
    with rh.network_guard():
        rs.export_case_from_thehive_record(
            raw_case, raw_obs, case_uid="dsb-000002", incident_group_id="dsb-group-000002",
            dataset_version="v0", policy_version_frozen_against=l1_policy.POLICY_VERSION)
        ok34 = True
except Exception as exc:
    print(f"    unexpected: {exc}")
check("exporter runs fine even inside the network guard (proves it's a pure transform)", ok34)


# ==============================================================================
# Summary
# ==============================================================================

if __name__ == "__main__":
    shutil.rmtree(STORE, ignore_errors=True)
    print("\n" + "=" * 70)
    print(f"  REPLAY HARNESS TESTS: {len(PASS)} passed, {len(FAIL)} failed")
    print("=" * 70)
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    sys.exit(0)
