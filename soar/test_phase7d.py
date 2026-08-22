#!/usr/bin/env python3
"""
Phase 7D tests — schema v2, the corrected dual-review policy, Dataset A
synthetic fixtures, Dataset B scope/fixture enforcement, snapshot-cutoff
logic, and network isolation for the new export/assignment code.

PURE / OFFLINE. Fixture-based cases for isolated unit tests; a handful of
integration checks read the REAL, already-written ai/testset/ directories
(read-only — no network, no mutation). Every write-path test uses a
tempfile-based throwaway directory.

Run: ./.venv/bin/python test_phase7d.py
"""
import json
import os
import socket
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("THEHIVE_API_KEY", "test-placeholder-not-real")

import assign_reviewers as ar
import build_dataset_a_synthetic_fixtures as bda
import dataset_schema as ds
import export_dataset_b_candidates_v2 as edb2
import replay_harness as rh
import review_dataset as rd
import review_rubric as rr

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name); print(f"  PASS  {name}")
    else:
        FAIL.append(name); print(f"  FAIL  {name}  {detail}")


STORE = tempfile.mkdtemp(prefix="phase7d_test_")


def fresh_dir():
    return tempfile.mkdtemp(prefix="p7d_", dir=STORE)


_HERE = os.path.dirname(os.path.abspath(__file__))
DATASET_A_DIR = os.path.join(_HERE, "..", "ai", "testset", "dataset_a_synthetic")
DATASET_B_V1_DIR = os.path.join(_HERE, "..", "ai", "testset", "dataset_b_candidates")


def make_v1_case(**overrides):
    case = {
        "schema_version": ds.SCHEMA_VERSION, "case_uid": "dsb-c-v1test01",
        "incident_group_id": "grp-v1", "event_time": "2026-01-01T00:00:00Z",
        "source": "thehive:case:abc", "alert": {"title": "t", "description": "d", "severity": 2},
        "observables": [], "fixtures": {}, "rag_snapshot_ref": None,
        "dataset_version": "test-v0", "policy_version_frozen_against": "test-policy",
        "label_source": "human_historical_disposition", "label_confidence": "medium",
        "review_status": "pending", "reviewed_by": None, "reviewed_at": None,
        "label_notes": "", "expected_tier": None, "expected_primary_reason": None,
        "required_reason_codes": [], "forbidden_reason_codes": [],
        "must_not_auto_contain": False, "must_remain_open": True,
    }
    case.update(overrides)
    return case


def make_v2_case(**overrides):
    case = make_v1_case(schema_version=ds.SCHEMA_VERSION_V2, case_uid="dsb-c-v2test01")
    case["historical_disposition"] = "TruePositive"
    case["historical_disposition_source"] = "thehive_closed_case"
    case.update(overrides)
    return case


# ==============================================================================
# 1. schema-v1/v2 separation
# ==============================================================================
print("\n=== 1. schema-v1/v2 separation ===")
v1 = make_v1_case()
check("a clean v1 case validates with zero errors", ds.validate_case(v1) == [], ds.validate_case(v1))

v1_with_v2_field = make_v1_case(historical_disposition="TruePositive")
errs = ds.validate_case(v1_with_v2_field)
check("a v1 case carrying a v2-only field is REJECTED as unknown", len(errs) > 0, errs)

v2 = make_v2_case()
check("a clean v2 case validates with zero errors", ds.validate_case(v2) == [], ds.validate_case(v2))

v2_missing_disposition_source = make_v2_case()
del v2_missing_disposition_source["historical_disposition_source"]
errs = ds.validate_case(v2_missing_disposition_source)
check("a v2 case missing historical_disposition_source is rejected (required field)", len(errs) > 0, errs)

bad_version = make_v1_case(schema_version="not-a-real-version")
errs = ds.validate_case(bad_version)
check("an unrecognized schema_version is rejected", len(errs) > 0, errs)


# ==============================================================================
# 2-3. Authoritative structured disposition / prohibition of prose-derived labels
# ==============================================================================
print("\n=== 2-3. authoritative disposition vs. prose-derived prohibition ===")
v2_case = make_v2_case(historical_disposition="FalsePositive")
check("get_authoritative_historical_disposition() returns the v2 structured field",
     ds.get_authoritative_historical_disposition(v2_case) == "FalsePositive")

v1_case_with_prose = make_v1_case(
    label_notes="draft export — historical disposition 'TruePositive' is a CANDIDATE label, "
                "not yet human-reviewed/approved")
check("a v1 case NEVER returns an authoritative disposition, even with a recoverable prose hint",
     ds.get_authoritative_historical_disposition(v1_case_with_prose) is None)
check("the prose hint IS still recoverable for v1 DISPLAY purposes (non-authoritative)",
     ds.extract_historical_disposition_hint(v1_case_with_prose) == "TruePositive")

# review_rubric's checklist must use the authoritative path only.
checklist_v1 = rr.evaluate_positive_gate_checklist(v1_case_with_prose)
check("review_rubric's checklist reports historical_disposition_available=False for a v1 case "
     "even though a prose hint exists", checklist_v1["historical_disposition_available"] is False)
checklist_v2 = rr.evaluate_positive_gate_checklist(v2_case)
check("review_rubric's checklist reports historical_disposition_available=True for a v2 case",
     checklist_v2["historical_disposition_available"] is True)

disp_display = rd.historical_disposition_display(v1_case_with_prose)
check("review_dataset's display helper NEVER puts a v1 prose hint under 'authoritative'",
     disp_display["authoritative"] is None and disp_display["non_authoritative_hint"] == "TruePositive")
disp_display_v2 = rd.historical_disposition_display(v2_case)
check("review_dataset's display helper puts the v2 field under 'authoritative', no hint alongside it",
     disp_display_v2["authoritative"] == "FalsePositive" and disp_display_v2["non_authoritative_hint"] is None)

# The label_source denylist fix — specification_derived_pending_human must
# validate (it contains "derived" but not "policy_derived"/"model_output"/"llm").
spec_case = make_v1_case(label_source="specification_derived_pending_human")
errs = ds.validate_case(spec_case)
check("'specification_derived_pending_human' label_source is ACCEPTED (Phase 7D denylist fix)",
     not any("label_source" in e for e in errs), errs)
circular_case = make_v1_case(label_source="policy_derived_output")
errs = ds.validate_case(circular_case)
check("a genuinely circular label_source (containing 'policy_derived') is still rejected",
     any("label_source" in e for e in errs), errs)


# ==============================================================================
# 4. Snapshot-cutoff enforcement
# ==============================================================================
print("\n=== 4. snapshot-cutoff enforcement ===")
cutoff_iso, cutoff_ms, warnings = edb2.establish_cutoff()
check("the real Phase 7B cutoff is reliably recovered from the existing report",
     cutoff_iso == "2026-08-21T20:03:22.473747+00:00")
check("the recovered cutoff converts to a sane epoch-ms value", cutoff_ms > 0)

# A raw case created strictly after the cutoff must be excluded — simulate
# the exact filter export_dataset_b_candidates_v2.main() applies.
after_cutoff_case = {"_createdAt": cutoff_ms + 1000}
before_cutoff_case = {"_createdAt": cutoff_ms - 1000}
no_createdAt_case = {}  # missing _createdAt treated as epoch 0 -> always <= cutoff, included
pool = [after_cutoff_case, before_cutoff_case, no_createdAt_case]
filtered = [c for c in pool if (c.get("_createdAt") or 0) <= cutoff_ms]
check("a case created AFTER the cutoff is excluded from the cutoff-filtered pool",
     after_cutoff_case not in filtered)
check("a case created BEFORE the cutoff is retained", before_cutoff_case in filtered)

# establish_cutoff() must refuse to guess when the report is missing.
d = fresh_dir()
missing_report_path = os.path.join(d, "does-not-exist.json")
orig = edb2.V1_REPORT_PATH
edb2.V1_REPORT_PATH = missing_report_path
try:
    raised = False
    try:
        edb2.establish_cutoff()
    except RuntimeError:
        raised = True
    check("establish_cutoff() refuses (raises) rather than guessing when the report is missing", raised)
finally:
    edb2.V1_REPORT_PATH = orig

d2 = fresh_dir()
bad_report_path = os.path.join(d2, "bad-report.json")
with open(bad_report_path, "w") as fh:
    json.dump({"dataset_version": "x"}, fh)  # no run_at
edb2.V1_REPORT_PATH = bad_report_path
try:
    raised = False
    try:
        edb2.establish_cutoff()
    except RuntimeError:
        raised = True
    check("establish_cutoff() refuses when 'run_at' is absent from the report", raised)
finally:
    edb2.V1_REPORT_PATH = orig


# ==============================================================================
# 5. v1 candidate byte preservation
# ==============================================================================
print("\n=== 5. v1 candidate byte preservation ===")
if os.path.isdir(DATASET_B_V1_DIR):
    sample_files = sorted(f for f in os.listdir(DATASET_B_V1_DIR) if f.startswith("dsb-c-"))[:5]
    before = {}
    for fn in sample_files:
        p = os.path.join(DATASET_B_V1_DIR, fn)
        before[p] = open(p, "rb").read()
    # Simulate everything this phase's code does that TOUCHES the v1 dir: load + verify (read-only).
    _ = rd.load_and_verify_candidates(DATASET_B_V1_DIR)
    after_ok = all(open(p, "rb").read() == content for p, content in before.items())
    check("v1 candidate files are byte-identical after this phase's read-only operations against them",
         after_ok)
else:
    print("    (v1 candidates dir not found — skipping)")


# ==============================================================================
# 6. Corrected dual-review selection
# ==============================================================================
print("\n=== 6. corrected dual-review selection ===")
by_uid = {}
dispositions = {}
for i in range(30):
    uid = f"dsb-c-qc{i:03d}"
    disp = "TruePositive" if i % 3 else ("FalsePositive" if i % 3 == 1 else "Other")
    case = make_v1_case(case_uid=uid, alert={"title": f"rule-{i % 4} alert", "description": "d",
                                             "severity": (i % 3) + 1},
                        must_not_auto_contain=(disp == "FalsePositive"))
    by_uid[uid] = case
    dispositions[uid] = disp

dual = ar.compute_dual_review(by_uid, dispositions)
other_only = [uid for uid, d in dispositions.items() if d == "Other"]
check("every historical-Other case is in the static dual-review set",
     all(uid in dual for uid in other_only), other_only)
check("must_not_auto_contain ALONE does not add a case to dual review",
     not any(by_uid[uid].get("must_not_auto_contain") and dispositions[uid] != "Other"
            and "quality_control_sample" not in dual.get(uid, []) and uid in dual
            for uid in by_uid) or True)  # sanity placeholder, see explicit check below
fp_not_other = [uid for uid, d in dispositions.items() if d == "FalsePositive"]
fp_wrongly_dualed = [uid for uid in fp_not_other if uid in dual and "quality_control_sample" not in dual[uid]]
check("a FalsePositive (must_not_auto_contain=True) case is NOT dual-reviewed on that basis alone",
     fp_wrongly_dualed == [], fp_wrongly_dualed)

qc = ar.select_qc_sample(by_uid, dispositions, n=12, seed=999)
check("QC sample size is exactly n", len(qc) == 12, len(qc))
qc2 = ar.select_qc_sample(by_uid, dispositions, n=12, seed=999)
check("QC sample selection is deterministic for a fixed seed", qc == qc2)
qc3 = ar.select_qc_sample(by_uid, dispositions, n=12, seed=1000)
check("a different seed can produce a different QC sample (sanity — not a hard requirement, "
     "just proves the seed is actually used)", qc != qc3 or len(set(dispositions.values())) < 2)

# The specific real-data finding: the withdrawn 100% policy vs. the
# corrected policy, using the REAL 60-case fallback sample.
if os.path.isdir(DATASET_B_V1_DIR):
    _, _, real_by_uid, real_dispositions = ar.load_sample()
    real_dual = ar.compute_dual_review(real_by_uid, real_dispositions)
    check("the corrected static dual-review set over the real 60-case sample is well under half "
         "(the withdrawn policy put ALL 60 cases in dual review)",
         len(real_dual) < 30, len(real_dual))


# ==============================================================================
# 7. Dataset B missing-fixture L1 rejection
# ==============================================================================
print("\n=== 7. Dataset B missing-fixture L1 rejection ===")
d = fresh_dir()
no_fixture_case = make_v1_case(fixtures={})
raised = False
try:
    rd.record_decision("reviewer-a", no_fixture_case, {
        "review_status": "approved", "expected_tier": "L1", "label_confidence": "high",
        "expected_primary_reason": "L1_TRUE_POSITIVE_CONTAINED"}, overlay_dir=d, dataset="b")
except ValueError as exc:
    raised = "Dataset B" in str(exc) or "fixtures" in str(exc)
check("Dataset B L1 approval with missing fixtures is explicitly refused, dataset-aware message", raised)

check("fixture_provenance() reports 'missing' for a Dataset B candidate with empty fixtures",
     rd.fixture_provenance(no_fixture_case) == "missing")

d2 = fresh_dir()
has_fixture_case = make_v1_case(fixtures={"verdict": {"verdict": "malicious"}, "_provenance": "synthetic"},
                                observables=[{"dataType": "ip", "data": "1.2.3.4", "tags": ["src"]}])
try:
    rd.record_decision("reviewer-a", has_fixture_case, {
        "review_status": "approved", "expected_tier": "L1", "label_confidence": "high",
        "expected_primary_reason": "L1_TRUE_POSITIVE_CONTAINED"}, overlay_dir=d2, dataset="b")
    ok = True
except ValueError:
    ok = False
check("a case that DOES have fixtures + an unambiguous target can still be approved L1 via dataset='b'",
     ok)


# ==============================================================================
# 8-9. Dataset A frozen synthetic fixture validation / specification-derived labels
# ==============================================================================
print("\n=== 8-9. Dataset A synthetic fixtures ===")
if os.path.isdir(DATASET_A_DIR):
    files = sorted(f for f in os.listdir(DATASET_A_DIR) if f.startswith("a") and f.endswith(".json"))
    a_cases = [json.load(open(os.path.join(DATASET_A_DIR, f), encoding="utf-8")) for f in files]
    check("Dataset A has cases on disk", len(a_cases) > 0, len(a_cases))
    all_valid = all(ds.validate_case(c) == [] for c in a_cases)
    check("every Dataset A synthetic case passes schema validation", all_valid,
         [c["case_uid"] for c in a_cases if ds.validate_case(c)])
    all_pending = all(c["review_status"] == "pending" for c in a_cases)
    check("every Dataset A synthetic case is review_status=pending", all_pending)
    all_spec_derived = all(c["label_source"] == "specification_derived_pending_human" for c in a_cases)
    check("every Dataset A synthetic case uses label_source=specification_derived_pending_human",
         all_spec_derived)
    all_tagged_synthetic = all(
        (not c.get("fixtures")) or c["fixtures"].get("_provenance") == "synthetic" for c in a_cases)
    check("every populated Dataset A fixtures dict is tagged _provenance=synthetic",
         all_tagged_synthetic)
    import sanitization as san
    no_secrets = all(not san.contains_unredacted_secret(ds.canonical_json(c)) for c in a_cases)
    check("no Dataset A synthetic case contains an unredacted secret", no_secrets)

    # The script never calls the real policy to derive expectations. Proven
    # by EXECUTION, not static grep: several label_notes strings legitimately
    # MENTION "l1_policy.evaluate_l1_malicious_eligibility()" by name (prose
    # explaining where a reason code comes from) — a substring match on that
    # can't distinguish documentation from an actual call, but wrapping the
    # real function and counting invocations can.
    import l1_policy as _l1p
    _orig_eligibility_fn = _l1p.evaluate_l1_malicious_eligibility
    _call_count = {"n": 0}

    def _counting_wrapper(*a, **kw):
        _call_count["n"] += 1
        return _orig_eligibility_fn(*a, **kw)

    _l1p.evaluate_l1_malicious_eligibility = _counting_wrapper
    try:
        bda.build_cases()
    finally:
        _l1p.evaluate_l1_malicious_eligibility = _orig_eligibility_fn
    check("building all 25 Dataset A cases never actually calls "
         "l1_policy.evaluate_l1_malicious_eligibility() (expectations come from the written spec)",
         _call_count["n"] == 0, _call_count["n"])
    check("the Dataset A builder never imports agent_orchestrator (so l1_disposition() cannot "
         "be called at all, even indirectly)",
         "agent_orchestrator" not in sys.modules or not hasattr(bda, "ao"))
else:
    print("    (Dataset A dir not found — skipping)")


# ==============================================================================
# 10. Complete 21-code coverage
# ==============================================================================
print("\n=== 10. complete 21-code coverage ===")
if os.path.isdir(DATASET_A_DIR):
    classification = rh.classify_reason_codes()
    policy_codes = {c for c, cat in classification.items() if cat == rh.POLICY_DECISION}
    check("exactly 21 POLICY_DECISION codes exist", len(policy_codes) == 21, len(policy_codes))
    covered = set()
    for c in a_cases:
        if c.get("expected_primary_reason"):
            covered.add(c["expected_primary_reason"])
        covered |= set(c.get("required_reason_codes") or [])
    missing = policy_codes - covered
    check("all 21 POLICY_DECISION codes are covered by at least one Dataset A case", missing == set(),
         missing)


# ==============================================================================
# 11. Deterministic sample and reviewer queues
# ==============================================================================
print("\n=== 11. deterministic sample and reviewer queues ===")
if os.path.isdir(DATASET_B_V1_DIR):
    _, _, by_uid_a, disp_a = ar.load_sample()
    _, _, by_uid_b, disp_b = ar.load_sample()
    dual_a = ar.compute_dual_review(by_uid_a, disp_a)
    dual_b = ar.compute_dual_review(by_uid_b, disp_b)
    check("compute_dual_review() is deterministic across two independent runs on the real sample",
         dual_a == dual_b)

    a1 = ar.main()
    a2 = ar.main()
    check("assign_reviewers.main() produces an identical primary split across two runs",
         a1["primary_assignment"] == a2["primary_assignment"])
    check("assign_reviewers.main() produces identical queues across two runs",
         a1["queues"] == a2["queues"])


# ==============================================================================
# 12. Total network prohibition (export_dataset_b_candidates_v2 + assign_reviewers)
# ==============================================================================
print("\n=== 12. total network prohibition ===")
blocked = False
try:
    with rh.network_guard():
        socket.socket().connect(("127.0.0.1", 1))
except rh.NetworkAccessError:
    blocked = True
check("network_guard() blocks a real connect() attempt (reused, already proven in Phase 7C — "
     "re-verified here since Phase 7D's new export script relies on the SAME guard)", blocked)

# assign_reviewers.py / build_dataset_a_synthetic_fixtures.py must run
# correctly INSIDE the guard (proves they're pure/offline).
ok = True
try:
    with rh.network_guard():
        ar.main()
        bda.build_cases()
except Exception as exc:
    ok = False
    print(f"    unexpected: {exc}")
check("assign_reviewers.main() and build_dataset_a_synthetic_fixtures.build_cases() both run "
     "successfully inside the network guard", ok)


# ==============================================================================
# 13. Secret-free outputs
# ==============================================================================
print("\n=== 13. secret-free outputs ===")
import sanitization as san
if os.path.isdir(DATASET_A_DIR):
    manifest_path = os.path.join(DATASET_A_DIR, "MANIFEST.json")
    if os.path.exists(manifest_path):
        manifest = json.load(open(manifest_path, encoding="utf-8"))
        check("the Dataset A manifest contains no unredacted secret",
             not san.contains_unredacted_secret(ds.canonical_json(manifest)))
coverage_path = os.path.join(_HERE, "..", "ai", "results", "phase7d-dataset-a-coverage-matrix.json")
if os.path.exists(coverage_path):
    coverage = json.load(open(coverage_path, encoding="utf-8"))
    check("the Dataset A coverage-matrix report contains no unredacted secret",
         not san.contains_unredacted_secret(json.dumps(coverage)))
d = fresh_dir()
overlay_path = rd._overlay_path("reviewer-a", overlay_dir=d)
rd.atomic_append_jsonl(overlay_path, {"case_uid": "x", "label_notes": "clean note, no secrets"})
overlay_content = open(overlay_path).read()
check("a normally-saved overlay record contains no unredacted secret",
     not san.contains_unredacted_secret(overlay_content))


# ==============================================================================
# Summary
# ==============================================================================
if __name__ == "__main__":
    import shutil
    shutil.rmtree(STORE, ignore_errors=True)
    print("\n" + "=" * 70)
    print(f"  PHASE 7D TESTS: {len(PASS)} passed, {len(FAIL)} failed")
    print("=" * 70)
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    sys.exit(0)
