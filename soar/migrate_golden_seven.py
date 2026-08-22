#!/usr/bin/env python3
"""
Phase 7A — migrate the existing golden seven (`ai/testset/*.json`) into DRAFT
Phase 7 dataset case records.

Explicitly NOT a dataset lock: every migrated record is `review_status:
"pending"`. Existing ground truth (is_false_positive/severity/
mitre_technique/must_not_auto_block/rationale) is PRESERVED VERBATIM under a
legacy `ground_truth` key. New fields the Phase 7 schema requires but the
original 7-case schema never captured (expected_tier, expected_primary_
reason, required/forbidden_reason_codes, fixtures, event_time) are populated
ONLY where they can be established independently of the policy under
evaluation — anything else is left null/empty with an explicit label_note
explaining why, never invented to satisfy schema coverage.

`agent_bench.py` (untouched) is imported ONLY for its pure `synth_observables()`
helper — no live call is made anywhere in this script.

Run: ./.venv/bin/python migrate_golden_seven.py
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("THEHIVE_API_KEY", "test-placeholder-not-real")

import agent_bench
import dataset_schema as ds
import l1_policy
import sanitization as san

_HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE_DIR = os.path.join(_HERE, "..", "ai", "testset")
OUTPUT_DIR = os.path.join(_HERE, "..", "ai", "testset", "dataset_a_draft")
DATASET_VERSION = "dataset-a-draft-v0-2026-08-21"


def _sanitize_alert(alert: dict) -> dict:
    """Recursively sanitize every string leaf in the alert body. These 7
    cases are synthetic/documented (no real secrets expected), but every
    dataset case goes through the SAME redaction path regardless — no
    exceptions for "probably safe" content."""
    if isinstance(alert, dict):
        return {k: _sanitize_alert(v) for k, v in alert.items()}
    if isinstance(alert, list):
        return [_sanitize_alert(v) for v in alert]
    if isinstance(alert, str):
        return san.sanitize_text(alert, html_escape=False)
    return alert


def migrate_one(golden: dict) -> dict:
    gt = golden.get("ground_truth") or {}
    must_not_auto_contain = bool(gt.get("must_not_auto_block", True))  # fail-closed default: True
    case_uid = golden["id"]

    sanitized_alert = _sanitize_alert(golden.get("alert") or {})
    observables = agent_bench.synth_observables(golden.get("alert") or {})

    notes = [
        "Migrated from the pre-Phase-7 golden-seven set (ai/testset/*.json) as a DRAFT record.",
        "Legacy ground_truth (is_false_positive/severity/mitre_technique/must_not_auto_block/"
        "rationale) preserved verbatim under the 'ground_truth' key.",
        "event_time was not recorded in the original source — set to null; this case cannot be "
        "approved until an event_time is established (required for temporal RAG rules).",
        "fixtures are empty — no frozen verdict/trace/tool-call fixtures exist yet for this case; "
        "it is NOT replay-ready until fixtures are captured (out of scope for Phase 7A).",
    ]

    expected_tier = None
    forbidden_reason_codes = []
    if must_not_auto_contain:
        # Directly and safely derivable from the human-authored SAFETY LABEL
        # itself (must_not_auto_block), not from the policy under
        # evaluation's internal logic — this case must never be expected to
        # reach an auto-contained L1 close.
        expected_tier = "L2"
        forbidden_reason_codes = [l1_policy.Reason.L1_TRUE_POSITIVE_CONTAINED]
        notes.append("expected_tier set to L2 — directly implied by the original "
                     "must_not_auto_block=True safety label, not derived from policy internals.")
    else:
        notes.append("expected_tier left null — must_not_auto_block=False alone does not "
                     "establish whether this specific case clears every L1 eligibility gate "
                     "(rule allowlist, corroboration, tool usage, etc.); requires human review.")

    return {
        "schema_version": ds.SCHEMA_VERSION,
        "case_uid": case_uid,
        "incident_group_id": f"group-{case_uid}",
        "event_time": None,
        "source": golden.get("source", "unknown"),
        "alert": sanitized_alert,
        "observables": observables,
        "fixtures": {},
        "rag_snapshot_ref": None,
        "dataset_version": DATASET_VERSION,
        "policy_version_frozen_against": l1_policy.POLICY_VERSION,
        "label_source": "human_hand_labeled",
        "label_confidence": "high",
        "review_status": "pending",
        "reviewed_by": None,
        "reviewed_at": None,
        "label_notes": " ".join(notes),
        "expected_tier": expected_tier,
        "expected_primary_reason": None,
        "required_reason_codes": [],
        "forbidden_reason_codes": forbidden_reason_codes,
        "must_not_auto_contain": must_not_auto_contain,
        "must_remain_open": True,
        # Legacy fields, preserved for human readability / backward compat:
        "id": golden.get("id"),
        "note": golden.get("note"),
        "ground_truth": gt,
    }


def main():
    source_files = sorted(glob.glob(os.path.join(SOURCE_DIR, "*.json")))
    if not source_files:
        sys.exit(f"no golden-set files found under {SOURCE_DIR}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    migrated = []
    for path in source_files:
        with open(path, encoding="utf-8") as fh:
            golden = json.load(fh)
        record = migrate_one(golden)

        errors = ds.validate_case(record)
        if errors:
            sys.exit(f"migrated record for {golden.get('id')!r} FAILED schema validation: {errors}")

        serialized = ds.canonical_json(record)
        if san.contains_unredacted_secret(serialized):
            sys.exit(f"secret-scan FAILED for {golden.get('id')!r} — refusing to write. "
                     f"This should be structurally impossible for the golden seven; "
                     f"investigate before re-running.")

        out_path = os.path.join(OUTPUT_DIR, f"{record['case_uid']}.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2, sort_keys=True)
            fh.write("\n")
        migrated.append(record)
        print(f"  migrated {golden['id']} -> {out_path}  "
             f"(expected_tier={record['expected_tier']!r}, review_status=pending)")

    print(f"\n{len(migrated)} draft records written to {OUTPUT_DIR}")
    pending_review = [m["case_uid"] for m in migrated]
    print(f"ALL {len(pending_review)} cases require human review before dataset lock: {pending_review}")
    return migrated


if __name__ == "__main__":
    main()
