#!/usr/bin/env python3
"""
Phase 7C/7D — offline, resumable human-review CLI for Dataset A (synthetic,
specification-derived) and Dataset B (historical, TheHive-sourced) cases.

Operates ONLY on already-sanitized candidate files. NEVER connects to a
network (wrapped in replay_harness.network_guard() for the whole review
session). NEVER rewrites an original candidate file — every decision is
appended to a per-reviewer, append-only overlay file under
soar/review_overlays/.

This tool does NOT generate or recommend an expected label using the
policy under evaluation — evaluate_positive_gate_checklist() (see
review_rubric.py) is policy-INDEPENDENT: generic, objective evidence facts
only, never a reproduction of l1_policy.py's actual gates. That would be
circular ground truth.

Phase 7D changes:
  - `--dataset {a,b}` selects which candidate population to review — no
    more single implicit target.
  - Dataset B prefers the schema-v2, authoritative-disposition export
    (`ai/testset/dataset_b_candidates_v2/`) when it exists, falling back to
    the Phase 7C v1/prose-hint export with an explicit warning otherwise —
    the prose extractor is NEVER used as an authoritative source on this
    path, only as a clearly-labeled non-authoritative display aid for v1
    records (see dataset_schema.get_authoritative_historical_disposition()).
  - Fixture provenance (synthetic / historical / missing) is now shown
    explicitly for every case.
  - The corrected, narrowed dual-review policy (assign_reviewers.py) is
    supported via `effective_queue()`, which layers two DYNAMIC triggers
    (a case actually proposed L1 by one reviewer, or marked disputed) on
    top of the static assignment file — see assign_reviewers.py's module
    docstring for why these two are dynamic rather than pre-computed.

Usage (interactive, run by a human reviewer — NOT by this session):
    ./.venv/bin/python review_dataset.py --dataset b --reviewer reviewer-a
    ./.venv/bin/python review_dataset.py --dataset b --reviewer reviewer-a --progress
    ./.venv/bin/python review_dataset.py --dataset b --conflicts
    ./.venv/bin/python review_dataset.py --dataset a --reviewer reviewer-a
"""
import argparse
import glob
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dataset_schema as ds
import rag_snapshot as rs
import replay_harness as rh
import review_rubric as rr
import sanitization as san

_HERE = os.path.dirname(os.path.abspath(__file__))
DATASET_B_V1_DIR = os.path.join(_HERE, "..", "ai", "testset", "dataset_b_candidates")
DATASET_B_V2_DIR = os.path.join(_HERE, "..", "ai", "testset", "dataset_b_candidates_v2")
DATASET_A_DIR = os.path.join(_HERE, "..", "ai", "testset", "dataset_a_synthetic")
OVERLAY_DIR = os.path.join(_HERE, "review_overlays")
ASSIGNMENTS_PATH_B = os.path.join(OVERLAY_DIR, "ASSIGNMENTS_v2.json")

# Backward-compat aliases (Phase 7C-era default target) — several pure
# functions below still accept an explicit candidates_dir/overlay_dir and
# default to these when a caller doesn't pass one; resolve_dataset() is the
# Phase 7D-correct way to pick a target and should be preferred by new code.
CANDIDATES_DIR = DATASET_B_V1_DIR
ASSIGNMENTS_PATH = ASSIGNMENTS_PATH_B


def resolve_dataset(dataset: str):
    """
    Returns (candidates_dir, sample_manifest_path_or_None,
    requires_fixtures_for_l1: bool, label: str) for "a" or "b".

    Dataset B prefers the v2 (authoritative-disposition) export if its
    MANIFEST.json exists, else falls back to v1 with a printed warning —
    same fallback rule as assign_reviewers.load_sample(), kept consistent
    deliberately so both tools agree on which population is "live".
    """
    if dataset == "a":
        return DATASET_A_DIR, None, False, "dataset_a_synthetic"
    if dataset == "b":
        if os.path.exists(os.path.join(DATASET_B_V2_DIR, "MANIFEST.json")):
            sample_path = os.path.join(DATASET_B_V2_DIR, "REVIEW_SAMPLE_MANIFEST.json")
            return DATASET_B_V2_DIR, sample_path, True, "dataset_b_v2_authoritative"
        print("WARNING: Dataset B v2 export not found — falling back to the Phase 7C v1 "
             "export (prose-hint disposition, NOT authoritative). See the Phase 7D "
             "stop-and-report for why.", file=sys.stderr)
        sample_path = os.path.join(DATASET_B_V1_DIR, "REVIEW_SAMPLE_v2_MANIFEST.json")
        return DATASET_B_V1_DIR, sample_path, True, "dataset_b_v1_fallback"
    raise ValueError(f"unknown dataset {dataset!r} — must be 'a' or 'b'")


# ==============================================================================
# Pure / testable core — no interactive input(), no CLI parsing
# ==============================================================================

def load_and_verify_candidates(candidates_dir: str = CANDIDATES_DIR) -> dict:
    """Loads every candidate + the manifest, INDEPENDENTLY re-verifies the
    manifest against the loaded content (hash + structural checks) before
    returning anything. Raises RuntimeError (never returns a dict) if
    verification fails — reviewing against a possibly-tampered set is
    refused outright, not merely warned about."""
    import glob
    files = sorted(f for f in glob.glob(os.path.join(candidates_dir, "*.json"))
                   if not os.path.basename(f).startswith(("MANIFEST", "REVIEW_SAMPLE")))
    cases = [json.load(open(f, encoding="utf-8")) for f in files]
    manifest = json.load(open(os.path.join(candidates_dir, "MANIFEST.json"), encoding="utf-8"))
    errors = rs.verify_manifest(manifest, cases)
    if errors:
        raise RuntimeError(f"candidate set verification FAILED — refusing to review: {errors}")
    return {c["case_uid"]: c for c in cases}


def load_sample_manifest(candidates_dir: str = CANDIDATES_DIR, version: int = 2,
                         path: str = None) -> dict:
    """`path`, if given, is used verbatim (Phase 7D — resolve_dataset()
    returns the correct path for whichever dataset/version is live).
    Falls back to the Phase 7C v{version}-suffixed naming under
    `candidates_dir` for backward compatibility when `path` is omitted."""
    if path is None:
        path = os.path.join(candidates_dir, f"REVIEW_SAMPLE_v{version}_MANIFEST.json")
    manifest = json.load(open(path, encoding="utf-8"))
    return manifest


def verify_sample_against_candidates(sample_manifest: dict, by_uid: dict) -> list:
    """Independently re-checks every case_content_hash in the sample
    manifest against the CURRENTLY loaded candidate content."""
    errors = []
    for uid, expected_hash in sample_manifest["case_content_hashes"].items():
        if uid not in by_uid:
            errors.append(f"sample references {uid!r} which is not in the candidate set")
            continue
        actual = ds.case_content_hash(by_uid[uid])
        if actual != expected_hash:
            errors.append(f"content_hash mismatch for {uid!r} in the review sample")
    return errors


def load_assignments(path: str = ASSIGNMENTS_PATH) -> dict:
    return json.load(open(path, encoding="utf-8"))


def _overlay_path(reviewer_id: str, overlay_dir: str = OVERLAY_DIR) -> str:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in reviewer_id)
    return os.path.join(overlay_dir, f"{safe}.jsonl")


def atomic_append_jsonl(path: str, record: dict) -> None:
    """POSIX-atomic append of ONE JSON line. os.O_APPEND writes are atomic
    for writes not exceeding PIPE_BUF (4096 bytes on Linux) on the same
    filesystem — comfortably true for one decision record. Never truncates,
    never rewrites existing content; the file is genuinely append-only."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    line = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
    if len(line) > 4096:
        # Should be structurally impossible (label_notes is bounded free
        # text) — fail loudly rather than silently risk a torn write.
        raise ValueError(f"decision record too large for an atomic append ({len(line)} bytes)")
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o644)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def read_overlay(reviewer_id: str, overlay_dir: str = OVERLAY_DIR) -> dict:
    """Reads a reviewer's overlay file, returns {case_uid: latest_decision}
    — the LAST line for a given case_uid wins, allowing revision by simply
    appending a new decision. Tolerates a missing file (no decisions yet)."""
    path = _overlay_path(reviewer_id, overlay_dir)
    latest = {}
    if not os.path.exists(path):
        return latest
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            latest[rec["case_uid"]] = rec
    return latest


def fixture_provenance(case: dict) -> str:
    """
    Classifies a case's fixtures as one of "synthetic" / "historical" /
    "independently_recorded" / "missing" — shown explicitly to reviewers so
    they never mistake a frozen synthetic fixture for a real historical one
    or vice versa. Dataset A's builder tags every fixtures dict with
    `_provenance` (see build_dataset_a_synthetic_fixtures.py); a case with
    no fixtures at all (every current Dataset B candidate) is "missing" —
    never silently treated as "not applicable".
    """
    fixtures = case.get("fixtures") or {}
    if not fixtures:
        return "missing"
    tag = fixtures.get("_provenance")
    if tag in ("synthetic", "historical", "independently_recorded"):
        return tag
    return "unmarked"  # a fixtures dict exists but wasn't tagged — flagged, not hidden


def historical_disposition_display(case: dict) -> dict:
    """
    Returns {"authoritative": str|None, "non_authoritative_hint": str|None}.
    `authoritative` is EVER populated only via
    dataset_schema.get_authoritative_historical_disposition() (schema v2's
    structured field) — the prose extractor never appears under that key.
    `non_authoritative_hint` is populated ONLY for v1 records, from the
    prose extractor, and is always paired with an explicit "not
    authoritative" label wherever it's displayed — see
    format_case_for_display().
    """
    authoritative = ds.get_authoritative_historical_disposition(case)
    hint = None
    if case.get("schema_version") != ds.SCHEMA_VERSION_V2:
        hint = ds.extract_historical_disposition_hint(case)
    return {"authoritative": authoritative, "non_authoritative_hint": hint}


def record_decision(reviewer_id: str, case: dict, decision: dict, *, overlay_dir: str = OVERLAY_DIR,
                    dataset: str = None) -> dict:
    """
    Validates `decision` against the rubric (review_rubric.validate_decision)
    — REFUSES (raises ValueError) to save an invalid decision, never saves
    a partial/invalid record. On success, appends one atomic line to the
    reviewer's overlay file and returns the full saved record (including
    computed metadata: decided_at, the checklist snapshot).

    `dataset`, if given ("a"/"b"), adds an EXPLICIT, dataset-aware refusal
    for "approve Dataset B as L1 with missing fixtures" — functionally this
    duplicates review_rubric.validate_decision()'s own generic evidence gate
    (every current Dataset B candidate has fixture_provenance()=="missing",
    so that gate already refuses it), but the Phase 7D instruction asks for
    this explicitly and by name, so it is also checked directly here with
    an unambiguous message rather than relying only on the generic gate's
    wording.
    """
    decision = dict(decision)
    decision["reviewer_id"] = reviewer_id
    decision.setdefault("required_reason_codes", [])
    decision.setdefault("forbidden_reason_codes", [])

    if (dataset == "b" and decision.get("review_status") == "approved"
            and decision.get("expected_tier") == "L1" and fixture_provenance(case) == "missing"):
        raise ValueError("decision rejected: Dataset B case has NO investigation fixtures — "
                         "cannot be approved as L1 (Dataset B currently evaluates L2 escalation, "
                         "false-auto-containment prevention, and TruePositive/FalsePositive "
                         "handling, NOT positive L1 automation — see DATASET_B_SCOPE.md)")

    errors = rr.validate_decision(case, decision)
    if errors:
        raise ValueError(f"decision rejected by the review rubric: {errors}")

    if san.contains_unredacted_secret(ds.canonical_json(decision)):
        raise ValueError("decision record appears to contain an unredacted secret — refusing to save")

    record = {
        "case_uid": case["case_uid"],
        "case_content_hash": ds.case_content_hash(case),
        "reviewer_id": reviewer_id,
        "review_status": decision["review_status"],
        "expected_tier": decision.get("expected_tier"),
        "expected_primary_reason": decision.get("expected_primary_reason"),
        "required_reason_codes": decision.get("required_reason_codes", []),
        "forbidden_reason_codes": decision.get("forbidden_reason_codes", []),
        "label_confidence": decision["label_confidence"],
        "label_notes": decision.get("label_notes", ""),
        "rubric_checklist": rr.evaluate_positive_gate_checklist(case),
        "fixture_provenance": fixture_provenance(case),
        "decided_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_append_jsonl(_overlay_path(reviewer_id, overlay_dir), record)
    return record


def compute_progress(reviewer_id: str, queue: list, overlay_dir: str = OVERLAY_DIR) -> dict:
    decided = read_overlay(reviewer_id, overlay_dir)
    done = [uid for uid in queue if uid in decided]
    remaining = [uid for uid in queue if uid not in decided]
    status_counts = {}
    for uid in done:
        st = decided[uid]["review_status"]
        status_counts[st] = status_counts.get(st, 0) + 1
    return {"reviewer_id": reviewer_id, "queue_size": len(queue), "done": len(done),
           "remaining": len(remaining), "remaining_case_uids": remaining,
           "status_counts": status_counts}


def effective_queue(reviewer_id: str, assignments: dict, overlay_dir: str = OVERLAY_DIR) -> list:
    """
    Phase 7D — the reviewer's REAL queue: the static assignment (primary +
    the two pre-computable dual-review criteria, see assign_reviewers.py)
    PLUS two dynamic escalations layered on top, computed live from the
    OTHER reviewer(s)' overlay decisions:
      - a case the other reviewer actually proposed L1-eligible for
        (review_status="approved", expected_tier="L1");
      - a case the other reviewer marked `disputed`.
    Both are added to THIS reviewer's queue the moment they're observed, so
    a second opinion is always sought — this is what makes "every case
    proposed as L1-eligible" and "every disputed case" real guarantees
    without requiring a policy replay or a re-run of assign_reviewers.py.
    """
    queue = list(assignments["queues"].get(reviewer_id, []))
    queue_set = set(queue)
    all_reviewers = sorted(assignments["queues"].keys())
    for other in all_reviewers:
        if other == reviewer_id:
            continue
        for uid, rec in read_overlay(other, overlay_dir).items():
            proposed_l1 = rec.get("review_status") == "approved" and rec.get("expected_tier") == "L1"
            disputed = rec.get("review_status") == "disputed"
            if (proposed_l1 or disputed) and uid not in queue_set:
                queue.append(uid)
                queue_set.add(uid)
    return queue


def compute_conflicts(assignments: dict, overlay_dir: str = OVERLAY_DIR) -> list:
    """
    For every case_uid that TWO OR MORE reviewers have actually decided —
    whether it was in the static dual_review set, or reached a second
    reviewer only via the dynamic escalation in effective_queue() — compare
    their LATEST decisions. Returns a list of conflict dicts; empty means no
    disagreement among reviewers who have both decided. Checking every
    case with 2+ decisions (not just the statically-flagged ones) is
    deliberate: a dynamically dual-reviewed case must be just as eligible
    for adjudication as a statically-flagged one.
    """
    dual = assignments.get("dual_review", {})
    all_reviewers = sorted(assignments["queues"].keys())
    overlays = {r: read_overlay(r, overlay_dir) for r in all_reviewers}

    decided_by = {}
    for r, overlay in overlays.items():
        for uid in overlay:
            decided_by.setdefault(uid, []).append(r)

    conflicts = []
    for uid, reviewers_who_decided in sorted(decided_by.items()):
        if len(reviewers_who_decided) < 2:
            continue
        decisions = {r: overlays[r][uid] for r in reviewers_who_decided}
        statuses = {r: d["review_status"] for r, d in decisions.items()}
        tiers = {r: d["expected_tier"] for r, d in decisions.items()}
        if len(set(statuses.values())) > 1 or len(set(tiers.values())) > 1:
            conflicts.append({"case_uid": uid, "statuses": statuses, "tiers": tiers,
                             "dual_review_reasons": dual.get(uid, ["dynamic_escalation"])})
    return conflicts


def write_adjudication_queue(conflicts: list, overlay_dir: str = OVERLAY_DIR) -> str:
    path = os.path.join(overlay_dir, "ADJUDICATION_QUEUE.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(),
                  "conflict_count": len(conflicts), "conflicts": conflicts}, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def format_case_for_display(case: dict) -> str:
    """Sanitized, human-readable case rendering for the CLI — every field
    shown here already passed through sanitization at export time; this
    function adds NO new content, only formatting."""
    checklist = rr.evaluate_positive_gate_checklist(case)
    disposition = historical_disposition_display(case)
    provenance = fixture_provenance(case)
    obs_lines = "\n".join(
        f"    - {o.get('dataType')}={o.get('data')} tags={o.get('tags')}"
        for o in (case.get("observables") or [])) or "    (none)"
    disposition_line = (f"historical disposition (AUTHORITATIVE, schema v2): {disposition['authoritative']!r}"
                        if disposition["authoritative"] is not None else
                        f"[EVIDENCE ONLY, NOT AUTHORITATIVE — schema v1 prose hint] "
                        f"historical disposition: {disposition['non_authoritative_hint']!r}")
    lines = [
        f"case_uid: {case['case_uid']}   incident_group_id: {case['incident_group_id']}   "
        f"schema_version: {case.get('schema_version')}",
        f"severity: {(case.get('alert') or {}).get('severity')}   "
        f"event_time: {case.get('event_time')}   closure_time: {case.get('closure_time')}",
        f"title: {(case.get('alert') or {}).get('title')}",
        f"description: {(case.get('alert') or {}).get('description')}",
        "observables:",
        obs_lines,
        f"fixtures present: {bool(case.get('fixtures'))}   fixture_provenance: {provenance.upper()}",
        "",
        disposition_line,
        f"draft must_not_auto_contain (from the historical FalsePositive signal only): "
        f"{case.get('must_not_auto_contain')}",
        "",
        "policy-INDEPENDENT positive-gate checklist (objective facts only — NOT a",
        "reproduction of the policy under evaluation):",
    ]
    for k, v in checklist.items():
        lines.append(f"  [{'x' if v else ' '}] {k}")
    lines += [
        "",
        f"externally-evaluable reason codes available: {sorted(rr.EXTERNALLY_EVALUABLE_REASON_CODES)}",
    ]
    return "\n".join(lines)


# ==============================================================================
# Interactive CLI — thin, calls only the pure functions above
# ==============================================================================

def _prompt(msg, default=None):
    suffix = f" [{default}]" if default is not None else ""
    val = input(f"{msg}{suffix}: ").strip()
    return val or default


def run_review_session(dataset: str, reviewer_id: str):
    candidates_dir, sample_path, requires_fixtures, label = resolve_dataset(dataset)
    by_uid = load_and_verify_candidates(candidates_dir)

    if sample_path is not None:
        sample_manifest = load_sample_manifest(path=sample_path)
        sample_errors = verify_sample_against_candidates(sample_manifest, by_uid)
        if sample_errors:
            sys.exit(f"REFUSING TO REVIEW — sample verification failed: {sample_errors}")
        queue_universe = set(sample_manifest["case_uids"])
    else:
        queue_universe = set(by_uid.keys())  # Dataset A: no sub-sample, review everything

    if dataset == "b":
        assignments = load_assignments(ASSIGNMENTS_PATH_B)
        if reviewer_id not in assignments["queues"]:
            sys.exit(f"unknown reviewer_id {reviewer_id!r} — not in {ASSIGNMENTS_PATH_B}")
        queue = [uid for uid in effective_queue(reviewer_id, assignments) if uid in queue_universe]
    else:
        queue = sorted(queue_universe)  # Dataset A: single shared queue, no split/dual-review

    progress = compute_progress(reviewer_id, queue)
    print(f"Dataset: {label}   Reviewer: {reviewer_id}   Progress: {progress['done']}/"
         f"{progress['queue_size']} done, {progress['remaining']} remaining")

    for case_uid in progress["remaining_case_uids"]:
        case = by_uid[case_uid]
        print("\n" + "=" * 70)
        print(format_case_for_display(case))
        print("=" * 70)

        status = _prompt("review_status (approved/disputed/excluded)")
        tier = _prompt("expected_tier (L1/L2/none)", "L2")
        tier = None if tier and tier.lower() == "none" else tier
        primary = _prompt("expected_primary_reason (or blank)") or None
        required = [c.strip() for c in (_prompt("required_reason_codes, comma-separated (or blank)") or "").split(",") if c.strip()]
        forbidden = [c.strip() for c in (_prompt("forbidden_reason_codes, comma-separated (or blank)") or "").split(",") if c.strip()]
        confidence = _prompt("label_confidence (high/medium/low)")
        notes = _prompt("label_notes (or blank)") or ""

        decision = {"review_status": status, "expected_tier": tier, "expected_primary_reason": primary,
                   "required_reason_codes": required, "forbidden_reason_codes": forbidden,
                   "label_confidence": confidence, "label_notes": notes}
        try:
            saved = record_decision(reviewer_id, case, decision, dataset=dataset)
            print(f"SAVED: {case_uid} -> {saved['review_status']} / {saved['expected_tier']}")
        except ValueError as exc:
            print(f"REJECTED (not saved) — fix and this case will be re-prompted next run: {exc}")


def main():
    parser = argparse.ArgumentParser(description="Phase 7C/7D offline Dataset A/B review CLI")
    parser.add_argument("--dataset", choices=["a", "b"], help="which candidate population to review")
    parser.add_argument("--reviewer", help="reviewer identifier, e.g. reviewer-a")
    parser.add_argument("--progress", action="store_true", help="show progress only, no review session")
    parser.add_argument("--conflicts", action="store_true",
                        help="compute and write the Dataset B adjudication queue")
    args = parser.parse_args()

    with rh.network_guard():
        if args.conflicts:
            assignments = load_assignments(ASSIGNMENTS_PATH_B)
            conflicts = compute_conflicts(assignments)
            path = write_adjudication_queue(conflicts)
            print(f"{len(conflicts)} conflict(s) written to {path}")
            return

        if not args.dataset:
            sys.exit("--dataset {a,b} is required (or use --conflicts)")
        if not args.reviewer:
            sys.exit("--reviewer is required (or use --conflicts)")

        if args.progress:
            candidates_dir, sample_path, _, _ = resolve_dataset(args.dataset)
            if args.dataset == "b":
                assignments = load_assignments(ASSIGNMENTS_PATH_B)
                queue = effective_queue(args.reviewer, assignments)
            else:
                queue = sorted(load_and_verify_candidates(candidates_dir).keys())
            print(json.dumps(compute_progress(args.reviewer, queue), indent=2))
            return

        run_review_session(args.dataset, args.reviewer)


if __name__ == "__main__":
    main()
