#!/usr/bin/env python3
"""
Phase 7D — CORRECTED reviewer assignment. Replaces the Phase 7C dual-review
policy, which was withdrawn: the old criteria ("every proposed L1-eligible
case" OR "every must_not_auto_contain case") were complementary over one
boolean field and put 100% of the sample in dual review. See
L1-L2-SAFETY-AUDIT.md Phase 7C §5 for the original finding.

Narrowed policy (every case gets exactly one PRIMARY reviewer; dual/
secondary review is added for):
  1. every historical `Other` disposition (STATIC — known in advance,
     included in the initial assignment below);
  2. a deterministic, stratified, 12-case quality-control sample, balanced
     across TruePositive/FalsePositive, severity, and rule family (STATIC,
     included below);
  3. every case actually PROPOSED as L1-eligible by a reviewer (i.e. a
     primary reviewer's own decision sets `expected_tier: "L1"`) and every
     case a reviewer marks `disputed` — both are DYNAMIC, only knowable
     once review decisions exist, and are computed live by
     `review_dataset.py`'s `effective_queue()` from the overlay files, NOT
     baked into this script's static output. See the note below for why a
     static proxy for "proposed L1-eligible" was tried and rejected.

`must_not_auto_contain` ALONE no longer triggers dual review (withdrawn,
per Phase 7C's finding).

REJECTED DESIGN (documented, not silently dropped): an earlier draft of
this script computed "proposed L1-eligible" as a STATIC pre-review proxy —
historical disposition TruePositive AND not already must_not_auto_contain.
Running it against the real 60-case sample put 46 of 60 cases in that
bucket alone (most historically-closed SOC cases in this dataset ARE
TruePositive), pushing dual review to 58/60 — in practice almost as total
as the withdrawn 100% policy, even though the LOGIC was no longer a
tautology. "Proposed" more naturally reads as an event a REVIEWER causes
(by actually proposing L1 during their own review), not a guess made in
advance from the historical label alone — especially since Dataset B
currently has zero cases with populated fixtures, so no case can honestly
be proposed L1 today anyway (see Phase 7D §3). Moving this criterion to a
dynamic, decision-triggered check fixes both the false pre-review positive
rate AND better matches the word "proposed" in the instruction.

Operates ONLY on already-written candidate files and a sample manifest. No
network call, no candidate file modified. Reviewer identifiers are neutral
("reviewer-a"/"reviewer-b") — never a real name or email.

Sample source: prefers the Phase 7D v2 export (`ai/testset/
dataset_b_candidates_v2/REVIEW_SAMPLE_MANIFEST.json`, authoritative
structured disposition) if it exists; FALLS BACK to the Phase 7C v1-schema
sample (`ai/testset/dataset_b_candidates/REVIEW_SAMPLE_v2_MANIFEST.json`,
prose-hint disposition) with an explicit, printed warning if the v2 export
has not been run yet (e.g. blocked on THEHIVE_API_KEY not being available in
this environment — see the Phase 7D stop-and-report). Re-running this script
after the v2 export completes will automatically pick up the authoritative
sample with no code change.
"""
import json
import os
import random
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dataset_schema as ds

_HERE = os.path.dirname(os.path.abspath(__file__))
V1_CANDIDATES_DIR = os.path.join(_HERE, "..", "ai", "testset", "dataset_b_candidates")
V2_CANDIDATES_DIR = os.path.join(_HERE, "..", "ai", "testset", "dataset_b_candidates_v2")
OVERLAY_DIR = os.path.join(_HERE, "review_overlays")

REVIEWER_A = "reviewer-a"
REVIEWER_B = "reviewer-b"
ASSIGNMENT_SEED = 20260821       # frozen — same family as the sample-selection seed
QC_SAMPLE_SEED = 20260822        # frozen, DISTINCT from ASSIGNMENT_SEED/REVIEW_SUBSET_SEED
QC_SAMPLE_SIZE = 12


def load_sample():
    """Returns (candidates_dir, sample_source_label, by_uid, dispositions).
    `dispositions` uses the AUTHORITATIVE structured field for a v2 sample,
    the non-authoritative prose hint (clearly labeled) for a v1 fallback."""
    v2_sample_path = os.path.join(V2_CANDIDATES_DIR, "REVIEW_SAMPLE_MANIFEST.json")
    if os.path.exists(v2_sample_path):
        manifest = json.load(open(v2_sample_path, encoding="utf-8"))
        by_uid = {}
        for uid in manifest["case_uids"]:
            by_uid[uid] = json.load(open(os.path.join(V2_CANDIDATES_DIR, f"{uid}.json"), encoding="utf-8"))
        dispositions = {uid: ds.get_authoritative_historical_disposition(c) for uid, c in by_uid.items()}
        return V2_CANDIDATES_DIR, "phase7d_v2_authoritative", by_uid, dispositions

    print("WARNING: Phase 7D v2 sample not found (the live v2 export has not been run yet — "
         "see the Phase 7D stop-and-report for why). Falling back to the Phase 7C v1-schema "
         "sample (prose-hint disposition, NOT authoritative). Re-run this script after the v2 "
         "export completes to pick up the authoritative sample automatically.")
    v1_sample_path = os.path.join(V1_CANDIDATES_DIR, "REVIEW_SAMPLE_v2_MANIFEST.json")
    manifest = json.load(open(v1_sample_path, encoding="utf-8"))
    by_uid = {}
    for uid in manifest["case_uids"]:
        by_uid[uid] = json.load(open(os.path.join(V1_CANDIDATES_DIR, f"{uid}.json"), encoding="utf-8"))
    dispositions = {uid: ds.extract_historical_disposition_hint(c) for uid, c in by_uid.items()}
    return V1_CANDIDATES_DIR, "phase7c_v1_fallback_prose_hint", by_uid, dispositions


def _rule_family_bucket(case: dict) -> str:
    title = str((case.get("alert") or {}).get("title") or "").strip().lower()
    words = title.split()[:2]
    return "-".join(words) if words else "unknown"


def select_qc_sample(by_uid: dict, dispositions: dict, *, n: int = QC_SAMPLE_SIZE,
                     seed: int = QC_SAMPLE_SEED) -> list:
    """
    Deterministic, seeded, stratified quality-control sample — balanced
    across (historical disposition restricted to TruePositive/FalsePositive,
    severity, rule-family bucket). Sorts by case_uid FIRST (same order-
    independence fix as select_review_subset_v2 in Phase 7C) so the result
    is reproducible regardless of dict/caller iteration order.
    """
    eligible = [uid for uid, d in dispositions.items() if d in ("TruePositive", "FalsePositive")]
    eligible.sort()

    def stratum_key(uid):
        case = by_uid[uid]
        sev = (case.get("alert") or {}).get("severity")
        return (dispositions[uid], sev, _rule_family_bucket(case))

    strata = defaultdict(list)
    for uid in eligible:
        strata[stratum_key(uid)].append(uid)

    rng = random.Random(seed)
    selected = []
    selected_set = set()
    for key, members in sorted(strata.items(), key=lambda kv: str(kv[0])):
        members = list(members)
        rng.shuffle(members)
        if members:
            selected.append(members[0])
            selected_set.add(members[0])

    remaining = [uid for uid in eligible if uid not in selected_set]
    rng.shuffle(remaining)
    for uid in remaining:
        if len(selected) >= n:
            break
        selected.append(uid)
        selected_set.add(uid)

    return selected[:n]


def compute_dual_review(by_uid: dict, dispositions: dict) -> dict:
    """
    Returns {case_uid: [reason, ...]} for every case needing a SECOND
    reviewer under the STATIC portion of the corrected Phase 7D policy —
    the two criteria knowable BEFORE any review happens: historical `Other`
    disposition, and the fixed 12-case QC sample. The other two criteria
    ("proposed L1-eligible", "disputed") are DYNAMIC — see the module
    docstring and `review_dataset.effective_queue()` — and are deliberately
    NOT computed here, since they depend on review decisions that don't
    exist yet at assignment time.
    """
    dual = {}
    for uid, case in by_uid.items():
        if dispositions.get(uid) == "Other":
            dual.setdefault(uid, []).append("historical_other_disposition")

    qc_sample = select_qc_sample(by_uid, dispositions)
    for uid in qc_sample:
        dual.setdefault(uid, []).append("quality_control_sample")

    return dual


def main():
    candidates_dir, sample_source, by_uid, dispositions = load_sample()
    uids = sorted(by_uid.keys())  # stable, content-independent order

    rng = random.Random(ASSIGNMENT_SEED)
    shuffled = list(uids)
    rng.shuffle(shuffled)
    half = len(shuffled) // 2
    primary = {uid: REVIEWER_A for uid in shuffled[:half]}
    primary.update({uid: REVIEWER_B for uid in shuffled[half:]})

    dual_review = compute_dual_review(by_uid, dispositions)

    queues = {REVIEWER_A: [], REVIEWER_B: []}
    for uid in uids:
        queues[primary[uid]].append(uid)
        if uid in dual_review:
            other = REVIEWER_B if primary[uid] == REVIEWER_A else REVIEWER_A
            queues[other].append(uid)

    assignment = {
        "policy": "phase7d_narrowed_dual_review",
        "sample_source": sample_source,
        "candidates_dir": candidates_dir,
        "seed": ASSIGNMENT_SEED,
        "qc_sample_seed": QC_SAMPLE_SEED,
        "total_cases": len(uids),
        "primary_assignment": primary,
        "dual_review": dual_review,
        "dual_review_reason_counts": dict(Counter(r for rs in dual_review.values() for r in rs)),
        "queue_sizes": {r: len(q) for r, q in queues.items()},
        "primary_counts": {REVIEWER_A: sum(1 for v in primary.values() if v == REVIEWER_A),
                          REVIEWER_B: sum(1 for v in primary.values() if v == REVIEWER_B)},
        "dual_review_count": len(dual_review),
        "queues": queues,
    }

    os.makedirs(OVERLAY_DIR, exist_ok=True)
    path = os.path.join(OVERLAY_DIR, "ASSIGNMENTS_v2.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(assignment, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print(f"sample_source: {sample_source}")
    print(f"total cases: {len(uids)}")
    print(f"primary counts: {assignment['primary_counts']}")
    print(f"dual review count: {len(dual_review)}")
    print(f"dual review reason breakdown: {assignment['dual_review_reason_counts']}")
    print(f"queue sizes: {assignment['queue_sizes']}")
    print(f"assignments written: {path}")
    return assignment


if __name__ == "__main__":
    main()
