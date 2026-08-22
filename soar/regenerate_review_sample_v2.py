#!/usr/bin/env python3
"""
Phase 7C — regenerate the deterministic review sample as v2 (incident-group
capped), preserving v1 unchanged. Reads ONLY the already-written, already-
sanitized candidate files on disk — makes NO network call, modifies NONE of
the 226 candidate JSON records.
"""
import glob
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dataset_schema as ds
import export_dataset_b_candidates as edb
import rag_snapshot as rs
import sanitization as san

_HERE = os.path.dirname(os.path.abspath(__file__))
CANDIDATES_DIR = os.path.join(_HERE, "..", "ai", "testset", "dataset_b_candidates")
RESULTS_DIR = os.path.join(_HERE, "..", "ai", "results")


def load_candidates():
    files = sorted(glob.glob(os.path.join(CANDIDATES_DIR, "*.json")))
    files = [f for f in files if not f.endswith("MANIFEST.json")]
    cases = [json.load(open(f, encoding="utf-8")) for f in files]
    return cases


def verify_candidates_unchanged(cases):
    manifest = json.load(open(os.path.join(CANDIDATES_DIR, "MANIFEST.json"), encoding="utf-8"))
    errs = rs.verify_manifest(manifest, cases)
    return manifest, errs


def parse_v1_worksheet_uids():
    path = os.path.join(CANDIDATES_DIR, "REVIEW_SUBSET_WORKSHEET.md")
    text = open(path, encoding="utf-8").read()
    return sorted(set(re.findall(r"\| `(dsb-c-[0-9a-f]+)`", text)))


def build_sample_manifest(sample_version: int, case_uids: list, by_uid: dict, *, seed, target,
                          max_per_group=None, exception_max_per_group=None, exceptions=None):
    return {
        "sample_manifest_version": sample_version,
        "generated_from": "ai/testset/dataset_b_candidates/MANIFEST.json",
        "seed": seed,
        "target": target,
        "max_per_group": max_per_group,
        "exception_max_per_group": exception_max_per_group,
        "exceptions": exceptions or [],
        "sample_size": len(case_uids),
        "case_uids": case_uids,
        "case_content_hashes": {uid: ds.case_content_hash(by_uid[uid]) for uid in case_uids},
    }


def write_worksheet_to(path: str, subset: list, strata_report: dict, group_representation: dict,
                       exceptions: list):
    lines = [
        "# Dataset B — deterministic review subset v2 (Phase 7C, incident-group capped)",
        "",
        f"Generated with frozen seed `{edb.REVIEW_SUBSET_SEED}`, max 3 cases per "
        f"`incident_group_id` (documented exception up to 5 for a stratum that cannot "
        f"otherwise be represented) — corrects a Phase 7B finding where one 60-case "
        f"incident group could dominate the sample. Selection happened BEFORE any policy "
        f"replay was run against these candidates (none was run in this phase at all).",
        "",
        f"**{len(subset)} of {sum(strata_report.values())} eligible candidates selected.** "
        f"Every selected record remains `review_status: \"pending\"`.",
        "",
        "## Incident-group representation in this sample",
        "```",
        json.dumps(group_representation, indent=2),
        "```",
        "",
        "## Documented exceptions (stratum could not be represented within the base cap)",
        "```",
        json.dumps(exceptions, indent=2) if exceptions else "(none)",
        "```",
        "",
        "## Strata sizes (full eligible pool)",
        "```",
        json.dumps(strata_report, indent=2),
        "```",
        "",
        "## Selected case_uids (pseudonymous — no real case id/number appears here)",
        "",
        "| case_uid | must_not_auto_contain (draft) | severity | incident_group_id |",
        "|---|---|---|---|",
    ]
    for r in subset:
        lines.append(f"| `{r['case_uid']}` | {r['must_not_auto_contain']} | "
                     f"{(r.get('alert') or {}).get('severity')} | `{r['incident_group_id']}` |")
    lines += [
        "",
        "## Review instructions",
        "Same workflow as `ai/testset/dataset_a_draft/REVIEW_WORKSHEET.md` and "
        "`REVIEW_RUBRIC.md`. Each candidate's historical disposition "
        "(`label_source: \"human_historical_disposition\"`) is a CANDIDATE label, "
        "never automatic ground truth.",
    ]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main():
    print("=== VERIFY CANDIDATE SET UNCHANGED ===")
    cases = load_candidates()
    by_uid = {c["case_uid"]: c for c in cases}
    manifest, errs = verify_candidates_unchanged(cases)
    print(f"candidate count: {len(cases)}")
    print(f"manifest_hash: {manifest['manifest_hash']}")
    print(f"verification errors: {errs}")
    if errs:
        sys.exit("candidate set verification FAILED — aborting, refusing to build a sample "
                 "against a possibly-tampered set")

    dispositions = {c["case_uid"]: ds.extract_historical_disposition_hint(c) for c in cases}
    print(f"disposition hints recovered: {sum(1 for v in dispositions.values() if v)}/{len(cases)}")

    # ---- v1: the EXISTING worksheet's selection, preserved as-is, NOT recomputed ----
    print("\n=== PRESERVE v1 (from the existing worksheet, not recomputed) ===")
    v1_uids = parse_v1_worksheet_uids()
    print(f"v1 sample size (from worksheet): {len(v1_uids)}")
    v1_manifest = build_sample_manifest(1, v1_uids, by_uid, seed=edb.REVIEW_SUBSET_SEED, target=60)
    v1_path = os.path.join(CANDIDATES_DIR, "REVIEW_SAMPLE_v1_MANIFEST.json")
    with open(v1_path, "w", encoding="utf-8") as fh:
        json.dump(v1_manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"v1 sample manifest written: {v1_path}")

    # Also preserve the v1 worksheet under an explicit v1-labeled filename
    # (the original filename is left untouched too — belt and braces).
    v1_worksheet_src = os.path.join(CANDIDATES_DIR, "REVIEW_SUBSET_WORKSHEET.md")
    v1_worksheet_dst = os.path.join(CANDIDATES_DIR, "REVIEW_SUBSET_WORKSHEET_v1.md")
    with open(v1_worksheet_src, encoding="utf-8") as src, open(v1_worksheet_dst, "w", encoding="utf-8") as dst:
        dst.write(src.read())
    print(f"v1 worksheet preserved as: {v1_worksheet_dst}")

    # ---- v2: incident-group-capped, corrected selection ----
    print("\n=== GENERATE v2 (incident-group capped) ===")
    subset_v2, strata_v2, group_rep_v2, exceptions_v2 = edb.select_review_subset_v2(
        cases, dispositions, target=60, seed=edb.REVIEW_SUBSET_SEED,
        max_per_group=3, exception_max_per_group=5)
    v2_uids = sorted(r["case_uid"] for r in subset_v2)
    print(f"v2 sample size: {len(v2_uids)}")
    print(f"exceptions used: {len(exceptions_v2)}")

    largest_group_size_v2 = max(group_rep_v2.values()) if group_rep_v2 else 0
    largest_group_pct_v2 = round(100 * largest_group_size_v2 / len(v2_uids), 1) if v2_uids else 0.0

    v2_manifest = build_sample_manifest(2, v2_uids, by_uid, seed=edb.REVIEW_SUBSET_SEED, target=60,
                                        max_per_group=3, exception_max_per_group=5,
                                        exceptions=exceptions_v2)
    v2_path = os.path.join(CANDIDATES_DIR, "REVIEW_SAMPLE_v2_MANIFEST.json")
    with open(v2_path, "w", encoding="utf-8") as fh:
        json.dump(v2_manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"v2 sample manifest written: {v2_path}")

    # ---- v1 vs v2 largest-group comparison ----
    v1_group_counts = Counter(by_uid[uid]["incident_group_id"] for uid in v1_uids)
    largest_group_size_v1 = max(v1_group_counts.values()) if v1_group_counts else 0
    largest_group_pct_v1 = round(100 * largest_group_size_v1 / len(v1_uids), 1) if v1_uids else 0.0

    added = sorted(set(v2_uids) - set(v1_uids))
    removed = sorted(set(v1_uids) - set(v2_uids))
    unchanged = sorted(set(v1_uids) & set(v2_uids))

    disposition_dist_v2 = Counter(dispositions.get(uid) for uid in v2_uids)
    severity_dist_v2 = Counter((by_uid[uid].get("alert") or {}).get("severity") for uid in v2_uids)
    rule_family_dist_v2 = Counter(edb._rule_family_bucket(by_uid[uid]) for uid in v2_uids)

    comparison = {
        "v1_sample_size": len(v1_uids),
        "v2_sample_size": len(v2_uids),
        "v1_largest_group_size": largest_group_size_v1,
        "v1_largest_group_pct": largest_group_pct_v1,
        "v2_largest_group_size": largest_group_size_v2,
        "v2_largest_group_pct": largest_group_pct_v2,
        "v2_group_representation": group_rep_v2,
        "v2_exceptions": exceptions_v2,
        "cases_added_in_v2": added,
        "cases_removed_from_v1": removed,
        "cases_unchanged": unchanged,
        "v2_historical_disposition_distribution": dict(disposition_dist_v2),
        "v2_severity_distribution": dict(severity_dist_v2),
        "v2_rule_family_distribution": dict(rule_family_dist_v2),
        "seed": edb.REVIEW_SUBSET_SEED,
        "v2_sample_manifest_hash": san.sha256_hex(ds.canonical_json(v2_manifest)),
    }
    print("\n=== v1 vs v2 COMPARISON ===")
    print(json.dumps({k: v for k, v in comparison.items()
                      if k not in ("cases_added_in_v2", "cases_removed_from_v1", "cases_unchanged")},
                     indent=2))
    print(f"cases added in v2: {len(added)}, removed from v1: {len(removed)}, "
         f"unchanged: {len(unchanged)}")

    comparison_path = os.path.join(RESULTS_DIR, "phase7c-sample-v1-vs-v2.json")
    with open(comparison_path, "w", encoding="utf-8") as fh:
        json.dump(comparison, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"\ncomparison report written: {comparison_path}")

    # ---- v2 worksheet — written ONLY to its own explicitly-versioned file.
    # The original REVIEW_SUBSET_WORKSHEET.md (Phase 7B's v1 output) is never
    # touched again after this script runs — it stays exactly as Phase 7B
    # left it, a frozen historical record, not silently reused as a "latest"
    # alias for whichever version ran most recently. ----
    v2_worksheet_path = os.path.join(CANDIDATES_DIR, "REVIEW_SUBSET_WORKSHEET_v2.md")
    write_worksheet_to(v2_worksheet_path, subset_v2, strata_v2, group_rep_v2, exceptions_v2)
    print(f"v2 worksheet written: {v2_worksheet_path}")

    # ---- final re-verify: candidates STILL untouched after this whole run ----
    cases_after = load_candidates()
    _, errs_after = verify_candidates_unchanged(cases_after)
    print(f"\npost-run candidate verification errors: {errs_after}")
    if errs_after:
        sys.exit("CANDIDATES WERE MODIFIED DURING THIS RUN — this must never happen")

    return comparison


if __name__ == "__main__":
    main()
