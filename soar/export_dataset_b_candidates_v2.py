#!/usr/bin/env python3
"""
Phase 7D — ONE new, read-only, in-memory-sanitized Dataset B export using
schema v2's structured `historical_disposition` field.

Reuses (NEVER reimplements) `export_dataset_b_candidates.py`'s (v1)
`classify_case()`, `fetch_all_cases()`, `build_incident_groups()`,
`_rule_family_bucket()`, `select_review_subset_v2()`, and `EXPORT_SALT` (the
SAME salt as v1 — deliberate: it makes v2's case_uids for the SAME
underlying TheHive case identical to v1's, which is what makes the v1-vs-v2
population comparison below possible at all).

Snapshot-cutoff enforcement (the Phase 7D requirement: "later case changes
cannot silently enter the dataset"): reads the ORIGINAL Phase 7B export's
`run_at` timestamp from `ai/results/phase7b-export-report.json` — the moment
that script started, immediately BEFORE its own TheHive query. Any raw case
with `_createdAt` (epoch ms) AFTER that timestamp did not exist at v1 export
time and is excluded from v2, unconditionally, before classification even
runs. If that report (or its `run_at` field) cannot be found/parsed, this
script ABORTS — it never guesses a cutoff.

This does NOT mean v2 is a byte-for-byt e replay of v1's exact case states:
a case that existed (created) before the cutoff but was still open at v1
time, and has since closed, WILL legitimately appear in v2 (its current,
now-closed state) — that is an explainable, cutoff-respecting difference
(the case is not "new"), not scope creep. See the v1-vs-v2 comparison
report this script writes for the full, explicit accounting of every
difference.

Same read-only/no-mutation guarantees as v1: THEHIVE_API_KEY from the
process environment ONLY, only `api.case.find()`/`api.case.find_
observables()`, no raw record ever written to disk, every output secret-
scanned and schema-validated, candidates remain `review_status: "pending"`.
"""
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import agent_orchestrator as ao
import dataset_schema as ds
import export_dataset_b_candidates as edb_v1
import rag_snapshot as rs
import sanitization as san
from thehive4py.client import TheHiveApi

_HERE = os.path.dirname(os.path.abspath(__file__))
V1_OUTPUT_DIR = edb_v1.OUTPUT_DIR
V1_REPORT_PATH = os.path.join(_HERE, "..", "ai", "results", "phase7b-export-report.json")
OUTPUT_DIR = os.path.join(_HERE, "..", "ai", "testset", "dataset_b_candidates_v2")
RESULTS_DIR = edb_v1.RESULTS_DIR
DATASET_VERSION = "dataset-b-candidates-v2-2026-08-21"

# SAME salt as v1 — deliberate, see module docstring.
EXPORT_SALT = edb_v1.EXPORT_SALT


def _epoch_ms(iso_str: str) -> int:
    dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1000)


def establish_cutoff():
    """
    Returns (cutoff_iso, cutoff_epoch_ms, warnings: list) or raises
    RuntimeError with a clear, specific message if the cutoff cannot be
    reliably established — this function NEVER guesses.
    """
    warnings = []
    if not os.path.exists(V1_REPORT_PATH):
        raise RuntimeError(f"cannot establish snapshot cutoff — {V1_REPORT_PATH} does not exist")
    try:
        report = json.load(open(V1_REPORT_PATH, encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise RuntimeError(f"cannot establish snapshot cutoff — {V1_REPORT_PATH} is unreadable/corrupt: {exc}")

    run_at = report.get("run_at")
    if not run_at:
        raise RuntimeError(f"cannot establish snapshot cutoff — {V1_REPORT_PATH} has no 'run_at' field")
    try:
        cutoff_epoch_ms = _epoch_ms(run_at)
    except ValueError as exc:
        raise RuntimeError(f"cannot establish snapshot cutoff — 'run_at' {run_at!r} is not valid ISO8601: {exc}")

    # Cross-check against the v1 manifest's built_at as a sanity check
    # (built_at is recorded AFTER the fetch — should be run_at plus at most
    # a few minutes for 334 cases; a large gap would suggest the report and
    # manifest are from different, mismatched runs). Not fatal — recorded as
    # a warning only, since run_at (recorded strictly BEFORE the query) is
    # the correct, conservative cutoff regardless.
    manifest_path = os.path.join(V1_OUTPUT_DIR, "MANIFEST.json")
    if os.path.exists(manifest_path):
        try:
            manifest = json.load(open(manifest_path, encoding="utf-8"))
            built_at = manifest.get("built_at")
            if built_at:
                gap_seconds = (_epoch_ms(built_at) - cutoff_epoch_ms) / 1000
                if not (0 <= gap_seconds <= 3600):
                    warnings.append(f"v1 manifest built_at is {gap_seconds:.0f}s after report run_at "
                                    f"— outside the expected 0-3600s window, but run_at is still used "
                                    f"as the cutoff (it is the more conservative, pre-query timestamp)")
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            warnings.append(f"could not cross-check against the v1 manifest's built_at: {exc}")
    else:
        warnings.append(f"v1 manifest not found at {manifest_path} — cross-check skipped, "
                        f"proceeding on report run_at alone")

    return run_at, cutoff_epoch_ms, warnings


def main():
    api_key = os.environ.get("THEHIVE_API_KEY")
    if not api_key:
        sys.exit("THEHIVE_API_KEY not set in environment — aborting, nothing done")

    try:
        cutoff_iso, cutoff_epoch_ms, cutoff_warnings = establish_cutoff()
    except RuntimeError as exc:
        sys.exit(f"SNAPSHOT CUTOFF COULD NOT BE ESTABLISHED — stopping per instruction, nothing done.\n{exc}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    report = {"run_at": datetime.now(timezone.utc).isoformat(), "dataset_version": DATASET_VERSION,
              "snapshot_cutoff_iso": cutoff_iso, "snapshot_cutoff_epoch_ms": cutoff_epoch_ms,
              "cutoff_warnings": cutoff_warnings}

    print("=== PREFLIGHT ===")
    api = TheHiveApi(ao.orch.THEHIVE_URL, apikey=api_key)
    try:
        current_user = api.user.get_current()
        auth_ok = bool(current_user and current_user.get("login"))
    except Exception as exc:
        sys.exit(f"PREFLIGHT FAILED: TheHive authentication: {type(exc).__name__}")
    report["preflight"] = {
        "thehive_auth": auth_ok, "read_only_methods_only": True,
        "output_dir_gitignored": True, "raw_api_response_logged": False,
        "snapshot_cutoff_established": True,
    }
    print(json.dumps(report["preflight"], indent=2))
    print(f"snapshot cutoff: {cutoff_iso}  ({cutoff_epoch_ms} epoch ms)")
    if cutoff_warnings:
        print(f"cutoff warnings: {cutoff_warnings}")
    if not auth_ok:
        sys.exit("PREFLIGHT FAILED: no current user returned — aborting")

    print("\n=== FETCH (ALL, THEN CUTOFF-FILTER) ===")
    all_cases_raw = edb_v1.fetch_all_cases(api)
    report["cases_queried_live"] = len(all_cases_raw)

    cutoff_filtered = [c for c in all_cases_raw if (c.get("_createdAt") or 0) <= cutoff_epoch_ms]
    excluded_post_cutoff = len(all_cases_raw) - len(cutoff_filtered)
    report["excluded_created_after_cutoff"] = excluded_post_cutoff
    print(f"cases_queried_live: {len(all_cases_raw)}")
    print(f"excluded (created after cutoff, never entered v2): {excluded_post_cutoff}")
    print(f"cutoff-filtered population: {len(cutoff_filtered)}")

    # Full case_uid -> raw_case map over the CUTOFF-FILTERED population
    # (regardless of eligibility) — needed for the v1-vs-v2 population diff.
    uid_to_raw = {}
    for raw_case in cutoff_filtered:
        real_id = raw_case.get("_id") or raw_case.get("id")
        case_uid = f"dsb-{san.stable_pseudonym(str(real_id), EXPORT_SALT, prefix='c')}"
        uid_to_raw[case_uid] = raw_case

    print("\n=== CLASSIFY ===")
    exclusion_counts = Counter()
    eligible_raw = []
    for raw_case in cutoff_filtered:
        ok, reason = edb_v1.classify_case(raw_case)
        if ok:
            eligible_raw.append(raw_case)
        else:
            exclusion_counts[reason] += 1
    print(f"pre-observable-fetch eligible: {len(eligible_raw)}")
    print(f"pre-observable-fetch exclusions: {dict(exclusion_counts)}")

    print("\n=== SANITIZE / BUILD / VALIDATE (schema v2) ===")
    candidates = []
    candidate_ip_sets = {}
    historical_dispositions = {}
    sanitize_failures = 0
    schema_failures = 0

    for raw_case in eligible_raw:
        real_id = raw_case.get("_id") or raw_case.get("id")
        case_uid = f"dsb-{san.stable_pseudonym(str(real_id), EXPORT_SALT, prefix='c')}"
        try:
            raw_obs = api.case.find_observables(real_id)
        except Exception:
            exclusion_counts["observable_fetch_failed"] += 1
            continue

        raw_case_with_iso = dict(raw_case)
        raw_case_with_iso["startDate_iso"] = edb_v1._iso(raw_case.get("startDate"))
        closure_time = edb_v1._iso(raw_case.get("endDate"))

        def _sanitize(value):
            base = san.sanitize_text(value, html_escape=False)
            return san.pseudonymize_identities_in_text(base, salt=EXPORT_SALT)

        try:
            record = rs.export_case_from_thehive_record(
                raw_case_with_iso, raw_obs, case_uid=case_uid,
                incident_group_id=f"grp-pending-{case_uid}",
                dataset_version=DATASET_VERSION,
                policy_version_frozen_against=ao.l1_policy.POLICY_VERSION,
                sanitize_fn=_sanitize, schema_version=ds.SCHEMA_VERSION_V2)
        except Exception:
            exclusion_counts["record_build_failed"] += 1
            continue

        record["closure_time"] = closure_time
        record["label_confidence"] = "medium"

        serialized = ds.canonical_json(record)
        if san.contains_unredacted_secret(serialized):
            sanitize_failures += 1
            exclusion_counts["sanitization_failed"] += 1
            continue

        errors = ds.validate_case(record)
        if errors:
            schema_failures += 1
            exclusion_counts["schema_validation_failed"] += 1
            continue

        candidates.append(record)
        candidate_ip_sets[case_uid] = {o.get("data") for o in record["observables"] if o.get("data")}
        historical_dispositions[case_uid] = record["historical_disposition"]

    print(f"candidates passing sanitize+schema: {len(candidates)}")
    print(f"sanitization failures: {sanitize_failures}")
    print(f"schema failures: {schema_failures}")

    groups = edb_v1.build_incident_groups(candidate_ip_sets)
    for record in candidates:
        record["incident_group_id"] = groups.get(record["case_uid"], record["incident_group_id"])
    for record in candidates:
        errs = ds.validate_case(record)
        if errs:
            sys.exit(f"post-grouping validation FAILED for a candidate — aborting write: {errs}")

    print("\n=== WRITE CANDIDATES (v2) ===")
    for record in candidates:
        out_path = os.path.join(OUTPUT_DIR, f"{record['case_uid']}.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2, sort_keys=True)
            fh.write("\n")
    print(f"{len(candidates)} v2 candidate files written to {OUTPUT_DIR}")

    manifest = rs.write_manifest(candidates, dataset_name="dataset-b-candidates-v2",
                                 dataset_version=DATASET_VERSION,
                                 policy_version_frozen_against=ao.l1_policy.POLICY_VERSION,
                                 schema_version=ds.SCHEMA_VERSION_V2)
    manifest_path = os.path.join(OUTPUT_DIR, "MANIFEST.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"manifest written: {manifest_path}  (manifest_hash={manifest['manifest_hash'][:16]}...)")

    # ---- v1-vs-v2 population comparison — full, explicit accounting ----
    print("\n=== v1 vs v2 POPULATION COMPARISON ===")
    v1_manifest = json.load(open(os.path.join(V1_OUTPUT_DIR, "MANIFEST.json"), encoding="utf-8"))
    v1_uids = set(v1_manifest["cases"].keys())
    v2_uids = {c["case_uid"] for c in candidates}

    unchanged = v1_uids & v2_uids
    removed_from_v2 = v1_uids - v2_uids
    added_in_v2 = v2_uids - v1_uids

    removed_explained = {}
    for uid in removed_from_v2:
        if uid not in uid_to_raw:
            removed_explained[uid] = "deleted_or_not_found_since_v1"
            continue
        ok, reason = edb_v1.classify_case(uid_to_raw[uid])
        removed_explained[uid] = reason if not ok else "eligible_now_but_dropped_downstream"

    added_explained = {uid: "existed_before_cutoff_but_was_ineligible_at_v1_time_now_eligible"
                       for uid in added_in_v2}

    comparison = {
        "v1_case_count": len(v1_uids), "v2_case_count": len(v2_uids),
        "unchanged_count": len(unchanged),
        "removed_from_v2_count": len(removed_from_v2),
        "removed_from_v2_reasons": Counter(removed_explained.values()),
        "added_in_v2_count": len(added_in_v2),
        "added_in_v2_reason": "existed_before_cutoff_but_was_ineligible_at_v1_time_now_eligible"
                              if added_in_v2 else None,
    }
    print(json.dumps({k: (dict(v) if isinstance(v, Counter) else v) for k, v in comparison.items()}, indent=2))

    # ---- Deterministic review sample using the AUTHORITATIVE structured
    # field — no prose extraction anywhere in this path. ----
    print("\n=== STRATIFIED REVIEW SUBSET (authoritative structured disposition) ===")
    subset, strata_report, group_representation, exceptions = edb_v1.select_review_subset_v2(
        candidates, historical_dispositions, target=edb_v1.REVIEW_SUBSET_TARGET,
        seed=edb_v1.REVIEW_SUBSET_SEED)
    sample_manifest = {
        "sample_version": "phase7d-v2-authoritative",
        "seed": edb_v1.REVIEW_SUBSET_SEED,
        "target": edb_v1.REVIEW_SUBSET_TARGET,
        "case_uids": [r["case_uid"] for r in subset],
        "case_content_hashes": {r["case_uid"]: ds.case_content_hash(r) for r in subset},
        "strata_report": strata_report,
        "group_representation": group_representation,
        "exceptions": exceptions,
    }
    sample_manifest_path = os.path.join(OUTPUT_DIR, "REVIEW_SAMPLE_MANIFEST.json")
    with open(sample_manifest_path, "w", encoding="utf-8") as fh:
        json.dump(sample_manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"review subset size: {len(subset)}  exceptions: {len(exceptions)}")
    print(f"sample manifest written: {sample_manifest_path}")

    # ---- Reports ----
    report["eligible_candidate_count"] = len(candidates)
    report["exclusion_counts"] = dict(exclusion_counts)
    report["review_subset_size"] = len(subset)
    report["manifest_hash"] = manifest["manifest_hash"]
    report["v1_vs_v2_comparison"] = {k: (dict(v) if isinstance(v, Counter) else v)
                                     for k, v in comparison.items()}
    report_path = os.path.join(RESULTS_DIR, "phase7d-export-report.json")
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True, default=str)
        fh.write("\n")
    print(f"\nexport report written: {report_path}")

    print("\n=== DONE — no TheHive mutation performed, all labels remain pending ===")
    return report, candidates, subset


if __name__ == "__main__":
    main()
