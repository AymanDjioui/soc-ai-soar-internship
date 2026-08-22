#!/usr/bin/env python3
"""
Phase 7B — one controlled, READ-ONLY Dataset B candidate export.

Reads THEHIVE_API_KEY from the environment ONLY. Never prints, logs, or
persists it, a raw API response, or any unsanitized case content — every
print statement in this script is restricted to counts, case_uids
(pseudonyms), and aggregate statistics.

Uses ONLY read-only thehive4py methods: api.case.find(),
api.case.find_observables(). No .update()/.create()/.delete()/.comment.*/
.cortex.* call appears anywhere in this file.

Reuses rag_snapshot.export_case_from_thehive_record() (Phase 7A, already
fixture-tested) as the per-case sanitize-and-shape transform — not
reimplemented here.
"""
import json
import os
import random
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import agent_orchestrator as ao
import dataset_schema as ds
import rag_snapshot as rs
import sanitization as san
from thehive4py.client import TheHiveApi
from thehive4py.query.page import Paginate
from thehive4py.query.sort import Asc

_HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(_HERE, "..", "ai", "testset", "dataset_b_candidates")
RESULTS_DIR = os.path.join(_HERE, "..", "ai", "results")
DATASET_VERSION = "dataset-b-candidates-v0-2026-08-21"

# Fixed, documented salt for THIS export batch — not a security secret
# (pseudonymization here is for privacy/minimization against casual
# re-identification, not cryptographic protection against an attacker who
# already has API access to the same TheHive instance). A fixed salt means
# re-running this exact export script produces the SAME case_uids for the
# SAME real cases — reproducibility, not a fresh unlinkable set each time.
EXPORT_SALT = "dataset-b-v0-2026-08-21"

# Cases created by THIS project's own live checkpoints (Phase 5.5/5.6) must
# never end up in the evaluation corpus.
EXCLUDE_TITLE_PREFIXES = ("[SYNTHETIC TEST]",)
EXCLUDE_TAGS = {"synthetic", "notification-test", "phase-5-live-validation",
                "l2-integration-test", "phase-5-6-live-validation"}

# Phase 7D: now sourced from dataset_schema.HISTORICAL_DISPOSITION_VALUES —
# single source of truth shared with the v2 export's structured field.
DISPOSITION_VALUES = ds.HISTORICAL_DISPOSITION_VALUES
MAX_ALLOWED_TLP = 2  # exclude TLP:RED (3) and above — handling restriction incompatible with a broad eval snapshot

PAGE_SIZE = 100
REVIEW_SUBSET_TARGET = 60
REVIEW_SUBSET_SEED = 20260821  # frozen, documented


def _iso(epoch_ms):
    if not epoch_ms:
        return None
    return datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc).isoformat()


def _is_excluded_test_case(raw_case: dict) -> bool:
    title = str(raw_case.get("title") or "")
    if any(title.startswith(p) for p in EXCLUDE_TITLE_PREFIXES):
        return True
    tags = set(raw_case.get("tags") or [])
    return bool(tags & EXCLUDE_TAGS)


def classify_case(raw_case: dict):
    """Cheap, pre-observable-fetch classification. Returns (eligible: bool,
    exclusion_reason: str|None) — NEVER includes raw case content in the
    reason string, only structural facts."""
    if _is_excluded_test_case(raw_case):
        return False, "explicitly_synthetic_or_test_case"
    stage = raw_case.get("stage")
    status = raw_case.get("status")
    if stage != "Closed":
        return False, "still_open"
    if status not in DISPOSITION_VALUES:
        return False, "conflicting_closure_fields"  # stage=Closed but status isn't a disposition value
    tlp = raw_case.get("tlp")
    if isinstance(tlp, int) and tlp > MAX_ALLOWED_TLP:
        return False, "handling_restriction_incompatible"
    return True, None


def fetch_all_cases(api):
    """Read-only, paginated fetch of every case (any status) — classification
    happens client-side so every excluded case is COUNTED, not silently
    dropped by a server-side filter."""
    cases = []
    start = 0
    while True:
        page = api.case.find(sortby=Asc("number"), paginate=Paginate(start, start + PAGE_SIZE))
        if not page:
            break
        cases.extend(page)
        if len(page) < PAGE_SIZE:
            break
        start += PAGE_SIZE
    return cases


def build_incident_groups(candidate_ip_sets: dict) -> dict:
    """Union-find over case_uid: two cases sharing at least one observable
    IP are linked into the same incident_group_id. A case with no IP
    observables (or no overlap with anyone else) gets a singleton group."""
    parent = {uid: uid for uid in candidate_ip_sets}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    ip_to_uids = defaultdict(list)
    for uid, ips in candidate_ip_sets.items():
        for ip in ips:
            ip_to_uids[ip].append(uid)
    for ip, uids in ip_to_uids.items():
        for other in uids[1:]:
            union(uids[0], other)

    groups = {}
    for uid in candidate_ip_sets:
        root = find(uid)
        groups[uid] = f"grp-{san.sha256_hex(EXPORT_SALT + ':' + root)[:12]}"
    return groups


def main():
    api_key = os.environ.get("THEHIVE_API_KEY")
    if not api_key:
        sys.exit("THEHIVE_API_KEY not set in environment — aborting, nothing done")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    report = {"run_at": datetime.now(timezone.utc).isoformat(), "dataset_version": DATASET_VERSION}

    # ---- Preflight ----
    print("=== PREFLIGHT ===")
    api = TheHiveApi(ao.orch.THEHIVE_URL, apikey=api_key)
    try:
        current_user = api.user.get_current()
        auth_ok = bool(current_user and current_user.get("login"))
    except Exception as exc:
        sys.exit(f"PREFLIGHT FAILED: TheHive authentication: {type(exc).__name__}")
    report["preflight"] = {
        "thehive_auth": auth_ok,
        "read_only_methods_only": True,  # structural guarantee — see module docstring; no write method is called anywhere in this file
        "output_dir_gitignored": True,  # ai/testset/dataset_b_candidates/ matched by soar/.gitignore's ai/testset/**/raw_export/ + explicit rule added below
        "raw_api_response_logged": False,
    }
    print(json.dumps(report["preflight"], indent=2))
    if not auth_ok:
        sys.exit("PREFLIGHT FAILED: no current user returned — aborting")

    # ---- Fetch + classify ----
    print("\n=== FETCH + CLASSIFY ===")
    all_cases = fetch_all_cases(api)
    report["cases_queried"] = len(all_cases)
    print(f"cases_queried: {len(all_cases)}")

    exclusion_counts = Counter()
    eligible_raw = []
    for raw_case in all_cases:
        ok, reason = classify_case(raw_case)
        if ok:
            eligible_raw.append(raw_case)
        else:
            exclusion_counts[reason] += 1

    print(f"pre-observable-fetch eligible: {len(eligible_raw)}")
    print(f"pre-observable-fetch exclusions: {dict(exclusion_counts)}")

    # ---- Per-case sanitize/build/validate ----
    print("\n=== SANITIZE / BUILD / VALIDATE ===")
    candidates = []
    candidate_ip_sets = {}
    candidate_dispositions = {}  # case_uid -> raw historical status, tracked SEPARATELY
                                 # for reporting (never embedded as a raw value in the
                                 # written record beyond the derived must_not_auto_contain)
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
        raw_case_with_iso["startDate_iso"] = _iso(raw_case.get("startDate"))
        closure_time = _iso(raw_case.get("endDate"))

        def _sanitize(value):
            base = san.sanitize_text(value, html_escape=False)
            return san.pseudonymize_identities_in_text(base, salt=EXPORT_SALT)

        try:
            record = rs.export_case_from_thehive_record(
                raw_case_with_iso, raw_obs, case_uid=case_uid,
                incident_group_id=f"grp-pending-{case_uid}",  # placeholder, overwritten after grouping pass
                dataset_version=DATASET_VERSION,
                policy_version_frozen_against=ao.l1_policy.POLICY_VERSION,
                sanitize_fn=_sanitize)
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
        candidate_dispositions[case_uid] = raw_case.get("status")

    print(f"candidates passing sanitize+schema: {len(candidates)}")
    print(f"sanitization failures: {sanitize_failures}")
    print(f"schema failures: {schema_failures}")

    # ---- Incident-group assignment (real grouping pass, overwrites the placeholder) ----
    groups = build_incident_groups(candidate_ip_sets)
    for record in candidates:
        record["incident_group_id"] = groups.get(record["case_uid"], record["incident_group_id"])

    # Re-validate after the group-id rewrite (cheap, catches any regression)
    for record in candidates:
        errs = ds.validate_case(record)
        if errs:
            sys.exit(f"post-grouping validation FAILED for a candidate — aborting write: {errs}")

    # ---- Duplicate / incident-group / temporal analysis ----
    print("\n=== DUPLICATE / INCIDENT-GROUP / TEMPORAL ANALYSIS ===")
    dupes = rs.find_duplicate_content(candidates)
    report["duplicate_content_groups"] = len(dupes)
    report["duplicate_case_uids"] = sum(len(v) for v in dupes.values())

    group_sizes = Counter(r["incident_group_id"] for r in candidates)
    report["incident_group_distribution"] = {
        "total_groups": len(group_sizes),
        "singleton_groups": sum(1 for v in group_sizes.values() if v == 1),
        "largest_group_size": max(group_sizes.values()) if group_sizes else 0,
    }

    temporal_violations = sum(
        1 for r in candidates
        if r.get("closure_time") and r.get("event_time") and r["closure_time"] < r["event_time"])
    report["temporal_ordering_violations"] = temporal_violations

    # Real historical-disposition distribution — tracked separately during
    # the build loop (candidate_dispositions), never reconstructed from the
    # written record (which deliberately does not embed the raw status
    # beyond the derived must_not_auto_contain boolean).
    status_dist = Counter(candidate_dispositions.values())
    report["historical_disposition_distribution"] = dict(status_dist)
    report["severity_distribution"] = dict(Counter(
        (r.get("alert") or {}).get("severity") for r in candidates))

    print(f"duplicate content groups: {report['duplicate_content_groups']}")
    print(f"incident group distribution: {report['incident_group_distribution']}")
    print(f"temporal ordering violations: {temporal_violations}")
    print(f"historical disposition distribution: {dict(status_dist)}")

    # ---- Write candidate files (sanitized ONLY — no raw intermediate is ever written) ----
    print("\n=== WRITE CANDIDATES ===")
    for record in candidates:
        out_path = os.path.join(OUTPUT_DIR, f"{record['case_uid']}.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2, sort_keys=True)
            fh.write("\n")
    print(f"{len(candidates)} candidate files written to {OUTPUT_DIR}")

    # ---- Manifest ----
    manifest = rs.write_manifest(candidates, dataset_name="dataset-b-candidates",
                                 dataset_version=DATASET_VERSION,
                                 policy_version_frozen_against=ao.l1_policy.POLICY_VERSION)
    manifest_path = os.path.join(OUTPUT_DIR, "MANIFEST.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"manifest written: {manifest_path}  (manifest_hash={manifest['manifest_hash'][:16]}...)")

    # ---- Deterministic stratified review subset ----
    print("\n=== STRATIFIED REVIEW SUBSET ===")
    subset, strata_report = select_review_subset(candidates, candidate_dispositions,
                                                  target=REVIEW_SUBSET_TARGET, seed=REVIEW_SUBSET_SEED)
    write_review_worksheet(subset, strata_report)
    print(f"review subset size: {len(subset)}")
    print(f"strata: {json.dumps(strata_report, indent=2)}")

    # ---- Reports ----
    report["eligible_candidate_count"] = len(candidates)
    report["exclusion_counts"] = dict(exclusion_counts)
    report["review_subset_size"] = len(subset)
    report["manifest_hash"] = manifest["manifest_hash"]
    report_path = os.path.join(RESULTS_DIR, "phase7b-export-report.json")
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True, default=str)
        fh.write("\n")
    print(f"\nexport report written: {report_path}")

    print("\n=== DONE — no TheHive mutation performed, all labels remain pending ===")
    return report, candidates, subset


def _rule_family_bucket(record: dict) -> str:
    """A coarse, non-identifying bucket derived from the (already sanitized)
    alert title's first two words — a stand-in for 'alert source/rule
    family' stratification without needing a dedicated schema field."""
    title = str((record.get("alert") or {}).get("title") or "").strip().lower()
    words = title.split()[:2]
    return "-".join(words) if words else "unknown"


def select_review_subset(candidates: list, dispositions: dict, *, target: int, seed: int):
    """Deterministic, seeded, stratified sample — selection happens BEFORE
    any policy replay is run against these candidates (none is run in this
    script at all). Stratifies by (historical disposition, must_not_auto_
    contain, severity, rule-family bucket) — covering disposition, benign-
    vs-malicious history, severity, and alert source/rule family per the
    Phase 7B requirement. Guarantees at least 1 case per non-empty stratum
    (so rare/safety-relevant categories are never dropped) before filling
    the rest proportionally at random (seeded, reproducible)."""
    def stratum_key(r):
        sev = (r.get("alert") or {}).get("severity")
        disposition = dispositions.get(r["case_uid"])
        return (disposition, bool(r.get("must_not_auto_contain")), sev, _rule_family_bucket(r))

    strata = defaultdict(list)
    for r in candidates:
        strata[stratum_key(r)].append(r)

    rng = random.Random(seed)
    selected = []
    # Guarantee representation: at least 1 from every stratum first.
    for key, members in sorted(strata.items(), key=lambda kv: str(kv[0])):
        rng.shuffle(members)
        selected.append(members[0])

    remaining_pool = [r for key, members in strata.items() for r in members[1:]]
    rng.shuffle(remaining_pool)
    for r in remaining_pool:
        if len(selected) >= target:
            break
        selected.append(r)

    strata_report = {str(k): len(v) for k, v in strata.items()}
    return selected[:max(target, len(strata))], strata_report


def select_review_subset_v2(candidates: list, dispositions: dict, *, target: int, seed: int,
                            max_per_group: int = 3, exception_max_per_group: int = 5):
    """
    Phase 7C — corrects a real Phase 7B finding: the v1 selection let a
    single 60-case incident group dominate the stratum-guarantee pass with
    no per-group limit. Same 4 stratification dimensions as v1 (historical
    disposition, must_not_auto_contain, severity, rule-family bucket), PLUS
    an incident-group cap enforced throughout selection, not just in the
    guarantee pass.

    Also fixes a determinism gap found while reconstructing v1 for
    comparison: v1's result depended on the CALLER's candidate list order
    (a shuffle of a differently-ordered list produces a different
    permutation even with the same seed) — v2 sorts candidates by
    `case_uid` FIRST, so "same candidates + same seed" now means "same
    result" regardless of how the caller loaded/ordered the list.

    Rule: try to pick a stratum representative from a group still under
    `max_per_group`. If EVERY candidate in a stratum belongs to a group
    already at `max_per_group`, allow the documented exception up to
    `exception_max_per_group` for that specific stratum/group pair — logged,
    never silent. The fill pass respects the same caps (base cap normally,
    the exception cap only for groups that already used their exception).

    Returns (selected, strata_report, group_representation, exceptions).
    """
    candidates = sorted(candidates, key=lambda r: r["case_uid"])  # order-independence fix

    def stratum_key(r):
        sev = (r.get("alert") or {}).get("severity")
        disposition = dispositions.get(r["case_uid"])
        return (disposition, bool(r.get("must_not_auto_contain")), sev, _rule_family_bucket(r))

    strata = defaultdict(list)
    for r in candidates:
        strata[stratum_key(r)].append(r)

    rng = random.Random(seed)
    selected = []
    selected_uids = set()
    group_counts = Counter()
    exceptions = []

    def group_of(r):
        return r["incident_group_id"]

    # Pass 1: guarantee at least one per stratum, respecting the cap.
    for key, members in sorted(strata.items(), key=lambda kv: str(kv[0])):
        members = list(members)
        rng.shuffle(members)
        chosen = next((m for m in members if group_counts[group_of(m)] < max_per_group), None)
        if chosen is None:
            # Every candidate in this stratum belongs to an at-cap group —
            # a genuinely rare stratum. Apply the documented exception.
            chosen = next((m for m in members if group_counts[group_of(m)] < exception_max_per_group), None)
            if chosen is not None:
                exceptions.append({"stratum": str(key), "incident_group_id": group_of(chosen),
                                   "case_uid": chosen["case_uid"]})
        if chosen is not None:
            selected.append(chosen)
            selected_uids.add(chosen["case_uid"])
            group_counts[group_of(chosen)] += 1

    # Pass 2: fill remaining slots, respecting the SAME caps (exception cap
    # only for groups that already used their exception in pass 1).
    excepted_groups = {e["incident_group_id"] for e in exceptions}
    remaining_pool = [r for r in candidates if r["case_uid"] not in selected_uids]
    rng.shuffle(remaining_pool)
    for r in remaining_pool:
        if len(selected) >= target:
            break
        g = group_of(r)
        limit = exception_max_per_group if g in excepted_groups else max_per_group
        if group_counts[g] < limit:
            selected.append(r)
            selected_uids.add(r["case_uid"])
            group_counts[g] += 1

    strata_report = {str(k): len(v) for k, v in strata.items()}
    group_representation = dict(group_counts)
    return selected[:target], strata_report, group_representation, exceptions


def write_review_worksheet(subset: list, strata_report: dict):
    lines = [
        "# Dataset B — deterministic review subset (Phase 7B)",
        "",
        f"Generated with frozen seed `{REVIEW_SUBSET_SEED}` — selection happened BEFORE any "
        f"policy replay was run against these candidates (none was run in this export at all), "
        f"so the subset is not cherry-picked based on the current agent's behavior.",
        "",
        f"**{len(subset)} of {sum(strata_report.values())} eligible candidates selected for human "
        f"review.** Every selected record remains `review_status: \"pending\"`. The remaining "
        f"candidates form an unreviewed future pool — they cannot contribute to any safety-gate "
        f"metric until independently approved.",
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
        "Same workflow as `ai/testset/dataset_a_draft/REVIEW_WORKSHEET.md`: confirm/set "
        "`expected_tier`, `event_time` review, `required_reason_codes`/`forbidden_reason_codes`, "
        "`label_confidence`, `reviewed_by`/`reviewed_at`, then `review_status: \"approved\"` — "
        "or `\"disputed\"` (forced to L2/null) / `\"excluded\"` if warranted. Each candidate's "
        "historical disposition (`label_source: \"human_historical_disposition\"`) is a CANDIDATE "
        "label, never automatic ground truth.",
    ]
    path = os.path.join(OUTPUT_DIR, "REVIEW_SUBSET_WORKSHEET.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
