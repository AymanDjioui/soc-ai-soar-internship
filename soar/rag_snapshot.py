#!/usr/bin/env python3
"""
Phase 7A — frozen, offline RAG corpus snapshot + leakage-controlled query.

The live `agent_tools.search_past_cases()` this replaces for replay purposes
has, by the original audit's own finding (L1-L2-SAFETY-AUDIT.md P7): "no
leave-one-out logic, no self-exclusion parameter" — a real, not-yet-
triggered risk that only manifests once a replayed case's own historical
record could be retrieved as its own "prior case."

This module is the offline, leakage-controlled replacement used ONLY during
`policy-replay` (see replay_harness.py) — never a live TheHive query. Every
function here operates on IN-MEMORY case records; nothing in this module
makes a network call. The live-export path (`export_from_thehive_records()`)
is foundation code for Phase 7B — it is NEVER invoked against a real TheHive
instance in Phase 7A, and is tested EXCLUSIVELY with injected fixtures.

Four leakage controls, all enforced together in `query_similar()`:
  1. Exact case-ID exclusion (a case can never retrieve itself).
  2. Canonical content-hash exclusion (a byte-identical duplicate can't
     retrieve itself under a different id).
  3. Incident-group exclusion (a related/duplicate alert from the SAME
     underlying incident can't leak the answer into an earlier case in the
     same family — "a later duplicate or related alert must not leak the
     answer into an earlier evaluation case").
  4. Temporal cutoff (a case can only retrieve OTHER cases closed strictly
     before its own event_time — no retrieving the future).
"""
from datetime import datetime, timezone

import dataset_schema
import sanitization


def _parse_event_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def build_snapshot(cases: list, snapshot_id: str = "default") -> dict:
    """
    Build an in-memory RAG snapshot from a list of ALREADY schema-valid
    dataset case records. Raises dataset_schema.DatasetValidationError if
    any case fails validation — a snapshot is never built from unvalidated
    input.

    Returns {"snapshot_id": str, "built_at": iso-str,
             "entries": {case_uid: {...}}}.
    """
    entries = {}
    for case in cases:
        dataset_schema.assert_valid_case(case)
        case_uid = case["case_uid"]
        if case_uid in entries:
            raise ValueError(f"duplicate case_uid in snapshot input: {case_uid!r}")
        entries[case_uid] = {
            "case_uid": case_uid,
            "incident_group_id": case["incident_group_id"],
            "event_time": case["event_time"],
            "event_time_parsed": _parse_event_time(case["event_time"]),
            "observables": case["observables"],
            "content_hash": dataset_schema.case_content_hash(case),
            "review_status": case["review_status"],
            "label_source": case["label_source"],
            # The legitimate "have we seen this before, how was it resolved"
            # signal — analogous to search_past_cases()'s disposition hint.
            "disposition_hint": (case.get("ground_truth") or {}).get("is_false_positive"),
            "mitre_technique": (case.get("ground_truth") or {}).get("mitre_technique"),
        }
    return {"snapshot_id": snapshot_id,
           "built_at": datetime.now(timezone.utc).isoformat(),
           "entries": entries}


def query_similar(snapshot: dict, target_observables: list, *, exclude_case_uid: str,
                  exclude_content_hash: str = None, exclude_incident_group_ids=None,
                  as_of_event_time: str = None, limit: int = 10) -> list:
    """
    Offline, leakage-controlled equivalent of agent_tools.search_past_cases()
    — exact observable-data match (same matching philosophy as the live
    tool: precise, not semantic), but with all four leakage controls
    enforced BEFORE any match is even attempted, not as an afterthought
    filter on the result.

    `exclude_incident_group_ids` should include the target case's OWN
    incident_group_id (callers are expected to pass this — see
    replay_harness.py, which always includes the case's own group).

    Returns a list of matching entries (each the same shape build_snapshot()
    produces), most-recent-first, capped at `limit`.
    """
    exclude_groups = set(exclude_incident_group_ids or ())
    as_of = _parse_event_time(as_of_event_time) if as_of_event_time else None
    target_values = {o.get("data") for o in (target_observables or []) if o.get("data")}

    candidates = []
    for case_uid, entry in snapshot["entries"].items():
        # ---- Leakage control 1: exact case-ID exclusion ----
        if case_uid == exclude_case_uid:
            continue
        # ---- Leakage control 2: canonical content-hash exclusion ----
        if exclude_content_hash is not None and entry["content_hash"] == exclude_content_hash:
            continue
        # ---- Leakage control 3: incident-group exclusion ----
        if entry["incident_group_id"] in exclude_groups:
            continue
        # ---- Leakage control 4: temporal cutoff — only cases CLOSED
        # (here: recorded) strictly BEFORE the evaluation case's own event
        # time are eligible. A case with no event_time is never returned as
        # a neighbor (its own temporal position is unknown, so it can't be
        # proven to precede anything) and never queries (see replay_harness).
        if as_of is not None:
            if entry["event_time_parsed"] is None or entry["event_time_parsed"] >= as_of:
                continue

        entry_values = {o.get("data") for o in (entry.get("observables") or []) if o.get("data")}
        if target_values & entry_values:
            candidates.append(entry)

    candidates.sort(key=lambda e: e["event_time_parsed"] or datetime.min.replace(tzinfo=timezone.utc),
                    reverse=True)
    return candidates[:limit]


def write_manifest(cases: list, *, dataset_name: str, dataset_version: str,
                   policy_version_frozen_against: str, schema_version: str = None) -> dict:
    """
    Build the frozen split manifest: per-case content hash + incident group,
    a SHA-256 over the canonical serialization of the whole manifest body
    (for tamper-evidence), and enough metadata to reproduce/audit the split
    later. Raises DatasetValidationError if any case is invalid.

    `schema_version` defaults to `dataset_schema.SCHEMA_VERSION` (v1) for
    backward compatibility with every existing caller; Phase 7D's v2 export
    passes `dataset_schema.SCHEMA_VERSION_V2` explicitly. Does NOT infer the
    version from the cases themselves — a manifest describes ONE homogeneous
    schema version for its whole file, by construction, and a mixed-version
    `cases` list is a caller bug this function is not responsible for masking.
    """
    schema_version = schema_version or dataset_schema.SCHEMA_VERSION
    cases_entry = {}
    for case in cases:
        dataset_schema.assert_valid_case(case)
        cases_entry[case["case_uid"]] = {
            "content_hash": dataset_schema.case_content_hash(case),
            "incident_group_id": case["incident_group_id"],
            "review_status": case["review_status"],
        }
    manifest = {
        "manifest_version": 1,
        "schema_version": schema_version,
        "dataset_name": dataset_name,
        "dataset_version": dataset_version,
        "policy_version_frozen_against": policy_version_frozen_against,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "case_count": len(cases_entry),
        "cases": cases_entry,
    }
    manifest["manifest_hash"] = sanitization.sha256_hex(dataset_schema.canonical_json(
        {k: v for k, v in manifest.items() if k != "manifest_hash"}))
    return manifest


def verify_manifest(manifest: dict, cases: list) -> list:
    """
    Independently re-verify a manifest against the ACTUAL case records —
    returns a list of discrepancy strings (empty = manifest matches
    reality). Checks: manifest structural validity, per-case content-hash
    match, no missing/extra cases, and the manifest's own tamper-evidence
    hash.
    """
    errors = list(dataset_schema.validate_manifest(manifest))
    if errors:
        return errors

    recomputed_hash = sanitization.sha256_hex(dataset_schema.canonical_json(
        {k: v for k, v in manifest.items() if k != "manifest_hash"}))
    if manifest.get("manifest_hash") != recomputed_hash:
        errors.append("manifest_hash does not match a fresh recomputation — manifest body was tampered "
                      "with or corrupted")

    by_uid = {}
    for case in cases:
        dataset_schema.assert_valid_case(case)
        by_uid[case["case_uid"]] = case

    manifest_uids = set(manifest["cases"].keys())
    actual_uids = set(by_uid.keys())
    if manifest_uids - actual_uids:
        errors.append(f"manifest references case_uid(s) not present in the supplied cases: "
                      f"{sorted(manifest_uids - actual_uids)}")
    if actual_uids - manifest_uids:
        errors.append(f"supplied cases include case_uid(s) not in the manifest: "
                      f"{sorted(actual_uids - manifest_uids)}")

    for case_uid in manifest_uids & actual_uids:
        actual_hash = dataset_schema.case_content_hash(by_uid[case_uid])
        if actual_hash != manifest["cases"][case_uid]["content_hash"]:
            errors.append(f"content_hash mismatch for {case_uid!r} — the case's alert/observables/"
                          f"source changed since the manifest was built")

    return errors


def find_duplicate_content(cases: list) -> dict:
    """Group case_uids by content_hash — any group with more than one member
    is a content-level duplicate (§4: 'canonical content-hash exclusion').
    Returns {content_hash: [case_uid, ...]} for groups with 2+ members only."""
    by_hash = {}
    for case in cases:
        h = dataset_schema.case_content_hash(case)
        by_hash.setdefault(h, []).append(case["case_uid"])
    return {h: uids for h, uids in by_hash.items() if len(uids) > 1}


# ==============================================================================
# Dataset B exporter FOUNDATION — Phase 7B territory. NEVER invoked against a
# live TheHive instance in Phase 7A. `thehive_query_fn` is REQUIRED (no
# default that could accidentally resolve to a live call) — every test for
# this function supplies a fixture.
# ==============================================================================

def export_case_from_thehive_record(raw_case: dict, raw_observables: list, *, case_uid: str,
                                     incident_group_id: str, dataset_version: str,
                                     policy_version_frozen_against: str, sanitize_fn=None,
                                     schema_version: str = None) -> dict:
    """
    Convert ONE raw TheHive-shaped case record (as an already-fetched dict —
    this function itself performs NO query, live or otherwise) into a
    schema-valid Phase 7 draft case record. `case_uid`/`incident_group_id`
    MUST be pre-assigned pseudonyms by the caller (this function does not
    invent pseudonymization — see Phase 7B's real export tooling for that).

    The resulting record is always `review_status: "pending"`,
    `label_source: "human_historical_disposition"` — a raw historical
    disposition is a CANDIDATE label, never automatically approved.
    `sanitize_fn` defaults to `sanitization.sanitize_text` (redaction only,
    no HTML-escaping — this is dataset content, not an email).

    `schema_version` defaults to `dataset_schema.SCHEMA_VERSION` (v1, the
    original Phase 7B shape — unchanged, no behavior difference for existing
    callers). Phase 7D callers pass `dataset_schema.SCHEMA_VERSION_V2` to
    additionally emit the STRUCTURED `historical_disposition` /
    `historical_disposition_source` fields (raw `status` verbatim + the
    fixed source tag `"thehive_closed_case"`) — the authoritative
    replacement for the old label_notes-prose-only disposition record.
    """
    sanitize_fn = sanitize_fn or sanitization.sanitize_text
    schema_version = schema_version or dataset_schema.SCHEMA_VERSION
    title = sanitize_fn(raw_case.get("title", ""))
    description = sanitize_fn(raw_case.get("description", ""))
    observables = [
        {"dataType": o.get("dataType"), "data": sanitize_fn(o.get("data")), "tags": o.get("tags") or []}
        for o in (raw_observables or [])
    ]
    disposition = raw_case.get("status")
    record = {
        "schema_version": schema_version,
        "case_uid": case_uid,
        "incident_group_id": incident_group_id,
        "event_time": raw_case.get("startDate_iso"),  # caller converts epoch -> ISO8601 before calling
        "source": f"thehive:case:{sanitization.correlation_id(str(raw_case.get('_id') or raw_case.get('id') or ''))}",
        "alert": {"title": title, "description": description, "severity": raw_case.get("severity")},
        "observables": observables,
        "fixtures": {},
        "rag_snapshot_ref": None,
        "dataset_version": dataset_version,
        "policy_version_frozen_against": policy_version_frozen_against,
        "label_source": "human_historical_disposition",
        "label_confidence": "medium",
        "review_status": "pending",
        "reviewed_by": None,
        "reviewed_at": None,
        "label_notes": f"draft export — historical disposition {disposition!r} is a CANDIDATE label, "
                      f"not yet human-reviewed/approved",
        "expected_tier": None,
        "expected_primary_reason": None,
        "required_reason_codes": [],
        "forbidden_reason_codes": [],
        "must_not_auto_contain": disposition == "FalsePositive",
        "must_remain_open": True,
    }
    if schema_version == dataset_schema.SCHEMA_VERSION_V2:
        record["historical_disposition"] = disposition if disposition in dataset_schema.HISTORICAL_DISPOSITION_VALUES else None
        record["historical_disposition_source"] = "thehive_closed_case"
    return record
