#!/usr/bin/env python3
"""
Phase 7A — strict schema definition and validator for replay-harness dataset
case records (Dataset A / Dataset B).

Side-effect-free (only imports the standard library + `l1_policy`, itself
side-effect-free — no thehive4py, no network, no file I/O at import time).

Design principles (per the Phase 7 mandatory corrections):
  - A historical human-closed disposition is a CANDIDATE label, never
    automatic ground truth — every case carries `label_source`,
    `label_confidence`, `review_status`, and only `review_status=="approved"`
    cases may contribute to safety-gate metrics.
  - Disputed cases default to L2 (never silently treated as L1 ground truth).
  - Reject unknown or malformed critical fields rather than guessing —
    `validate_case()` returns EVERY violation found, not just the first.
  - No field here is ever derived from the policy under evaluation (that
    would be circular ground truth) — `label_source` is a closed enum that
    structurally excludes any "policy-derived" value.
"""
import json
import re

import l1_policy

SCHEMA_VERSION = "phase7-v1"

# Phase 7D — schema v2 adds a STRUCTURED, authoritative historical-disposition
# field. v1 records (the 226 Phase 7B Dataset B candidates + the golden-seven
# Dataset A drafts) are frozen and never migrated in place — v2 is additive,
# used only by NEW records going forward (the separate Phase 7D Dataset B v2
# export). A case's OWN `schema_version` value decides which required-field
# set applies; both versions are simultaneously valid, never one replacing
# the other in validate_case().
SCHEMA_VERSION_V2 = "phase7-v2"
SUPPORTED_SCHEMA_VERSIONS = {SCHEMA_VERSION, SCHEMA_VERSION_V2}

REVIEW_STATUSES = {"pending", "approved", "disputed", "excluded"}
LABEL_CONFIDENCE_LEVELS = {"high", "medium", "low"}

# Closed allowlist — a value outside this set is REJECTED outright, which is
# what structurally prevents a "derived_from_policy" (or any other circular)
# label source from ever validating. New legitimate sources must be added
# here explicitly, never inferred.
LABEL_SOURCES = {
    "human_historical_disposition",  # a real TheHive case's human-closed disposition (Dataset B)
    "human_hand_labeled",            # a reviewer directly authored the label (Dataset A)
    "synthetic_adversarial",         # constructed specifically to test a known failure mode (P8)
    # Phase 7D — a case whose expected outcome was derived from the WRITTEN
    # eligibility specification (l1_policy.py's gate docstrings) and this
    # project's own audit requirements, NOT by executing the policy under
    # evaluation and copying its output. Still `review_status: "pending"` —
    # a human must confirm the derivation before it counts as ground truth.
    "specification_derived_pending_human",
}

# Defense-in-depth: even though LABEL_SOURCES is a closed allowlist, also
# explicitly name what must never appear, so a future accidental addition to
# LABEL_SOURCES is still caught by an independent check with a clear message.
#
# Phase 7D correction: the bare substring "derived" used to be in this list.
# It silently rejected the legitimate, explicitly-requested
# "specification_derived_pending_human" source (derived from WRITTEN DOCS,
# not from the policy under test) — a real bug that would have blocked this
# phase's own instructions. The actual circularity risk is a label sourced
# FROM THE POLICY ITSELF or FROM A MODEL'S OWN OUTPUT — narrowed to that.
_FORBIDDEN_LABEL_SOURCE_SUBSTRINGS = ("policy_derived", "derived_from_policy", "policy_output",
                                     "model_output", "llm")

# ---- Phase 7D structured historical-disposition (schema v2 only) ----
# Mirrors thehive4py.types.case.CaseStatus's real closed-disposition values
# (New/InProgress are open-case statuses, never a "historical disposition" —
# excluded on purpose) — single source of truth for what
# export_dataset_b_candidates.py's DISPOSITION_VALUES also uses.
HISTORICAL_DISPOSITION_VALUES = {"TruePositive", "FalsePositive", "Indeterminate", "Other", "Duplicated"}
HISTORICAL_DISPOSITION_SOURCES = {"thehive_closed_case"}
V2_REQUIRED_FIELDS = {"historical_disposition", "historical_disposition_source"}
V2_ALLOWED_EXTRA_FIELDS = {"historical_disposition_metadata"}

_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_ISO8601_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")

REQUIRED_FIELDS = {
    "schema_version", "case_uid", "incident_group_id", "event_time", "source",
    "alert", "observables", "fixtures", "rag_snapshot_ref", "dataset_version",
    "policy_version_frozen_against", "label_source", "label_confidence",
    "review_status", "reviewed_by", "reviewed_at", "label_notes",
    "expected_tier", "expected_primary_reason", "required_reason_codes",
    "forbidden_reason_codes", "must_not_auto_contain", "must_remain_open",
}

# Backward-compatibility fields carried through from the pre-Phase-7 golden-
# seven schema (`ai/testset/*.json`) during migration — not validated beyond
# "must be present if declared", kept for human readability, never required.
# `closure_time`: OPTIONAL, added for Dataset B (Phase 7B) — when the
# underlying case's human disposition was actually finalized, distinct from
# `event_time` (when the alert fired). Deliberately added here as an
# ALLOWED EXTRA rather than a new REQUIRED field / schema_version bump — the
# already-migrated golden-seven Phase 7A records never had this concept and
# must remain valid without it; a record that DOES carry it gets the same
# nullable-ISO8601 validation as event_time.
ALLOWED_EXTRA_FIELDS = {"id", "note", "ground_truth", "closure_time"}

# NOTE: v2-only fields (V2_REQUIRED_FIELDS / V2_ALLOWED_EXTRA_FIELDS) are
# DELIBERATELY excluded from this base set — validate_case() adds them to
# the allowed/required sets ONLY when the record's own schema_version is
# SCHEMA_VERSION_V2. A v1 record carrying historical_disposition* is
# rejected as an unknown field — this is the enforced v1/v2 separation.
ALLOWED_FIELDS = REQUIRED_FIELDS | ALLOWED_EXTRA_FIELDS


class DatasetValidationError(Exception):
    """Raised by assert_valid_case()/assert_valid_manifest() — carries every
    violation found, not just the first, in .errors."""
    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def _is_str(v) -> bool:
    return isinstance(v, str)


def _is_nonempty_str(v) -> bool:
    return isinstance(v, str) and len(v.strip()) > 0


def validate_case(case: dict) -> list:
    """
    Validate ONE dataset case record. Returns a list of human-readable error
    strings — empty list means valid. Never raises on a malformed case
    itself (that would stop error collection after the first problem);
    raises only TypeError if `case` isn't even a dict.

    Deliberately checks presence/type/enum-membership/cross-field
    consistency all in one pass so a single validation run surfaces every
    problem in a case, not one-at-a-time.
    """
    if not isinstance(case, dict):
        raise TypeError(f"case must be a dict, got {type(case).__name__}")

    errors = []

    # ---- schema_version decides which field sets apply, BEFORE anything
    # else is checked (Phase 7D — v1/v2 coexist; a record declares which
    # ruleset governs it). An unrecognized version falls back to the v1
    # field sets so the unknown/missing-field errors below still make sense,
    # but is flagged explicitly here too.
    declared_version = case.get("schema_version")
    is_v2 = declared_version == SCHEMA_VERSION_V2
    if declared_version not in SUPPORTED_SCHEMA_VERSIONS:
        errors.append(f"schema_version {declared_version!r} not in {sorted(SUPPORTED_SCHEMA_VERSIONS)}")

    required_fields = REQUIRED_FIELDS | (V2_REQUIRED_FIELDS if is_v2 else set())
    allowed_fields = ALLOWED_FIELDS | (V2_REQUIRED_FIELDS | V2_ALLOWED_EXTRA_FIELDS if is_v2 else set())

    # ---- Unknown-field rejection (typo protection) — also the v1/v2
    # separation enforcement: a v1 record carrying any v2-only field name is
    # rejected here as "unknown", since allowed_fields only adds the v2 set
    # when is_v2 is True. ----
    unknown = set(case.keys()) - allowed_fields
    if unknown:
        errors.append(f"unknown field(s) not in the Phase 7 schema: {sorted(unknown)}")

    # ---- Required-field presence ----
    missing = required_fields - set(case.keys())
    if missing:
        errors.append(f"missing required field(s): {sorted(missing)}")
        # Can't meaningfully validate types/cross-field rules on missing
        # fields — return early with just the presence errors.
        return errors

    # ---- case_uid / incident_group_id ----
    if not _is_nonempty_str(case["case_uid"]) or not _ID_RE.match(case["case_uid"]):
        errors.append(f"case_uid must be a non-empty [A-Za-z0-9_-]+ string, got {case['case_uid']!r}")
    if not _is_nonempty_str(case["incident_group_id"]) or not _ID_RE.match(case["incident_group_id"]):
        errors.append(f"incident_group_id must be a non-empty [A-Za-z0-9_-]+ string, "
                      f"got {case['incident_group_id']!r}")

    # ---- historical_disposition / historical_disposition_source (schema v2
    # ONLY — presence already enforced by required_fields above when is_v2).
    # This is now the AUTHORITATIVE source for a Dataset B case's raw
    # historical disposition — the Phase 7C prose extractor
    # (extract_historical_disposition_hint()) is NEVER treated as
    # authoritative for a v2 record; it remains a v1-only display aid. ----
    if is_v2:
        hd = case.get("historical_disposition")
        if hd is not None and hd not in HISTORICAL_DISPOSITION_VALUES:
            errors.append(f"historical_disposition {hd!r} not in "
                          f"{sorted(HISTORICAL_DISPOSITION_VALUES)} (or null)")
        hds = case.get("historical_disposition_source")
        if hds not in HISTORICAL_DISPOSITION_SOURCES:
            errors.append(f"historical_disposition_source {hds!r} not in "
                          f"{sorted(HISTORICAL_DISPOSITION_SOURCES)}")
        if "historical_disposition_metadata" in case and case["historical_disposition_metadata"] is not None:
            if not isinstance(case["historical_disposition_metadata"], dict):
                errors.append("historical_disposition_metadata must be a dict or null")

    # ---- event_time (nullable, but if present must be ISO8601) ----
    event_time = case["event_time"]
    if event_time is not None:
        if not _is_str(event_time) or not _ISO8601_RE.match(event_time):
            errors.append(f"event_time must be null or a strict ISO8601 timestamp, got {event_time!r}")

    # ---- closure_time (OPTIONAL extra field — nullable ISO8601 if present) ----
    if "closure_time" in case and case["closure_time"] is not None:
        ct = case["closure_time"]
        if not _is_str(ct) or not _ISO8601_RE.match(ct):
            errors.append(f"closure_time must be null or a strict ISO8601 timestamp, got {ct!r}")
        elif event_time is not None and _ISO8601_RE.match(event_time) and ct < event_time:
            errors.append(f"closure_time {ct!r} is BEFORE event_time {event_time!r} — "
                          f"a case cannot be closed before it happened")

    # ---- source ----
    if not _is_nonempty_str(case["source"]):
        errors.append("source must be a non-empty string")

    # ---- alert / observables / fixtures (structural only — content
    # sanitization is a separate build-time concern, see scan_case_for_secrets()) ----
    if not isinstance(case["alert"], dict):
        errors.append("alert must be a dict")
    if not isinstance(case["observables"], list):
        errors.append("observables must be a list")
    else:
        for i, obs in enumerate(case["observables"]):
            if not isinstance(obs, dict) or "dataType" not in obs or "data" not in obs:
                errors.append(f"observables[{i}] must be a dict with at least dataType/data")
            elif "tags" in obs and not isinstance(obs["tags"], list):
                errors.append(f"observables[{i}].tags must be a list if present")
    if not isinstance(case["fixtures"], dict):
        errors.append("fixtures must be a dict")

    # ---- rag_snapshot_ref (nullable string) ----
    if case["rag_snapshot_ref"] is not None and not _is_str(case["rag_snapshot_ref"]):
        errors.append("rag_snapshot_ref must be null or a string")

    # ---- dataset_version / policy_version_frozen_against ----
    if not _is_nonempty_str(case["dataset_version"]):
        errors.append("dataset_version must be a non-empty string")
    if not _is_nonempty_str(case["policy_version_frozen_against"]):
        errors.append("policy_version_frozen_against must be a non-empty string")

    # ---- label_source (closed allowlist + defense-in-depth denylist) ----
    label_source = case["label_source"]
    if label_source not in LABEL_SOURCES:
        errors.append(f"label_source {label_source!r} not in the allowed set {sorted(LABEL_SOURCES)} "
                      f"— ground truth must never be derived from the policy under evaluation")
    elif any(bad in label_source.lower() for bad in _FORBIDDEN_LABEL_SOURCE_SUBSTRINGS):
        errors.append(f"label_source {label_source!r} matches a forbidden pattern "
                      f"({_FORBIDDEN_LABEL_SOURCE_SUBSTRINGS}) — circular ground truth is never allowed")

    # ---- label_confidence ----
    if case["label_confidence"] not in LABEL_CONFIDENCE_LEVELS:
        errors.append(f"label_confidence {case['label_confidence']!r} not in {sorted(LABEL_CONFIDENCE_LEVELS)}")

    # ---- review_status + its cross-field consequences ----
    review_status = case["review_status"]
    if review_status not in REVIEW_STATUSES:
        errors.append(f"review_status {review_status!r} not in {sorted(REVIEW_STATUSES)}")

    if review_status == "approved":
        if not _is_nonempty_str(case["reviewed_by"]):
            errors.append("review_status is 'approved' but reviewed_by is missing/empty")
        if not _is_nonempty_str(case["reviewed_at"]) or not _ISO8601_RE.match(case["reviewed_at"] or ""):
            errors.append("review_status is 'approved' but reviewed_at is missing or not ISO8601")
        if case["expected_tier"] is None:
            errors.append("review_status is 'approved' but expected_tier is null — "
                          "an approved case must have a definite expected outcome")

    if review_status == "disputed" and case["expected_tier"] not in (None, "L2"):
        errors.append(f"review_status is 'disputed' but expected_tier is {case['expected_tier']!r} "
                      f"— disputed cases must default to L2 (or null), never L1 ground truth")

    if event_time is None and review_status not in ("pending", "excluded"):
        errors.append(f"event_time is null but review_status is {review_status!r} — a case "
                      f"without an event_time cannot be approved/disputed (temporal RAG rules need it)")

    # ---- reviewed_by / reviewed_at type checks (nullable otherwise) ----
    if case["reviewed_by"] is not None and not _is_str(case["reviewed_by"]):
        errors.append("reviewed_by must be null or a string")
    if case["reviewed_at"] is not None:
        if not _is_str(case["reviewed_at"]) or not _ISO8601_RE.match(case["reviewed_at"]):
            errors.append(f"reviewed_at must be null or a strict ISO8601 timestamp, got {case['reviewed_at']!r}")

    # ---- label_notes ----
    if not _is_str(case["label_notes"]):
        errors.append("label_notes must be a string (may be empty)")

    # ---- expected_tier ----
    if case["expected_tier"] not in (None, "L1", "L2"):
        errors.append(f"expected_tier must be null, 'L1', or 'L2', got {case['expected_tier']!r}")

    # ---- reason-code fields, cross-checked against the REAL enum, never hardcoded ----
    valid_codes = set(l1_policy.REASON_CODES)
    epr = case["expected_primary_reason"]
    if epr is not None and epr not in valid_codes:
        errors.append(f"expected_primary_reason {epr!r} is not a known l1_policy.Reason code")

    for field_name in ("required_reason_codes", "forbidden_reason_codes"):
        val = case[field_name]
        if not isinstance(val, list):
            errors.append(f"{field_name} must be a list")
            continue
        bad = [c for c in val if c not in valid_codes]
        if bad:
            errors.append(f"{field_name} contains unknown reason code(s): {bad}")

    if (set(case["required_reason_codes"]) & set(case["forbidden_reason_codes"])) if (
        isinstance(case["required_reason_codes"], list) and isinstance(case["forbidden_reason_codes"], list)
    ) else False:
        overlap = sorted(set(case["required_reason_codes"]) & set(case["forbidden_reason_codes"]))
        errors.append(f"required_reason_codes and forbidden_reason_codes overlap: {overlap}")

    # ---- must_not_auto_contain / must_remain_open ----
    if not isinstance(case["must_not_auto_contain"], bool):
        errors.append("must_not_auto_contain must be a bool")
    if not isinstance(case["must_remain_open"], bool):
        errors.append("must_remain_open must be a bool")

    return errors


def assert_valid_case(case: dict) -> None:
    errors = validate_case(case)
    if errors:
        raise DatasetValidationError(errors)


def canonical_json(obj) -> str:
    """Deterministic JSON serialization — sorted keys, fixed separators, no
    locale/whitespace ambiguity — so the SAME logical content always
    produces the SAME bytes, regardless of dict insertion order. The basis
    for every content hash and manifest checksum in Phase 7."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def case_content_hash(case: dict) -> str:
    """SHA-256 over a NORMALIZED SUBSET of fields — observables + alert +
    source — deliberately excluding mutable review/label metadata
    (review_status, label_notes, reviewed_by/at can all change over time
    without the underlying INCIDENT changing). This is the duplicate-
    detection hash (§4 of the Phase 7 plan): two case records with the same
    content hash describe the same underlying incident content, regardless
    of when/how they were labeled."""
    import sanitization
    normalized = {"alert": case.get("alert"), "observables": case.get("observables"),
                 "source": case.get("source")}
    return sanitization.sha256_hex(canonical_json(normalized))


def validate_manifest(manifest: dict) -> list:
    """Validate a Phase 7 dataset manifest (the frozen split record — see
    rag_snapshot.py's write_manifest()). Returns a list of error strings."""
    errors = []
    if not isinstance(manifest, dict):
        return ["manifest must be a dict"]
    required = {"manifest_version", "dataset_name", "dataset_version", "schema_version",
               "built_at", "case_count", "cases", "policy_version_frozen_against"}
    missing = required - set(manifest.keys())
    if missing:
        errors.append(f"manifest missing required field(s): {sorted(missing)}")
        return errors
    if manifest["schema_version"] not in SUPPORTED_SCHEMA_VERSIONS:
        errors.append(f"manifest schema_version {manifest['schema_version']!r} not in "
                      f"{sorted(SUPPORTED_SCHEMA_VERSIONS)}")
    if not isinstance(manifest["cases"], dict):
        errors.append("manifest.cases must be a dict of case_uid -> {content_hash, incident_group_id}")
        return errors
    if manifest["case_count"] != len(manifest["cases"]):
        errors.append(f"case_count {manifest['case_count']} != len(cases) {len(manifest['cases'])}")
    for case_uid, entry in manifest["cases"].items():
        if not isinstance(entry, dict) or "content_hash" not in entry or "incident_group_id" not in entry:
            errors.append(f"manifest.cases[{case_uid!r}] must have content_hash and incident_group_id")
    return errors


_DISPOSITION_HINT_RE = re.compile(r"historical disposition '(\w+)' is a CANDIDATE label")


def extract_historical_disposition_hint(case: dict):
    """
    BEST-EFFORT, NON-AUTHORITATIVE extraction of the raw historical
    disposition from a record's `label_notes` prose.

    Found live (Phase 7C, 2026-08-21): `rag_snapshot.export_case_from_
    thehive_record()` (Phase 7B) never persisted the raw historical
    disposition as its own structured field — only `must_not_auto_contain`
    (a derived boolean that collapses "Other" and "TruePositive" into the
    same False value, losing the distinction) and this human-readable
    sentence in `label_notes`.

    SUPERSEDED as an authoritative source by Phase 7D's schema v2
    `historical_disposition` field (see `get_authoritative_historical_
    disposition()` below) — this function is kept ONLY for v1-record
    display/backward compatibility (the 226 Phase 7C-era candidates still on
    schema v1 are never modified or re-exported by Phase 7D). It must NEVER
    be used as the authoritative source for any NEW decision, and the review
    tool no longer calls it on that path — see review_rubric.py /
    review_dataset.py.

    Returns the disposition string (e.g. "TruePositive") or None if the
    pattern isn't found (e.g. for the golden-seven, which never had this
    sentence at all — they use a different, structured `ground_truth` block
    instead).
    """
    m = _DISPOSITION_HINT_RE.search(case.get("label_notes") or "")
    return m.group(1) if m else None


def get_authoritative_historical_disposition(case: dict):
    """
    Phase 7D — the ONE authoritative path to a case's historical
    disposition. Returns the structured `historical_disposition` field for a
    schema-v2 record; returns None for a schema-v1 record, ALWAYS — a v1
    record's disposition is never treated as authoritative, even though
    `extract_historical_disposition_hint()` can still recover a non-
    authoritative hint from its prose for display purposes only.

    This is the prohibition the review tool enforces: prose-derived text can
    be SHOWN to a reviewer as non-authoritative context, but only this
    function's return value may ever be treated as ground-truth-eligible
    historical disposition.
    """
    if case.get("schema_version") == SCHEMA_VERSION_V2:
        return case.get("historical_disposition")
    return None
