#!/usr/bin/env python3
"""
Phase 7C — the human review rubric, encoded as enforceable rules, not just
documentation. Side-effect-free (no network, no file I/O beyond what its
caller does).

Deliberately NOT a reimplementation of l1_policy.py's actual gate logic —
that would let a reviewer (or this tool) derive expected outcomes from the
very policy being evaluated, which is circular ground truth (explicitly
forbidden). Every check here is a GENERIC, policy-INDEPENDENT evidentiary
question: does investigation evidence objectively exist in the record at
all, not "would l1_policy.py's specific gates pass."

Rubric (documented in full at
ai/testset/dataset_b_candidates/REVIEW_RUBRIC.md):
  1. A historical TruePositive does NOT automatically mean L1.
  2. L1 is expected only when independently-defined positive evidence
     supports it (not merely the absence of a red flag).
  3. Missing analyzer evidence, missing corroboration, an ambiguous target,
     a policy refusal, conflicting history, or unavailable verification all
     imply expected L2.
  4. FalsePositive/Other/disputed historical dispositions require explicit
     review, never a rubber stamp.
  5. Uncertainty defaults to L2.
  6. A case with required evidence missing cannot be approved as L1.
  7. No case contributes to a safety metric until `review_status ==
     "approved"`.
"""
import dataset_schema as ds
import replay_harness as rh

# Only EXTERNALLY EVALUABLE policy-decision reason codes are ever offered to
# a human reviewer — operational/recovery, assignment/notification, and
# internal-not-reachable codes remain covered by this project's existing
# test suite, never forced into a human label (Phase 7 mandatory correction).
EXTERNALLY_EVALUABLE_REASON_CODES = frozenset(
    code for code, category in rh.REASON_CODE_CLASSIFICATION.items()
    if category == rh.POLICY_DECISION
)

VALID_REVIEW_STATUSES = {"approved", "disputed", "excluded"}
VALID_TIERS = {"L1", "L2", None}
VALID_CONFIDENCE = {"high", "medium", "low"}


def evaluate_positive_gate_checklist(record: dict) -> dict:
    """
    A policy-INDEPENDENT checklist of objective, evidence-only facts about
    the record — generic investigative-completeness questions, never a
    reproduction of any specific l1_policy.py threshold or gate name.
    """
    fixtures = record.get("fixtures") or {}
    observables = record.get("observables") or []
    ip_obs = [o for o in observables if o.get("dataType") == "ip"]
    return {
        "has_any_investigation_fixture": bool(fixtures),
        "has_unambiguous_ip_target": len(ip_obs) == 1 or (
            len(ip_obs) > 1 and len({o.get("data") for o in ip_obs
                                     if "src" in (o.get("tags") or [])}) == 1),
        "has_multiple_unlabeled_ip_observables": len(ip_obs) > 1 and not any(
            "src" in (o.get("tags") or []) or "dst" in (o.get("tags") or []) for o in ip_obs),
        "has_event_time": record.get("event_time") is not None,
        "has_closure_time": bool(record.get("closure_time")),
        # Phase 7D: AUTHORITATIVE only — a schema-v2 record's structured
        # field, never the v1 prose extractor (see dataset_schema.
        # get_authoritative_historical_disposition()). A v1 record without
        # the structured field correctly shows False here, even if the
        # (non-authoritative) prose hint could technically be recovered —
        # that hint is display-only, never fed into this checklist.
        "historical_disposition_available": ds.get_authoritative_historical_disposition(record) is not None,
    }


def validate_decision(record: dict, decision: dict) -> list:
    """
    Returns a list of rubric-violation strings — empty means the decision is
    acceptable. This is a HARD gate: the review CLI refuses to save a
    decision that fails this, never a soft warning.
    """
    errors = []

    status = decision.get("review_status")
    tier = decision.get("expected_tier")
    confidence = decision.get("label_confidence")
    required = decision.get("required_reason_codes") or []
    forbidden = decision.get("forbidden_reason_codes") or []
    primary = decision.get("expected_primary_reason")
    reviewer_id = decision.get("reviewer_id")

    if status not in VALID_REVIEW_STATUSES:
        errors.append(f"review_status must be one of {sorted(VALID_REVIEW_STATUSES)}, got {status!r}")
    if tier not in VALID_TIERS:
        errors.append(f"expected_tier must be 'L1', 'L2', or null, got {tier!r}")
    if confidence not in VALID_CONFIDENCE:
        errors.append(f"label_confidence must be one of {sorted(VALID_CONFIDENCE)}, got {confidence!r}")
    if not reviewer_id or not str(reviewer_id).strip():
        errors.append("a reviewer identifier is required")

    # Rule: reason codes exposed to humans must be externally evaluable only.
    bad_codes = (set(required) | set(forbidden) | ({primary} if primary else set())) \
        - EXTERNALLY_EVALUABLE_REASON_CODES
    if bad_codes:
        errors.append(f"reason code(s) not in the externally-evaluable policy_decision set, "
                      f"never exposed to human labeling: {sorted(bad_codes)}")
    if set(required) & set(forbidden):
        errors.append(f"required_reason_codes and forbidden_reason_codes overlap: "
                      f"{sorted(set(required) & set(forbidden))}")

    if errors:  # can't meaningfully evaluate the rules below on malformed input
        return errors

    # Rule: disputed must default to L2 or null, never L1.
    if status == "disputed" and tier == "L1":
        errors.append("a disputed case must default to L2 or null — never approved as L1 ground truth")

    # Rule: excluded/disputed cases don't need a tier; approved cases DO.
    if status == "approved" and tier is None:
        errors.append("an approved case must have a definite expected_tier — uncertainty defaults to "
                      "L2, not to leaving the tier blank")

    # Rule: cannot approve L1 with required evidence missing — uncertainty
    # defaults to L2. "Required evidence" here means: SOME investigation
    # fixture exists AND the target is unambiguous — the same two objective,
    # policy-independent facts the checklist surfaces.
    if status == "approved" and tier == "L1":
        checklist = evaluate_positive_gate_checklist(record)
        missing = [k for k in ("has_any_investigation_fixture", "has_unambiguous_ip_target")
                  if not checklist[k]]
        if missing:
            errors.append(f"cannot approve as L1 — required evidence missing: {missing} "
                          f"(rubric: uncertainty must default to L2 for missing evidence)")

    return errors
