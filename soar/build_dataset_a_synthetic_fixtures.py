#!/usr/bin/env python3
"""
Phase 7D — Dataset A synthetic, specification-derived, frozen-fixture cases.

Every case's `expected_tier`/`expected_primary_reason`/`required_reason_
codes` was derived by READING l1_policy.py's gate docstrings and
REASON_CODE_CLASSIFICATION (replay_harness.py) — never by running
l1_policy.evaluate_l1_malicious_eligibility() and copying its output. That
distinction is checkable: this script never imports/calls
evaluate_l1_malicious_eligibility, l1_disposition, or run_policy_replay
anywhere.

label_source is "specification_derived_pending_human" for every case —
still `review_status: "pending"`, a human must confirm before this counts
as ground truth for any safety metric.

Every fixture is tagged `fixtures["_provenance"] = "synthetic"` — never
presented as historical/real. No real IP/email/credential/sensitive payload
anywhere (all IPs are RFC-precedented placeholder addresses already used
elsewhere in this codebase's own tests: 5.5.5.5-style digit-repeats, or
documented protected/RFC1918 lab addresses already public in
e2e_soc_orchestrator.py's PROTECTED_ASSETS list).

IMPORTANT, DOCUMENTED FINDING (surfaced, not hidden): of the 21 externally-
evaluable POLICY_DECISION reason codes, 8 are NOT reachable through the
current, real code path with ANY fixture design:
  - 6 are declared in l1_policy.Reason but never emitted by ANY function in
    this codebase today (grep-verified, zero emit sites beyond their own
    declaration): ATTACK_SIGNATURE_VETO, CASE_CLOSE_VERIFIED,
    HIGH_RISK_TECHNIQUE, PROMPT_INJECTION_SUSPECTED,
    RAG_INSUFFICIENT_HISTORY, STALE_EVIDENCE.
  - 2 ARE emitted in real production code, but specifically UNREACHABLE via
    replay_harness.run_policy_replay()'s current wiring: NOT_ARMED
    (_simulate_case hardcodes armed=True) and DUPLICATE_PROCESSING
    (_simulate_case never calls whatever records a tier decision, so the
    idempotency store never has a prior decision to find during replay).
Cases for all 8 are still built below (dataset-completeness coverage, per
build_reason_code_coverage_manifest()'s definition of "covered" — a case
declares the expectation, independent of whether a live replay can
currently confirm it) — each with a `label_notes` explaining the gap
plainly. This phase does NOT modify l1_policy.py/replay_harness.py to make
these reachable — that would be a policy/harness change, out of scope for
"dataset correction and evaluation-case preparation only".

Run: ./.venv/bin/python build_dataset_a_synthetic_fixtures.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dataset_schema as ds
import l1_policy
import replay_harness as rh

_HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(_HERE, "..", "ai", "testset", "dataset_a_synthetic")
RESULTS_DIR = os.path.join(_HERE, "..", "ai", "results")
DATASET_VERSION = "dataset-a-synthetic-v0-2026-08-21"

EVENT_TIME = "2026-08-21T12:00:00Z"


def _verdict(verdict, confidence, technique, reason, evidence, severity="high"):
    return {"verdict": verdict, "confidence": confidence, "severity": severity,
           "mitre_technique": technique, "reason": reason, "key_evidence": evidence}


def _analyzer_step(level="malicious"):
    return {"action": "run_analyzer",
           "result": {"status": "Success", "taxonomies": [
               {"level": level, "namespace": "synthetic", "predicate": "verdict", "value": level}]}}


def _analyzer_error_step():
    return {"action": "run_analyzer", "result": {"status": "Failure", "error": "analyzer timeout (synthetic)"}}


def _search_step(hint):
    return {"action": "search_past_cases", "result": {"hint": hint}}


def make_case(case_uid, title, description, *, severity, observables, fixtures,
             expected_tier, expected_primary_reason, required_reason_codes,
             must_not_auto_contain, label_notes, forbidden_reason_codes=None):
    fixtures = dict(fixtures)
    fixtures.setdefault("_provenance", "synthetic")
    return {
        "schema_version": ds.SCHEMA_VERSION,
        "case_uid": case_uid,
        "incident_group_id": f"grp-{case_uid}",
        "event_time": EVENT_TIME,
        "source": "specification-derived-synthetic",
        "alert": {"title": title, "description": description, "severity": severity},
        "observables": observables,
        "fixtures": fixtures,
        "rag_snapshot_ref": None,
        "dataset_version": DATASET_VERSION,
        "policy_version_frozen_against": l1_policy.POLICY_VERSION,
        "label_source": "specification_derived_pending_human",
        "label_confidence": "high",
        "review_status": "pending",
        "reviewed_by": None,
        "reviewed_at": None,
        "label_notes": label_notes,
        "expected_tier": expected_tier,
        "expected_primary_reason": expected_primary_reason,
        "required_reason_codes": required_reason_codes,
        "forbidden_reason_codes": forbidden_reason_codes or [],
        "must_not_auto_contain": must_not_auto_contain,
        "must_remain_open": True,
    }


def _ip_obs(attacker_ip):
    return [{"dataType": "ip", "data": attacker_ip, "tags": ["src"]},
           {"dataType": "ip", "data": "192.168.10.30", "tags": ["dst"]}]


R = l1_policy.Reason
CLEAN_TRACE = [_search_step("prior TruePositive case matched this indicator"), _analyzer_step("malicious")]
CLEAN_TOOLS = ["search_past_cases", "run_analyzer"]


def build_cases():
    cases = []

    # ---- A1-A5: five fully eligible L1 positive controls ----
    positive_specs = [
        ("a01-c2-beacon", "C2 Beacon Detected", "T1071.001", 0.90, "5.5.5.5"),
        ("a02-cobalt-strike", "Cobalt Strike C2 Traffic", "T1071.001", 0.92, "6.6.6.6"),
        ("a03-asyncrat", "AsyncRAT Beacon to known-bad host", "T1071.001", 0.95, "7.7.7.7"),
        ("a04-adaptixc2", "AdaptixC2 Callback observed", "T1071.001", 0.88, "9.9.9.9"),
        ("a05-c2-known-bad", "C2 Beacon to known-bad IP", "T1071.001", 0.99, "2.2.2.2"),
    ]
    for uid, title, technique, conf, ip in positive_specs:
        cases.append(make_case(
            uid, title=title, description=f"{title} — synthetic positive control.", severity=3,
            observables=_ip_obs(ip),
            fixtures={"verdict": _verdict("malicious", conf, technique,
                                          "beacon pattern matches known C2 signature",
                                          "periodic beacon + JA3 match"),
                     "trace": CLEAN_TRACE, "tools_used": CLEAN_TOOLS,
                     "containment_target": ip, "containment_executed": True},
            expected_tier="L1", expected_primary_reason=R.L1_TRUE_POSITIVE_CONTAINED,
            required_reason_codes=[R.L1_TRUE_POSITIVE_CONTAINED],
            must_not_auto_contain=False,
            label_notes="Positive control: every l1_policy.evaluate_l1_malicious_eligibility() gate "
                        "(schema valid, malicious verdict, confidence>=0.85, allowlisted rule+"
                        "T1071.001 technique, both required tools used, no tool errors, tool-derived "
                        "corroboration present, no conflicting history, unambiguous external target, "
                        "guard-allowed, not already processed, armed) is designed to pass per the "
                        "WRITTEN gate list in l1_policy.py's own docstring — independently verified "
                        "not executed."))

    # ---- A6: partial rule match -> RULE_NOT_L1_ELIGIBLE ----
    cases.append(make_case(
        "a06-partial-rule-match", "C2 beacon observed, unlisted variant",
        "Rule keyword matches ('c2 beacon') but the MITRE technique (T1071.004, DNS-based C2) is "
        "NOT in L1_ALLOWED_TECHNIQUES ({T1071.001} only).", severity=3, observables=_ip_obs("3.3.3.3"),
        fixtures={"verdict": _verdict("malicious", 0.90, "T1071.004", "DNS tunneling C2 pattern", "DNS beacon"),
                 "trace": CLEAN_TRACE, "tools_used": CLEAN_TOOLS,
                 "containment_target": "3.3.3.3", "containment_executed": False},
        expected_tier="L2", expected_primary_reason=R.RULE_NOT_L1_ELIGIBLE,
        required_reason_codes=[R.RULE_NOT_L1_ELIGIBLE], must_not_auto_contain=True,
        label_notes="Per l1_policy.py: rule_allowlisted requires BOTH a keyword match AND an "
                    "allowlisted technique; a partial match yields RULE_NOT_L1_ELIGIBLE (not "
                    "UNKNOWN_RULE, which is reserved for a total non-match) — spec-derived from the "
                    "gate's own conditional (`RULE_NOT_L1_ELIGIBLE if (rule_name_matches or "
                    "technique_allowlisted) else UNKNOWN_RULE`)."))

    # ---- A7: low confidence -> LOW_CONFIDENCE ----
    cases.append(make_case(
        "a07-low-confidence", "C2 Beacon Detected (low confidence)",
        "Same allowlisted rule/technique as the positive controls, confidence 0.80 — above the "
        "containment guard's 0.75 floor but below l1_policy's own tighter 0.85 floor.",
        severity=2, observables=_ip_obs("1.2.3.4"),
        fixtures={"verdict": _verdict("malicious", 0.80, "T1071.001", "beacon pattern, lower confidence",
                                      "single beacon observation"),
                 "trace": CLEAN_TRACE, "tools_used": CLEAN_TOOLS,
                 "containment_target": "1.2.3.4", "containment_executed": False},
        expected_tier="L2", expected_primary_reason=R.LOW_CONFIDENCE,
        required_reason_codes=[R.LOW_CONFIDENCE], must_not_auto_contain=True,
        label_notes="Spec-derived from L1_CONTAIN_MIN_CONFIDENCE=0.85 in l1_policy.py — 0.80 clears "
                    "the containment guard's separate 0.75 floor (so this isolates l1_policy's own "
                    "gate, not the guard's) but fails l1_policy's tighter threshold."))

    # ---- A8: non-allowlisted rule/technique -> UNKNOWN_RULE ----
    cases.append(make_case(
        "a08-sqli", "SQL Injection Attempt", "Classic SQLi payload against a web login form — no "
        "rule-keyword match, technique T1190 is not allowlisted at all.", severity=2,
        observables=_ip_obs("45.83.123.44"),
        fixtures={"verdict": _verdict("malicious", 0.93, "T1190", "SQLi payload in request body",
                                      "UNION SELECT pattern"),
                 "trace": CLEAN_TRACE, "tools_used": CLEAN_TOOLS,
                 "containment_target": "45.83.123.44", "containment_executed": False},
        expected_tier="L2", expected_primary_reason=R.UNKNOWN_RULE,
        required_reason_codes=[R.UNKNOWN_RULE], must_not_auto_contain=True,
        label_notes="Spec-derived: neither the rule-keyword allowlist nor the technique allowlist "
                    "matches at all -> UNKNOWN_RULE per l1_policy.py's own conditional."))

    # ---- A9: inconclusive verdict -> NOVEL_CASE ----
    cases.append(make_case(
        "a09-inconclusive", "Unusual outbound beaconing pattern, unclassified",
        "The verdict itself is 'inconclusive' — l1_disposition() escalates every non-malicious "
        "verdict to L2 (Phase 6); 'inconclusive' specifically maps to NOVEL_CASE.", severity=2,
        observables=_ip_obs("8.8.4.4"),
        fixtures={"verdict": _verdict("inconclusive", 0.50, "N/A", "pattern does not match a known "
                                      "technique", "ambiguous timing")},
        expected_tier="L2", expected_primary_reason=R.NOVEL_CASE,
        required_reason_codes=[R.NOVEL_CASE], must_not_auto_contain=True,
        label_notes="Spec-derived directly from agent_orchestrator.l1_disposition()'s non-malicious "
                    "branch: `NOVEL_CASE if v=='inconclusive' else UNKNOWN_RULE`."))

    # ---- A10: missing tool usage -> MISSING_EVIDENCE ----
    cases.append(make_case(
        "a10-missing-evidence", "C2 Beacon Detected, investigation incomplete",
        "Allowlisted rule/technique/confidence, but the trace shows only run_analyzer — "
        "search_past_cases was never called, failing REQUIRED_TOOLS_FOR_L1_CONTAIN.", severity=3,
        observables=_ip_obs("6.6.6.7"),
        fixtures={"verdict": _verdict("malicious", 0.95, "T1071.001", "beacon pattern", "JA3 match"),
                 "trace": [_analyzer_step("malicious")], "tools_used": ["run_analyzer"],
                 "containment_target": "6.6.6.7", "containment_executed": False},
        expected_tier="L2", expected_primary_reason=R.MISSING_EVIDENCE,
        required_reason_codes=[R.MISSING_EVIDENCE], must_not_auto_contain=True,
        label_notes="Spec-derived from REQUIRED_TOOLS_FOR_L1_CONTAIN = (search_past_cases, "
                    "run_analyzer) — BOTH required; only one used here."))

    # ---- A11: conflicting RAG history -> CONFLICTING_EVIDENCE + RAG_DISPOSITION_CONFLICT ----
    cases.append(make_case(
        "a11-conflicting-history", "C2 Beacon Detected, prior FalsePositive on record",
        "Otherwise clean positive-control shape, but search_past_cases surfaces a prior "
        "FalsePositive disposition for this same indicator.", severity=2,
        observables=_ip_obs("7.7.7.8"),
        fixtures={"verdict": _verdict("malicious", 0.90, "T1071.001", "beacon pattern", "JA3 match"),
                 "trace": [_search_step("prior FalsePositive disposition for this indicator"),
                          _analyzer_step("malicious")],
                 "tools_used": CLEAN_TOOLS, "containment_target": "7.7.7.8", "containment_executed": False},
        expected_tier="L2", expected_primary_reason=R.CONFLICTING_EVIDENCE,
        required_reason_codes=[R.CONFLICTING_EVIDENCE, R.RAG_DISPOSITION_CONFLICT],
        must_not_auto_contain=True,
        label_notes="Spec-derived: _has_conflicting_history() fires on a 'prior FalsePositive' "
                    "search hint, and l1_policy.py appends BOTH CONFLICTING_EVIDENCE and "
                    "RAG_DISPOSITION_CONFLICT together for that one gate — one case, two codes."))

    # ---- A12: tool failure -> TOOL_FAILURE ----
    cases.append(make_case(
        "a12-tool-failure", "C2 Beacon Detected, analyzer failed",
        "Otherwise clean positive-control shape, but the run_analyzer call itself errored.",
        severity=2, observables=_ip_obs("6.6.6.9"),
        fixtures={"verdict": _verdict("malicious", 0.90, "T1071.001", "beacon pattern", "JA3 match"),
                 "trace": [_search_step("prior TruePositive case matched this indicator"), _analyzer_error_step()],
                 "tools_used": CLEAN_TOOLS, "containment_target": "6.6.6.9", "containment_executed": False},
        expected_tier="L2", expected_primary_reason=R.TOOL_FAILURE,
        required_reason_codes=[R.TOOL_FAILURE], must_not_auto_contain=True,
        label_notes="Spec-derived from _any_tool_error() — a result dict with a truthy 'error' key "
                    "on any non-conclude action fails the no_tool_errors gate."))

    # ---- A13: malformed schema -> SCHEMA_INVALID (+ LOW_CONFIDENCE incidentally) ----
    cases.append(make_case(
        "a13-malformed-schema", "C2 Beacon Detected, malformed verdict",
        "The verdict dict IS present (so the harness's own malformed-case short-circuit does not "
        "fire) but its confidence field is non-numeric — fails _schema_valid().", severity=2,
        observables=_ip_obs("6.6.7.0"),
        fixtures={"verdict": {"verdict": "malicious", "confidence": "not-a-number", "severity": "high",
                              "mitre_technique": "T1071.001", "reason": "beacon pattern",
                              "key_evidence": "JA3 match"},
                 "trace": CLEAN_TRACE, "tools_used": CLEAN_TOOLS,
                 "containment_target": "6.6.7.0", "containment_executed": False},
        expected_tier="L2", expected_primary_reason=R.SCHEMA_INVALID,
        required_reason_codes=[R.SCHEMA_INVALID], must_not_auto_contain=True,
        label_notes="Spec-derived from _schema_valid()'s float(confidence) cast — a non-numeric "
                    "confidence fails schema validation AND, since the caught exception makes "
                    "conf default to 0.0, ALSO fails the confidence gate (LOW_CONFIDENCE may also "
                    "appear in a real run's reason_codes; SCHEMA_INVALID is the code this case is "
                    "specifically designed to demonstrate)."))

    # ---- A14: insufficient corroboration -> INSUFFICIENT_CORROBORATION ----
    cases.append(make_case(
        "a14-insufficient-corroboration", "C2 Beacon Detected, no corroborating signal",
        "Both required tools ARE used, but neither returns a corroborating signal: the analyzer "
        "comes back 'safe' and the history search finds no prior match.", severity=2,
        observables=_ip_obs("6.6.7.1"),
        fixtures={"verdict": _verdict("malicious", 0.90, "T1071.001", "beacon pattern", "JA3 match"),
                 "trace": [_search_step("no prior case matched this indicator"), _analyzer_step("safe")],
                 "tools_used": CLEAN_TOOLS, "containment_target": "6.6.7.1", "containment_executed": False},
        expected_tier="L2", expected_primary_reason=R.INSUFFICIENT_CORROBORATION,
        required_reason_codes=[R.INSUFFICIENT_CORROBORATION], must_not_auto_contain=True,
        label_notes="Spec-derived from _extract_corroboration(): a 'safe'-level analyzer taxonomy "
                    "and a search hint that doesn't start with 'prior TruePositive' both fail to "
                    "count as corroboration — count stays 0, below CORROBORATION_MIN_SOURCES=1. "
                    "Deliberately distinct from a10 (which fails on tool USE, not tool CONTENT)."))

    # ---- A15: ambiguous target -> AMBIGUOUS_TARGET (+ MISSING_EVIDENCE) ----
    cases.append(make_case(
        "a15-ambiguous-target", "C2 Beacon Detected, no resolvable target",
        "Otherwise clean positive-control shape, but no containment target could be determined "
        "(e.g. the only IP-typed observable is ambiguous/untagged).", severity=2,
        observables=[{"dataType": "ip", "data": "6.6.7.2", "tags": []}],
        fixtures={"verdict": _verdict("malicious", 0.90, "T1071.001", "beacon pattern", "JA3 match"),
                 "trace": CLEAN_TRACE, "tools_used": CLEAN_TOOLS,
                 "containment_target": None, "containment_executed": False},
        expected_tier="L2", expected_primary_reason=R.AMBIGUOUS_TARGET,
        required_reason_codes=[R.AMBIGUOUS_TARGET, R.MISSING_EVIDENCE], must_not_auto_contain=True,
        label_notes="Spec-derived: target_unambiguous gate fails when fixtures.containment_target "
                    "is falsy — l1_policy.py appends BOTH AMBIGUOUS_TARGET and MISSING_EVIDENCE for "
                    "that one gate failure."))

    # ---- A16: internal/private target refusal -> CONTAINMENT_REFUSED + PROTECTED_ASSET ----
    cases.append(make_case(
        "a16-private-target-refusal", "C2 Beacon Detected, target is an internal address",
        "Otherwise clean positive-control shape, but the resolved target (192.168.50.5) is an "
        "RFC1918 private address — policy_guard() refuses regardless of eligibility.", severity=2,
        observables=_ip_obs("192.168.50.5"),
        fixtures={"verdict": _verdict("malicious", 0.90, "T1071.001", "beacon pattern", "JA3 match"),
                 "trace": CLEAN_TRACE, "tools_used": CLEAN_TOOLS,
                 "containment_target": "192.168.50.5", "containment_executed": False},
        expected_tier="L2", expected_primary_reason=R.CONTAINMENT_REFUSED,
        required_reason_codes=[R.CONTAINMENT_REFUSED, R.PROTECTED_ASSET], must_not_auto_contain=True,
        label_notes="Spec-derived from agent_orchestrator.l1_disposition()'s final fallback branch: "
                    "when the guard refuses (here: policy_guard()'s RFC1918 check), eligibility is "
                    "never even computed and reason_codes is ALWAYS [CONTAINMENT_REFUSED, "
                    "PROTECTED_ASSET] together, regardless of the specific guard-refusal reason "
                    "text — this is the SAME final branch a PROTECTED_ASSETS-listed IP would hit."))

    # ---- A17: containment unverified -> CONTAINMENT_UNVERIFIED ----
    cases.append(make_case(
        "a17-containment-unverified", "C2 Beacon Detected, block not independently confirmed",
        "Fully eligible under every l1_policy gate, but the (Phase 2) independent pfSense "
        "verification of the block did not confirm it — falls back to L2 rather than closing L1.",
        severity=3, observables=_ip_obs("6.6.7.3"),
        fixtures={"verdict": _verdict("malicious", 0.95, "T1071.001", "beacon pattern", "JA3 match"),
                 "trace": CLEAN_TRACE, "tools_used": CLEAN_TOOLS,
                 "containment_target": "6.6.7.3", "containment_executed": False,
                 "containment_reason_code": "CONTAINMENT_UNVERIFIED"},
        expected_tier="L2", expected_primary_reason=R.CONTAINMENT_UNVERIFIED,
        required_reason_codes=[R.CONTAINMENT_UNVERIFIED], must_not_auto_contain=False,
        label_notes="Spec-derived from Phase 2's independent-verification requirement "
                    "(L1-L2-SAFETY-AUDIT.md §8): eligible + guard-allowed but NOT independently "
                    "verified contained falls back to L2 with CONTAINMENT_UNVERIFIED, never closes "
                    "L1 on Cortex's self-report alone. must_not_auto_contain=False (not True) "
                    "because the underlying verdict is genuinely malicious and correctly-eligible — "
                    "this is a 'not yet verified' state, not a 'must never contain' one; also "
                    "covers 'closure-verification failure -> L2 fallback' (containment verification "
                    "IS this policy's closure-verification step, per l1_disposition()'s own "
                    "docstring vocabulary)."))

    # ---- A18: duplicate/idempotent replay -> DUPLICATE_PROCESSING (harness-unreachable) ----
    cases.append(make_case(
        "a18-duplicate-processing", "C2 Beacon Detected, already processed",
        "Fully eligible under every l1_policy gate; this case's decision_key SHOULD already have a "
        "recorded tier decision from an earlier processing pass.", severity=2,
        observables=_ip_obs("6.6.7.4"),
        fixtures={"verdict": _verdict("malicious", 0.95, "T1071.001", "beacon pattern", "JA3 match"),
                 "trace": CLEAN_TRACE, "tools_used": CLEAN_TOOLS,
                 "containment_target": "6.6.7.4", "containment_executed": False},
        expected_tier="L2", expected_primary_reason=R.DUPLICATE_PROCESSING,
        required_reason_codes=[R.DUPLICATE_PROCESSING], must_not_auto_contain=False,
        label_notes="KNOWN HARNESS LIMITATION, spec-derived and documented, not fabricated: "
                    "l1_policy.evaluate_l1_malicious_eligibility()'s not_already_processed gate "
                    "reads idempotency.get_tier_decision(), but replay_harness._simulate_case() "
                    "NEVER calls whatever records a tier decision (recording is explicitly deferred "
                    "to the live caller, per l1_policy.py's own docstring) — so within a single "
                    "run_policy_replay() call, this gate can never actually be observed failing, "
                    "regardless of how the fixture is built. This case documents the INTENDED "
                    "outcome per the gate's written contract; a live replay of it today would show "
                    "predicted_tier=L1 (a documented mismatch, not a passing result) until the "
                    "harness is extended to simulate idempotency-store state across a batch — out "
                    "of scope for this phase (dataset preparation only, no harness changes)."))

    # ---- A19: not-armed execution -> NOT_ARMED (harness-unreachable) ----
    cases.append(make_case(
        "a19-not-armed", "C2 Beacon Detected, agent not armed",
        "Fully eligible under every l1_policy gate EXCEPT `armed` — the agent is running in "
        "dry-run/unarmed mode.", severity=2, observables=_ip_obs("6.6.7.5"),
        fixtures={"verdict": _verdict("malicious", 0.95, "T1071.001", "beacon pattern", "JA3 match"),
                 "trace": CLEAN_TRACE, "tools_used": CLEAN_TOOLS,
                 "containment_target": "6.6.7.5", "containment_executed": False},
        expected_tier="L2", expected_primary_reason=R.NOT_ARMED,
        required_reason_codes=[R.NOT_ARMED], must_not_auto_contain=False,
        label_notes="KNOWN HARNESS LIMITATION, spec-derived and documented, not fabricated: "
                    "l1_policy.evaluate_l1_malicious_eligibility()'s armed gate DOES emit NOT_ARMED "
                    "in real production use (armed=False), but replay_harness._simulate_case() "
                    "hardcodes armed=True for every replayed case (by design — replay evaluates "
                    "policy logic, not runtime arming state) — so this code is structurally "
                    "unreachable via run_policy_replay() specifically, though it IS reachable "
                    "in the live agent. Documents the intended, spec-correct outcome."))

    # ---- A20: verified containment and closure success -> CASE_CLOSE_VERIFIED (unimplemented) ----
    cases.append(make_case(
        "a20-close-verified", "C2 Beacon Detected, closure independently verified",
        "Represents the Phase 3 'verified TruePositive closure' success path — containment AND "
        "the subsequent case-closure step both independently verified.", severity=3,
        observables=_ip_obs("6.6.7.6"),
        fixtures={"verdict": _verdict("malicious", 0.97, "T1071.001", "beacon pattern", "JA3 match"),
                 "trace": CLEAN_TRACE, "tools_used": CLEAN_TOOLS,
                 "containment_target": "6.6.7.6", "containment_executed": True},
        expected_tier="L1", expected_primary_reason=R.CASE_CLOSE_VERIFIED,
        required_reason_codes=[R.CASE_CLOSE_VERIFIED], must_not_auto_contain=False,
        label_notes="KNOWN GAP, spec-derived and documented, not fabricated: l1_policy."
                    "evaluate_l1_closure_eligibility() (Phase 3) is the function that OUGHT to "
                    "emit a success-path code on verified closure, but grep-confirmed: "
                    "Reason.CASE_CLOSE_VERIFIED is declared and classified POLICY_DECISION, yet "
                    "NEVER actually appended to any reasons list anywhere in l1_policy.py or "
                    "agent_orchestrator.py today (a successful closure currently returns an EMPTY "
                    "reason_codes list, relying on eligible=True + already_closed alone). This case "
                    "documents the intended success-path label per the audit's own closure-"
                    "verification requirement; fixing the emission gap is a policy change, out of "
                    "scope here. Also NOT reachable via run_policy_replay() at all — closure "
                    "simulation isn't wired into batch replay (see replay_harness.py's own "
                    "docstring, Phase 7A scope)."))

    # ---- A21-A25: five codes never emitted anywhere in the current codebase ----
    unimplemented_specs = [
        ("a21-attack-signature-veto", R.ATTACK_SIGNATURE_VETO, "attack-signature veto",
         "is_attack_signature() (agent_orchestrator.py) already detects a known attack-class "
         "keyword match today, but ONLY adds an informational note string to the L2 escalation "
         "reason for a non-malicious verdict (Phase 6) — it never actually appends "
         "Reason.ATTACK_SIGNATURE_VETO to any reason_codes list, for a malicious OR non-malicious "
         "verdict. This case documents the intended veto behavior: a malicious verdict that ALSO "
         "matches a recognized attack-signature keyword should be explicitly vetoed from L1, "
         "distinct from an ordinary rule-not-eligible refusal."),
        ("a22-high-risk-technique", R.HIGH_RISK_TECHNIQUE, "high-risk MITRE technique veto",
         "Zero emit sites in the codebase today (grep-verified). Documents the intended behavior: "
         "a technique explicitly known to be high-risk (e.g. ransomware-associated encryption, "
         "T1486) should be vetoed from L1 auto-containment even if it were otherwise allowlisted — "
         "no such veto list exists in l1_policy.py yet; this is a genuine, currently-unimplemented "
         "gate the specification implies but the code doesn't yet enforce."),
        ("a23-prompt-injection", R.PROMPT_INJECTION_SUSPECTED, "prompt-injection suspected",
         "Zero emit sites in the codebase today (grep-verified). Documents the intended behavior: "
         "alert/observable content crafted to manipulate the LLM's own verdict (e.g. embedded "
         "instructions in a signature description) should be flagged and routed to L2, never "
         "silently trusted — no such detector exists in this codebase yet."),
        ("a24-rag-insufficient-history", R.RAG_INSUFFICIENT_HISTORY, "RAG insufficient history",
         "Zero emit sites in the codebase today (grep-verified) — DISTINCT from "
         "INSUFFICIENT_CORROBORATION (a14, which IS implemented and fires when the trace's own "
         "corroboration count is 0). This code's intended meaning per its name is broader: the "
         "RAG corpus itself has too few PRIOR cases on record for this indicator/technique to "
         "trust an automated decision at all, independent of what any single trace happened to "
         "return — a corpus-coverage gate, not a per-case evidence gate. Not implemented."),
        ("a25-stale-evidence", R.STALE_EVIDENCE, "stale evidence",
         "Zero emit sites in the codebase today (grep-verified). Documents the intended behavior: "
         "a tool result timestamped well before the current alert's event_time (e.g. reused/cached "
         "analyzer output from a much earlier run) should not count as fresh corroboration — no "
         "freshness/staleness check exists on trace results in l1_policy.py yet."),
    ]
    for uid, code, short, notes in unimplemented_specs:
        cases.append(make_case(
            uid, title=f"C2 Beacon Detected — {short} scenario (specification placeholder)",
            description=f"Placeholder case documenting the INTENDED, specification-derived "
                        f"behavior for {code} — see label_notes. Not reachable via any current "
                        f"code path; NOT a claim that the current policy produces this outcome.",
            severity=2, observables=_ip_obs("6.6.7.9"),
            fixtures={"verdict": _verdict("malicious", 0.90, "T1071.001", "beacon pattern", "JA3 match"),
                     "trace": CLEAN_TRACE, "tools_used": CLEAN_TOOLS,
                     "containment_target": "6.6.7.9", "containment_executed": False},
            expected_tier="L2", expected_primary_reason=code, required_reason_codes=[code],
            must_not_auto_contain=True,
            label_notes=f"KNOWN GAP, spec-derived and documented, not fabricated. {notes} "
                        f"required_reason_codes intentionally references a code the CURRENT policy "
                        f"cannot yet produce — coverage here is definitional (this dataset case "
                        f"declares the expectation), not a claim of current reachability. Do not "
                        f"run policy replay against this case and treat a resulting mismatch as a "
                        f"bug in the case; it is the documented, expected state of a not-yet-"
                        f"implemented gate."))

    return cases


def main():
    cases = build_cases()
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    errors_by_case = {}
    for case in cases:
        errs = ds.validate_case(case)
        if errs:
            errors_by_case[case["case_uid"]] = errs
    if errors_by_case:
        sys.exit(f"VALIDATION FAILED — aborting write:\n{json.dumps(errors_by_case, indent=2)}")

    import sanitization as san
    secret_hits = [c["case_uid"] for c in cases if san.contains_unredacted_secret(ds.canonical_json(c))]
    if secret_hits:
        sys.exit(f"SECRET SCAN FAILED for: {secret_hits} — aborting write")

    for case in cases:
        out_path = os.path.join(OUTPUT_DIR, f"{case['case_uid']}.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(case, fh, indent=2, sort_keys=True)
            fh.write("\n")

    import rag_snapshot as rs
    manifest = rs.write_manifest(cases, dataset_name="dataset-a-synthetic",
                                 dataset_version=DATASET_VERSION,
                                 policy_version_frozen_against=l1_policy.POLICY_VERSION)
    with open(os.path.join(OUTPUT_DIR, "MANIFEST.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")

    # ---- Coverage matrix ----
    classification = rh.classify_reason_codes()
    policy_codes = {c for c, cat in classification.items() if cat == rh.POLICY_DECISION}
    covered = set()
    reachable_via_replay = set()
    for c in cases:
        codes_here = set(c["required_reason_codes"])
        if c["expected_primary_reason"]:
            codes_here.add(c["expected_primary_reason"])
        covered |= codes_here
        if "KNOWN HARNESS LIMITATION" not in c["label_notes"] and "KNOWN GAP" not in c["label_notes"]:
            reachable_via_replay |= codes_here

    coverage = {
        "total_policy_decision_codes": len(policy_codes),
        "covered_by_dataset": sorted(policy_codes & covered),
        "missing_from_dataset": sorted(policy_codes - covered),
        "covered_and_reachable_via_current_replay_harness": sorted(policy_codes & reachable_via_replay),
        "covered_but_NOT_reachable_via_current_replay_harness":
            sorted((policy_codes & covered) - reachable_via_replay),
        "case_count": len(cases),
    }
    with open(os.path.join(RESULTS_DIR, "phase7d-dataset-a-coverage-matrix.json"), "w", encoding="utf-8") as fh:
        json.dump(coverage, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print(f"{len(cases)} Dataset A synthetic cases written to {OUTPUT_DIR}")
    print(f"manifest_hash: {manifest['manifest_hash']}")
    print(json.dumps(coverage, indent=2))
    return cases, coverage


if __name__ == "__main__":
    main()
