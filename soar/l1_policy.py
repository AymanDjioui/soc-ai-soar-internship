#!/usr/bin/env python3
"""
Deterministic L1 malicious-containment eligibility policy (Phase 1).

Positive-selection ONLY. An alert is eligible for automatic containment when every
gate below explicitly passes — absence of a red flag is never sufficient. This
replaces the earlier "allow unless a keyword blacklist matches" shape for the
CONTAINMENT path (see L1-L2-SAFETY-AUDIT.md for the full audit this responds to).

Reused, UNCHANGED, never reimplemented here: `containment_allowed()` /
`policy_guard()` / `kill_switch_active()` / `select_containment_target()` from
`e2e_soc_orchestrator.py`. Those already enforce: confidence floor (0.75),
RFC1918/CGNAT/Tailscale/protected-asset refusal, kill switch, rate limit. This
module only ADDS the tighter, agent-specific gates the audit found missing: rule
allowlist, evidence completeness, corroboration, conflict detection, idempotency,
and an explicit "armed" requirement.

Deliberately narrow. Phase 1's own instruction: "do not guess a broad allowlist."
The only rule proposed here is the one with actual validated evidence — see
L1_ALLOWED_TECHNIQUES below. Anything else routes to L2 by construction.

NOT YET WIRED (later phases, not this one):
  - independent pfSense verification of the block (Phase 2) — closure still
    trusts Cortex's own reported status, same as before this phase.
  - real L2 assignment / email matrix (Phase 3-5).
  - the full armed-mode preflight / demo-cutoff machinery (Phase 8/10) — this
    module only adds the narrow "SOAR_AGENT_MODE=armed" gate primitive.
"""
import os

import idempotency

POLICY_VERSION = "l1-policy-v1-2026-08-21"


# ==============================================================================
# Reason codes
# ==============================================================================

class Reason:
    L1_TRUE_POSITIVE_CONTAINED = "L1_TRUE_POSITIVE_CONTAINED"
    RULE_NOT_L1_ELIGIBLE = "RULE_NOT_L1_ELIGIBLE"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    UNKNOWN_RULE = "UNKNOWN_RULE"
    NOVEL_CASE = "NOVEL_CASE"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    TOOL_FAILURE = "TOOL_FAILURE"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    ATTACK_SIGNATURE_VETO = "ATTACK_SIGNATURE_VETO"
    HIGH_RISK_TECHNIQUE = "HIGH_RISK_TECHNIQUE"
    PROTECTED_ASSET = "PROTECTED_ASSET"
    CONTAINMENT_REFUSED = "CONTAINMENT_REFUSED"
    CONTAINMENT_UNVERIFIED = "CONTAINMENT_UNVERIFIED"
    RAG_INSUFFICIENT_HISTORY = "RAG_INSUFFICIENT_HISTORY"
    RAG_DISPOSITION_CONFLICT = "RAG_DISPOSITION_CONFLICT"
    L2_ASSIGNMENT_FAILED = "L2_ASSIGNMENT_FAILED"
    DUPLICATE_PROCESSING = "DUPLICATE_PROCESSING"
    PROMPT_INJECTION_SUSPECTED = "PROMPT_INJECTION_SUSPECTED"
    # Extra codes this module needs that weren't in the original 20-item list:
    AMBIGUOUS_TARGET = "AMBIGUOUS_TARGET"
    NOT_ARMED = "NOT_ARMED"
    INSUFFICIENT_CORROBORATION = "INSUFFICIENT_CORROBORATION"
    # Phase 2 additions:
    CONTAINMENT_ALREADY_PRESENT = "CONTAINMENT_ALREADY_PRESENT"
    PFSTATE_QUERY_FAILED = "PFSTATE_QUERY_FAILED"
    # Phase 2.5 addition:
    CONTAINMENT_STATE_CONFLICT = "CONTAINMENT_STATE_CONFLICT"
    # Phase 3 additions:
    CASE_CLOSE_VERIFIED = "CASE_CLOSE_VERIFIED"
    CASE_ALREADY_CLOSED_TRUE_POSITIVE = "CASE_ALREADY_CLOSED_TRUE_POSITIVE"
    CASE_DISPOSITION_CONFLICT = "CASE_DISPOSITION_CONFLICT"
    CASE_ALREADY_ESCALATED_L2 = "CASE_ALREADY_ESCALATED_L2"
    CASE_COMMENT_FAILED = "CASE_COMMENT_FAILED"
    CASE_CLOSE_FAILED = "CASE_CLOSE_FAILED"
    CASE_CLOSE_AMBIGUOUS = "CASE_CLOSE_AMBIGUOUS"
    CASE_STATE_QUERY_FAILED = "CASE_STATE_QUERY_FAILED"
    CONTAINMENT_RECORD_MISSING = "CONTAINMENT_RECORD_MISSING"
    CONTAINMENT_TARGET_MISMATCH = "CONTAINMENT_TARGET_MISMATCH"
    # Phase 4 additions (L2_ASSIGNMENT_FAILED already existed in the original list):
    L2_ASSIGNMENT_VERIFIED = "L2_ASSIGNMENT_VERIFIED"
    L2_ALREADY_ASSIGNED = "L2_ALREADY_ASSIGNED"
    L2_ASSIGNED_TO_EXISTING_ANALYST = "L2_ASSIGNED_TO_EXISTING_ANALYST"
    L2_USER_NOT_FOUND = "L2_USER_NOT_FOUND"
    L2_USER_AMBIGUOUS = "L2_USER_AMBIGUOUS"
    L2_USER_DISABLED = "L2_USER_DISABLED"
    L2_ASSIGNMENT_AMBIGUOUS = "L2_ASSIGNMENT_AMBIGUOUS"
    L2_ASSIGNMENT_VERIFY_FAILED = "L2_ASSIGNMENT_VERIFY_FAILED"
    L2_COMMENT_FAILED = "L2_COMMENT_FAILED"
    L2_CASE_NOT_OPEN = "L2_CASE_NOT_OPEN"
    L2_SKIPPED_VERIFIED_L1_CLOSURE = "L2_SKIPPED_VERIFIED_L1_CLOSURE"
    # Phase 5 additions — notification result terminology. NOTIFICATION_ACCEPTED
    # means only the responder/job's own success could be verified; this
    # module NEVER has a DELIVERY_VERIFIED reason code that gets set
    # automatically, because no code path here can programmatically confirm
    # actual mailbox receipt (see agent_orchestrator.py's module docstring).
    NOTIFICATION_ACCEPTED = "NOTIFICATION_ACCEPTED"
    NOTIFICATION_FAILED = "NOTIFICATION_FAILED"
    NOTIFICATION_AMBIGUOUS = "NOTIFICATION_AMBIGUOUS"
    NOTIFICATION_ALREADY_SENT = "NOTIFICATION_ALREADY_SENT"
    L1_NOTIFICATION_SKIPPED_UNVERIFIED = "L1_NOTIFICATION_SKIPPED_UNVERIFIED"
    # Phase 5.5 additions — the corrected recipient-tag flow can fail BEFORE
    # any responder is ever invoked; these are distinct from the generic
    # NOTIFICATION_FAILED so the audit trail shows exactly which stage refused.
    NOTIFICATION_RECIPIENT_CONFIG_MISSING = "NOTIFICATION_RECIPIENT_CONFIG_MISSING"
    NOTIFICATION_RECIPIENT_TAG_UNVERIFIED = "NOTIFICATION_RECIPIENT_TAG_UNVERIFIED"


REASON_CODES = sorted({v for k, v in vars(Reason).items() if not k.startswith("_")})


# ==============================================================================
# The narrow, initial allowlist — PROPOSAL, not yet approved for arming
# ==============================================================================
# The only technique with real, independently-verified evidence on record: the C2
# capture this week (case ~328003784 — MALICIOUS 0.9 T1071.001, guard-allowed,
# Cortex-confirmed block, manually pfctl-verified by Ayman) and the original C-1
# capture (Cobalt Strike C2, 68.64.183.127). Nothing else in this project has been
# independently verified at the firewall for an AUTONOMOUS (not human-armed) run.
# Do not add rules here without Ayman's explicit approval — Phase 1's own instruction.
L1_ALLOWED_TECHNIQUES = {
    "T1071.001",   # C2 beacon to a threat-intel-confirmed-malicious external IP
}
L1_ALLOWED_RULE_KEYWORDS = (
    "c2 beacon", "c2", "cobalt strike", "asyncrat", "adaptixc2",
)

# Both must appear in tools_used — deliberately strict: push the agent to actually
# check history AND pull live enrichment before an auto-block is even eligible.
REQUIRED_TOOLS_FOR_L1_CONTAIN = ("search_past_cases", "run_analyzer")

CORROBORATION_MIN_SOURCES = 1
L1_CONTAIN_MIN_CONFIDENCE = float(os.environ.get("SOAR_L1_CONTAIN_MIN_CONF", "0.85"))


# ==============================================================================
# Idempotency (gate 17) — now backed by the full composite idempotency store
# (idempotency.py), shared with containment/closure/assignment/email. Superseded
# the earlier audit-log-scan version: a dedicated per-decision-key record is more
# robust than grepping a shared JSONL log, and is now the single mechanism the
# whole L1/L2 pipeline uses (see idempotency.py's module docstring).
# ==============================================================================


# ==============================================================================
# The gate evaluation itself
# ==============================================================================

def _extract_corroboration(trace: list) -> int:
    """Count independent, tool-derived (not LLM-stated) signals corroborating
    'malicious'. Deliberately does NOT count the verdict's own reason/key_evidence
    text — that's the model's claim, not independent evidence."""
    count = 0
    for step in trace or []:
        action = step.get("action")
        result = step.get("result") or {}
        if action == "run_analyzer" and result.get("status") == "Success":
            for tax in result.get("taxonomies", []):
                if str(tax.get("level", "")).lower() in ("malicious", "suspicious"):
                    count += 1
                    break
        elif action == "search_past_cases":
            if str(result.get("hint", "")).startswith("prior TruePositive"):
                count += 1
    return count


def _has_conflicting_history(trace: list) -> bool:
    for step in trace or []:
        if step.get("action") == "search_past_cases":
            result = step.get("result") or {}
            if str(result.get("hint", "")).startswith("prior FalsePositive"):
                return True
    return False


def _any_tool_error(trace: list) -> bool:
    for step in trace or []:
        if step.get("action") in (None, "conclude"):
            continue
        result = step.get("result")
        if isinstance(result, dict) and result.get("error"):
            return True
    return False


def _schema_valid(verdict: dict) -> bool:
    required = ("verdict", "confidence", "severity", "mitre_technique", "reason", "key_evidence")
    if not isinstance(verdict, dict) or not all(f in verdict for f in required):
        return False
    if verdict.get("verdict") not in ("malicious", "benign", "inconclusive"):
        return False
    try:
        c = float(verdict.get("confidence"))
    except (TypeError, ValueError):
        return False
    return 0.0 <= c <= 1.0


def evaluate_l1_malicious_eligibility(verdict: dict, res: dict, alert: dict,
                                      alert_id: str, case_id: str, armed: bool,
                                      store_dir: str = None) -> dict:
    """
    Positive-eligibility gate for AUTOMATIC CONTAINMENT of a malicious verdict.
    Call this BEFORE attempting containment — its result decides whether
    containment is even attempted, not just whether the case later closes.

    `res` is the full dict returned by soc_agent.investigate() (has 'trace',
    'tools_used', 'containment'). `verdict` is res['verdict']. `armed` must be
    computed by the caller (SOAR_AGENT_DRY_RUN=0 AND SOAR_AGENT_MODE=armed).

    PURE / read-only with respect to the idempotency store: this function only
    READS `idempotency.get_tier_decision()` (gate 17) — it never records one.
    Recording happens explicitly, once, by the caller immediately after
    `l1_disposition()` computes the final tier — see agent_orchestrator.py.

    Returns {"eligible": bool, "reason_codes": [...], "gates": {name: bool},
             "policy_version": str, "decision_key": str}. Every failing gate
    contributes at least one reason code; nothing here mutates any external
    state (TheHive/Cortex/pfSense) or the idempotency store.
    """
    execution_mode = "armed" if armed else "dry_run"
    dkey = idempotency.decision_key(alert_id, case_id, POLICY_VERSION, execution_mode)
    reasons = []
    gates = {}

    # Gate: schema validation (defense in depth beyond soc_agent's own clamp).
    gates["schema_valid"] = _schema_valid(verdict)
    if not gates["schema_valid"]:
        reasons.append(Reason.SCHEMA_INVALID)

    # Gate: verdict is actually malicious (defense in depth — caller should
    # already only invoke this function on a malicious verdict).
    gates["verdict_malicious"] = (verdict or {}).get("verdict") == "malicious"
    if not gates["verdict_malicious"]:
        reasons.append(Reason.RULE_NOT_L1_ELIGIBLE)

    # Gate: confidence threshold (this module's own, tighter than the guard's 0.75).
    try:
        conf = float((verdict or {}).get("confidence") or 0.0)
    except (TypeError, ValueError):
        conf = 0.0
    gates["confidence_ok"] = conf >= L1_CONTAIN_MIN_CONFIDENCE
    if not gates["confidence_ok"]:
        reasons.append(Reason.LOW_CONFIDENCE)

    # Gate: rule + MITRE technique explicitly allowlisted (POSITIVE selection).
    technique = str((verdict or {}).get("mitre_technique", ""))
    title = str((alert or {}).get("title", "")).lower()
    tags = " ".join(str(t) for t in ((alert or {}).get("tags") or [])).lower()
    rule_name_matches = any(k in title or k in tags for k in L1_ALLOWED_RULE_KEYWORDS)
    technique_allowlisted = technique in L1_ALLOWED_TECHNIQUES
    gates["rule_allowlisted"] = rule_name_matches and technique_allowlisted
    if not gates["rule_allowlisted"]:
        reasons.append(Reason.RULE_NOT_L1_ELIGIBLE if (rule_name_matches or technique_allowlisted)
                       else Reason.UNKNOWN_RULE)

    # Gate: required investigation tools completed (evidence completeness).
    tools_used = res.get("tools_used") or []
    gates["required_tools_used"] = all(t in tools_used for t in REQUIRED_TOOLS_FOR_L1_CONTAIN)
    if not gates["required_tools_used"]:
        reasons.append(Reason.MISSING_EVIDENCE)

    # Gate: no tool call returned an outright error.
    trace = res.get("trace") or []
    gates["no_tool_errors"] = not _any_tool_error(trace)
    if not gates["no_tool_errors"]:
        reasons.append(Reason.TOOL_FAILURE)

    # Gate: threat-intel corroboration from a TOOL-DERIVED signal, not the LLM's
    # own stated reasoning. See docstring: first-ever sighting of a fresh IOC
    # with no history and clean live-analyzer results correctly fails this gate
    # and escalates to L2 — a human closing it TruePositive then builds the RAG
    # history that lets the SAME pattern pass this gate automatically next time.
    corroboration = _extract_corroboration(trace)
    gates["corroboration_ok"] = corroboration >= CORROBORATION_MIN_SOURCES
    if not gates["corroboration_ok"]:
        reasons.append(Reason.INSUFFICIENT_CORROBORATION)

    # Gate: no conflicting evidence (e.g. RAG history is predominantly FalsePositive).
    gates["no_conflicting_evidence"] = not _has_conflicting_history(trace)
    if not gates["no_conflicting_evidence"]:
        reasons.append(Reason.CONFLICTING_EVIDENCE)
        reasons.append(Reason.RAG_DISPOSITION_CONFLICT)

    # Gate: unambiguous attacker IP + the unchanged guard already allowed it
    # (external/routable/not protected/kill-switch/rate-limit/confidence-floor —
    # all already enforced inside containment_allowed(), reused not duplicated).
    containment = res.get("containment") or {}
    target_ip = containment.get("target")
    guard_allowed = bool(containment.get("allowed"))
    gates["target_unambiguous"] = bool(target_ip)
    if not gates["target_unambiguous"]:
        reasons.append(Reason.AMBIGUOUS_TARGET)
        reasons.append(Reason.MISSING_EVIDENCE)
    gates["guard_allowed"] = guard_allowed
    if not guard_allowed:
        reasons.append(Reason.CONTAINMENT_REFUSED)

    # Gate: idempotency — this decision key has not already received a tier
    # decision (composite store, shared with containment/closure/assignment/
    # email — see idempotency.py). Raises IdempotencyError on a corrupted
    # record, which the caller must treat as a hard failure (fail closed), not
    # catch-and-proceed.
    prior_tier = idempotency.get_tier_decision(
        dkey, store_dir=store_dir or idempotency.DEFAULT_STORE_DIR)
    gates["not_already_processed"] = prior_tier is None
    if prior_tier is not None:
        reasons.append(Reason.DUPLICATE_PROCESSING)

    # Gate: explicitly armed. No implicit/default arming.
    gates["armed"] = bool(armed)
    if not armed:
        reasons.append(Reason.NOT_ARMED)

    eligible = all(gates.values())
    seen = set()
    reasons = [r for r in reasons if not (r in seen or seen.add(r))]

    return {"eligible": eligible, "reason_codes": reasons, "gates": gates,
            "policy_version": POLICY_VERSION, "decision_key": dkey,
            "execution_mode": execution_mode}


# ==============================================================================
# Phase 3 — positive eligibility gate for VERIFIED TruePositive closure
# ==============================================================================
# Same shape/philosophy as evaluate_l1_malicious_eligibility() above: every gate
# must explicitly pass; absence of a red flag is never sufficient. PURE / read-
# only — this function never claims, completes, or PATCHes anything. It reads
# the idempotency store (containment + tier-decision + prior-closure records)
# and calls the injected `case_state_fn` (read-only GET) once. The caller
# (agent_orchestrator.close_l1_verified) performs the actual claim → comment →
# PATCH → re-verify → complete sequence only after this gate says eligible.

CASE_STATUS_TRUE_POSITIVE = "TruePositive"
CASE_STATUS_CONFLICTING = ("FalsePositive", "Other", "Indeterminate")


def evaluate_l1_closure_eligibility(alert_id: str, case_id: str, dkey: str,
                                    verdict: dict, containment_result: dict,
                                    case_state_fn, store_dir: str = None) -> dict:
    """
    Positive-eligibility gate for Phase 3 verified TruePositive closure.

    `containment_result` is the dict returned by `execute_and_verify_
    containment()` (Phase 2) — its `audit.idempotency_key` is used to look up
    the authoritative containment record; its `audit.target_ip` is compared
    against that record's own `detail.target` for consistency (gate 4).
    `case_state_fn(case_id)` is a REQUIRED injectable (no default — this module
    stays pure/network-free) that returns a dict with at least a `status` key,
    or raises/returns something falsy on failure.

    Returns {"eligible": bool, "already_closed": bool, "already_closed_by":
    str|None, "reason_codes": [...], "gates": {...}, "policy_version": str,
    "close_key": str, "case_state": dict|None}.

    `already_closed=True` is NOT a failure — it means Phase 3 closure has
    nothing left to do (either this exact workflow already completed it, or a
    human/prior run already set the case to TruePositive) and the caller
    should treat this as an idempotent success, never repeat the PATCH.
    """
    store_dir = store_dir or idempotency.DEFAULT_STORE_DIR
    close_key = idempotency.action_key(dkey, "closure", "verified-true-positive")
    reasons = []
    gates = {}

    # ---- Gate 1: ids valid ----
    gates["ids_valid"] = bool(alert_id) and bool(case_id)
    if not gates["ids_valid"]:
        reasons.append(Reason.SCHEMA_INVALID)

    # ---- Query current case state ONCE (requirement 7), used by the
    # already-closed short-circuit below AND by gates 8/9. ----
    try:
        case_state = case_state_fn(case_id)
    except Exception:
        case_state = None
    case_state_ok = isinstance(case_state, dict) and bool(case_state.get("status"))

    # ---- Idempotency short-circuit #1: OUR OWN prior run already completed
    # this exact verified closure — do not repeat, do not re-PATCH, no error. ----
    prior_closure = idempotency.get_status(close_key, store_dir=store_dir)
    if prior_closure is not None and prior_closure.get("status") == idempotency.STATUS_COMPLETED:
        return {"eligible": True, "already_closed": True, "already_closed_by": "this_workflow",
                "reason_codes": [Reason.CASE_ALREADY_CLOSED_TRUE_POSITIVE],
                "gates": {"already_completed_by_workflow": True},
                "policy_version": POLICY_VERSION, "close_key": close_key,
                "case_state": case_state}

    # ---- Idempotency short-circuit #2: the LIVE case is already TruePositive
    # even though OUR closure key was never claimed — a human (or a prior run
    # whose completion record was lost) already reached the same disposition.
    # Adopt it as a fact, don't re-PATCH, don't error. ----
    if case_state_ok and case_state.get("status") == CASE_STATUS_TRUE_POSITIVE:
        return {"eligible": True, "already_closed": True, "already_closed_by": "human_or_prior_run",
                "reason_codes": [Reason.CASE_ALREADY_CLOSED_TRUE_POSITIVE],
                "gates": {"already_true_positive_live": True},
                "policy_version": POLICY_VERSION, "close_key": close_key,
                "case_state": case_state}

    # ---- Gate 2: the immutable tier decision for this case says L1 ----
    tier = idempotency.get_tier_decision(dkey, store_dir=store_dir)
    gates["tier_is_l1"] = tier == "L1"
    if tier == "L2":
        reasons.append(Reason.CASE_ALREADY_ESCALATED_L2)
    elif tier != "L1":
        reasons.append(Reason.CASE_DISPOSITION_CONFLICT)

    # ---- Gate 3: verdict is actually malicious (defense in depth) ----
    gates["verdict_malicious"] = (verdict or {}).get("verdict") == "malicious"
    if not gates["verdict_malicious"]:
        reasons.append(Reason.RULE_NOT_L1_ELIGIBLE)

    # ---- Gates 4-5: containment record exists, is COMPLETED+verified, and its
    # recorded target matches the target this closure is being requested for. ----
    audit = (containment_result or {}).get("audit") or {}
    target_ip = audit.get("target_ip")
    c_key = audit.get("idempotency_key")
    containment_record = idempotency.get_status(c_key, store_dir=store_dir) if c_key else None
    c_detail = (containment_record or {}).get("detail") or {}
    gates["containment_verified"] = bool(
        containment_record is not None
        and containment_record.get("status") == idempotency.STATUS_COMPLETED
        and c_detail.get("executed") is True)
    if not gates["containment_verified"]:
        reasons.append(Reason.CONTAINMENT_RECORD_MISSING if containment_record is None
                       else Reason.CONTAINMENT_UNVERIFIED)

    gates["target_consistent"] = bool(target_ip) and c_detail.get("target") == target_ip
    if not gates["target_consistent"]:
        reasons.append(Reason.CONTAINMENT_TARGET_MISMATCH)

    # ---- Gate 6: closure idempotency not already completed — re-confirmed here
    # (belt-and-braces on top of the short-circuit above, which already
    # returned early if it were true; this keeps the gate visible in `gates`
    # for audit completeness even though it can never be the one gate that
    # fails given the short-circuit ordering). ----
    gates["closure_not_already_completed"] = prior_closure is None or \
        prior_closure.get("status") != idempotency.STATUS_COMPLETED

    # ---- Gate 7: case-state query itself succeeded ----
    gates["case_state_query_ok"] = case_state_ok
    if not case_state_ok:
        reasons.append(Reason.CASE_STATE_QUERY_FAILED)

    # ---- Gates 8-9: live case isn't already escalated/conflictingly disposed.
    # (Real L2 case-assignment fields don't exist yet — Phase 4, not built —
    # so "not already escalated" is judged from the immutable tier record
    # (gate 2) plus, here, the live case not already carrying a conflicting
    # terminal disposition a human gave it.) Only evaluated when the query
    # itself succeeded, to avoid stacking a second reason code on top of
    # CASE_STATE_QUERY_FAILED for the same underlying failure. ----
    if case_state_ok:
        gates["no_conflicting_disposition"] = case_state.get("status") not in CASE_STATUS_CONFLICTING
        if not gates["no_conflicting_disposition"]:
            reasons.append(Reason.CASE_DISPOSITION_CONFLICT)
    else:
        gates["no_conflicting_disposition"] = False

    # ---- Gate 10: no policy-version drift since the decision was recorded ----
    recorded_policy_version = c_detail.get("policy_version") or audit.get("policy_version")
    gates["policy_version_current"] = recorded_policy_version == POLICY_VERSION
    if not gates["policy_version_current"]:
        reasons.append(Reason.CASE_DISPOSITION_CONFLICT)

    eligible = all(gates.values())
    seen = set()
    reasons = [r for r in reasons if not (r in seen or seen.add(r))]

    return {"eligible": eligible, "already_closed": False, "already_closed_by": None,
            "reason_codes": reasons, "gates": gates, "policy_version": POLICY_VERSION,
            "close_key": close_key, "case_state": case_state}


# ==============================================================================
# Phase 4 — positive eligibility gate for VERIFIED L2 assignment
# ==============================================================================
# Same shape/philosophy as the L1 gates above. PURE / read-only — never claims,
# completes, or PATCHes anything, and never resolves the L2 user itself (that
# requires a live TheHive call — done by the caller, agent_orchestrator.
# resolve_l2_user(), and passed in already-resolved as `l2_user`).

def evaluate_l2_assignment_eligibility(alert_id: str, case_id: str, dkey: str,
                                       execution_mode: str, l2_user: dict,
                                       case_state_fn, store_dir: str = None,
                                       allow_l1_fallback: bool = False,
                                       caller_login: str = None) -> dict:
    """
    Positive-eligibility gate for Phase 4 verified L2 assignment.

    `l2_user` is the ALREADY-RESOLVED result of `agent_orchestrator.
    resolve_l2_user()`: {"resolved": bool, "user_id": str|None, "login": str,
    "reason_code": str|None}. `case_state_fn(case_id)` is REQUIRED (no
    default — pure/network-free module), same shape as Phase 3's: a dict with
    at least `status`/`stage`/`raw` (the raw TheHive case dict, for reading
    `assignee`), or a falsy/exception result on failure.

    `caller_login` (Phase 8F.1 fix): the AUTHENTICATED API caller's own login
    for THIS execution — the ALREADY-RESOLVED result of `agent_orchestrator.
    _resolve_caller_login()`, or None if that resolution failed/was
    ambiguous. Used ONLY to distinguish "the live case is already owned by
    a real human" (preserve, never overwrite) from "the live case is owned
    by our OWN service account because TheHive auto-assigns the case
    creator" (not a genuine human assignment — eligible for reassignment to
    SOAR_L2_LOGIN). `caller_login=None` ALWAYS falls into the fail-closed,
    preserve-existing-assignee branch — a failed/ambiguous caller-identity
    lookup must never be treated as "safe to overwrite."

    Returns {"eligible": bool, "already_satisfied": bool, "satisfied_by":
    str|None, "reason_codes": [...], "gates": {...}, "assign_key": str,
    "case_state": dict|None, "l2_user_id": str|None, "existing_assignee":
    str|None}.

    `already_satisfied=True` is NOT a failure — assignment/escalation is
    already effectively true (this workflow already did it, a verified L1
    closure superseded it, the live case is already TruePositive some other
    way, it's already assigned to soc-l2, or a HUMAN already owns it — human
    ownership satisfies the escalation requirement and is never overwritten).
    """
    store_dir = store_dir or idempotency.DEFAULT_STORE_DIR
    reasons = []
    gates = {}

    gates["ids_valid"] = bool(alert_id) and bool(case_id)
    if not gates["ids_valid"]:
        reasons.append(Reason.SCHEMA_INVALID)

    login = (l2_user or {}).get("login") or "unresolved"
    l2_user_id = (l2_user or {}).get("user_id")
    assign_key = idempotency.assignment_action_key(alert_id, case_id, login, execution_mode)

    gates["l2_user_resolved"] = bool((l2_user or {}).get("resolved")) and bool(l2_user_id)
    if not gates["l2_user_resolved"]:
        reasons.append((l2_user or {}).get("reason_code") or Reason.L2_USER_NOT_FOUND)

    # ---- Query current case state ONCE ----
    try:
        case_state = case_state_fn(case_id)
    except Exception:
        case_state = None
    case_state_ok = isinstance(case_state, dict) and bool(case_state.get("status"))
    raw = (case_state or {}).get("raw") or {}
    stage = (case_state or {}).get("stage")
    live_assignee = raw.get("assignee")

    def _result(already_satisfied, satisfied_by, extra_reasons, extra_gates, **extra):
        return {"eligible": True, "already_satisfied": already_satisfied,
                "satisfied_by": satisfied_by, "reason_codes": extra_reasons,
                "gates": extra_gates, "assign_key": assign_key, "case_state": case_state,
                "l2_user_id": l2_user_id, "existing_assignee": None, **extra}

    # ---- Idempotency short-circuit #1: OUR OWN prior run already completed
    # this exact assignment — do not repeat, do not re-PATCH, no error. ----
    prior = idempotency.get_status(assign_key, store_dir=store_dir)
    if prior is not None and prior.get("status") == idempotency.STATUS_COMPLETED:
        return _result(True, "this_workflow", [Reason.L2_ALREADY_ASSIGNED],
                       {"already_completed": True})

    # ---- Idempotency short-circuit #2: a verified L1 closure already
    # completed on this SAME decision key — assignment is unnecessary
    # (defensive; the caller should never reach here in that case). ----
    closure_key = idempotency.action_key(dkey, "closure", "verified-true-positive")
    closure_rec = idempotency.get_status(closure_key, store_dir=store_dir)
    if closure_rec is not None and closure_rec.get("status") == idempotency.STATUS_COMPLETED:
        return _result(True, "verified_l1_closure", [Reason.L2_SKIPPED_VERIFIED_L1_CLOSURE],
                       {"l1_closure_completed": True})

    # ---- Idempotency short-circuit #3: the LIVE case is already closed
    # TruePositive some other way (human, or a lost completion record) —
    # nothing left to escalate. ----
    if case_state_ok and stage == "Closed" and case_state.get("status") == CASE_STATUS_TRUE_POSITIVE:
        return _result(True, "already_true_positive_live",
                       [Reason.CASE_ALREADY_CLOSED_TRUE_POSITIVE], {"already_true_positive_live": True})

    # ---- Idempotency short-circuit #4: LIVE case already assigned to soc-l2 ----
    # CONFIRMED LIVE (Phase 5.6 checkpoint, 2026-08-21): TheHive's `assignee`
    # field round-trips as the user's LOGIN on read, NOT the internal `_id`
    # used to resolve it — a PATCH with the `_id` correctly assigns the
    # account, but a subsequent GET echoes back its login string. Comparing
    # against `l2_user_id` here caused a real false-negative live (a correct
    # assignment was reported as a verification mismatch). Compare against
    # `login` instead — gated on the resolution gate itself, not just
    # `login` truthiness, since `login` defaults to the literal string
    # "unresolved" when resolution failed and must never spuriously match.
    l2_resolved = gates.get("l2_user_resolved", False)
    if l2_resolved and case_state_ok and live_assignee == login:
        return _result(True, "already_assigned_live", [Reason.L2_ALREADY_ASSIGNED],
                       {"already_assigned_live": True})

    # ---- Idempotency short-circuit #5: LIVE case already owned by someone
    # other than the target L2 login. Phase 8F.1 fix: distinguish two cases.
    #   (a) that "someone" is OUR OWN authenticated caller for THIS
    #       execution (exact-match evidence via caller_login, never a
    #       heuristic like "looks like a service account name") — TheHive
    #       auto-assigns the case creator on promote_to_case(), which is not
    #       a genuine human assignment. NOT satisfied — fall through to the
    #       normal eligibility gates below so the case gets reassigned to
    #       SOAR_L2_LOGIN.
    #   (b) anyone/anything else — a real human, a DIFFERENT service
    #       account, or caller_login=None (the caller-identity lookup
    #       failed or was ambiguous) — preserve it, never overwrite. Human
    #       ownership satisfies the escalation requirement on its own, and
    #       an unresolved caller identity must always fail closed.
    # ----
    is_own_service_account = bool(caller_login) and live_assignee == caller_login
    if (l2_resolved and case_state_ok and live_assignee and live_assignee != login
            and not is_own_service_account):
        r = _result(True, "existing_analyst", [Reason.L2_ASSIGNED_TO_EXISTING_ANALYST],
                   {"human_owned": True})
        r["existing_assignee"] = live_assignee
        return r

    # ---- Gate: the immutable tier decision for this case says L2 ----
    tier = idempotency.get_tier_decision(dkey, store_dir=store_dir)
    # Phase 5: `allow_l1_fallback` covers the ONE legitimate exception — the
    # tier decision itself is L1 (never retroactively changed, per requirement
    # 7), but the verified TruePositive closure that decision was supposed to
    # produce FAILED verification. The case must still reach a human; the
    # caller (agent_orchestrator.assign_l2_verified) passes this flag ONLY in
    # that exact fallback, never as a general override.
    gates["tier_is_l2"] = (tier == "L2") or (allow_l1_fallback and tier == "L1")
    if not gates["tier_is_l2"]:
        reasons.append(Reason.CASE_DISPOSITION_CONFLICT)

    # ---- Gate: case-state query itself succeeded ----
    gates["case_state_query_ok"] = case_state_ok
    if not case_state_ok:
        reasons.append(Reason.CASE_STATE_QUERY_FAILED)

    # ---- Gate: the case is OPEN. `stage` ("New"/"InProgress"/"Closed") is the
    # real workflow-open indicator in this schema — `status` carries the
    # resolution TYPE (TruePositive/FalsePositive/...), not open/closed. ----
    if case_state_ok:
        gates["case_open"] = stage != "Closed"
        if not gates["case_open"]:
            reasons.append(Reason.L2_CASE_NOT_OPEN)
            if case_state.get("status") in CASE_STATUS_CONFLICTING:
                reasons.append(Reason.CASE_DISPOSITION_CONFLICT)
    else:
        gates["case_open"] = False

    # ---- Gate: assignment not already completed (belt-and-braces; the real
    # short-circuit above already returns early if true) ----
    gates["not_already_completed"] = prior is None or prior.get("status") != idempotency.STATUS_COMPLETED

    eligible = all(gates.values())
    seen = set()
    reasons = [r for r in reasons if not (r in seen or seen.add(r))]

    return {"eligible": eligible, "already_satisfied": False, "satisfied_by": None,
            "reason_codes": reasons, "gates": gates, "assign_key": assign_key,
            "case_state": case_state, "l2_user_id": l2_user_id, "existing_assignee": None}
