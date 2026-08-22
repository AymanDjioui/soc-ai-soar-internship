#!/usr/bin/env python3
"""
Agent-mode orchestrator — the SOC agent wired into the alert lifecycle, with
deterministic L1 auto-close / L2 escalation (AGENT-ROADMAP.md Phase G).

PARALLEL MODE. This is a SEPARATE entry point: it REUSES the proven orchestrator's
helpers by import and never edits e2e_soc_orchestrator.py. The live armed systemd
service (running the fixed two-call pipeline) is completely undisturbed. Select this
path explicitly; it is not the default.

    alert ─► soc_agent.investigate() ─► verdict + full reasoning trace
                                            │
                                   containment_allowed()  (unchanged guard)
                                            │
                              ┌─────────────┴──────────────┐
                        L1 auto-handle                 L2 escalate
                   (deterministic eligibility)      (anything unclear)
                   · benign  → close FalsePositive   · leave case open + comment
                   · malicious+external+contained    · notify (mailer)
                     → block, then close TruePositive

TIERED AUTONOMY — the model informs, code decides. The LLM never decides to close or
block. l1_disposition() (deterministic) decides the tier from the guard-checked verdict.

SAFETY:
  * SOAR_AGENT_DRY_RUN defaults to "1" — nothing is blocked or closed, only logged.
  * Case-closing is a mutation on the SHARED TheHive; it obeys the same dry-run gate and
    the same kill switch as containment. Closing is reversible (a human can reopen).
  * All guardrails (kill switch, confidence floor, RFC1918/CGNAT/protected-asset refusal,
    rate limit) are the orchestrator's own functions, imported unchanged.

Env: THEHIVE_API_KEY (req), ES_PASSWORD, SOAR_AGENT_DRY_RUN (default 1),
     SOAR_ALERT_ID (target one alert), plus the usual orchestrator/agent env.
"""
import json
import os
import sys
import time
from datetime import datetime, timezone

import requests
from thehive4py.query.filters import Eq

import soc_agent
# Reuse the proven orchestrator wholesale — same guard, same Cortex/mailer/audit paths.
import e2e_soc_orchestrator as orch
import idempotency
import l1_policy
import pfsense_verify

# Agent mode is dry-run by DEFAULT (opposite of the armed pipeline) — closing cases on a
# shared instance is not something to arm implicitly.
AGENT_DRY_RUN = os.environ.get("SOAR_AGENT_DRY_RUN", "1") != "0"
# Phase 8 (not yet fully built — preflight/demo-cutoff/banner) — but the narrow "must be
# explicitly armed" gate primitive is live now: SOAR_AGENT_DRY_RUN=0 ALONE is no longer
# sufficient to permit auto-containment. Both must be set. No implicit/default arming.
AGENT_ARMED = (not AGENT_DRY_RUN) and os.environ.get("SOAR_AGENT_MODE", "").strip().lower() == "armed"
# Retained for when a benign-closure allowlist is (re-)introduced with explicit approval —
# unused while Phase 6 keeps automatic FalsePositive closure disabled (see l1_disposition).
MIN_CONF_L1_CLOSE = float(os.environ.get("SOAR_L1_CLOSE_MIN_CONF", "0.85"))

# Phase 4: the configured L2 analyst account. Not a credential — a TheHive
# login/username, resolved to an internal user id via a live API lookup
# (resolve_l2_user()), never hardcoded as a database id.
SOAR_L2_LOGIN = os.environ.get("SOAR_L2_LOGIN", "soc-l2@thehive.local")


# ==============================================================================
# DETERMINISTIC L1 / L2 TIERING  — code decides, never the model
# ==============================================================================

# Signature classes that describe a REAL attack. A "benign" LLM verdict on one of these
# must NEVER auto-close it as a false positive — a real SQLi is a real SQLi even when the
# source is our own red-team Kali (found live: the agent tried to auto-dismiss real
# SQLi/XSS/LFI as FP because they came from Kali). Deterministic close-guard, same veto
# philosophy as containment: code overrides an unsafe auto-action the model proposed.
ATTACK_SIGNATURE_KEYWORDS = (
    "sql injection", "sqli", "xss", "cross site", "cross-site", "lfi", "traversal",
    "brute-force", "brute force", "bruteforce", "c2", "beacon", "malware", "exploit",
    "injection", "credential", "cred-dump", "cred dump", "rce", "command injection",
    "reverse shell", "privilege escalation", "persistence", "web attack",
)


def is_attack_signature(alert: dict) -> bool:
    """True if the alert's title/tags name a recognized attack class."""
    hay = (str(alert.get("title", "")) + " " + " ".join(
        str(t) for t in (alert.get("tags") or []))).lower()
    return any(k in hay for k in ATTACK_SIGNATURE_KEYWORDS)


def l1_disposition(verdict: dict, containment: dict, alert: dict = None,
                   eligibility: dict = None) -> dict:
    """
    Decide the SOC tier for an assessed alert. Pure function of the (already
    guard-checked) verdict + containment outcome + the Phase 1 eligibility result.
    Returns tier / action / status / reason / reason_codes.

    PHASE 6: automatic benign/FalsePositive closure is DISABLED. Every non-malicious
    verdict escalates to L2, unconditionally, regardless of confidence. The earlier
    "benign + high-confidence + not a keyword-matched attack signature" shape was
    audited as allow-by-default and is not safe enough to run unattended — see
    L1-L2-SAFETY-AUDIT.md. `is_attack_signature()` is kept (imported/used below) as
    informational context on the escalation, ready for reactivation if a positive
    benign-closure allowlist is built and explicitly approved later.

    PHASE 1: malicious auto-close now requires `eligibility["eligible"]` (computed by
    `l1_policy.evaluate_l1_malicious_eligibility()` BEFORE containment is attempted,
    see process_alert_agent) in addition to `containment.executed` — a malicious
    verdict alone was never sufficient, but now the containment attempt itself is
    gated on the positive allowlist, not just the pre-existing guard.
    """
    v = (verdict or {}).get("verdict")

    # ---- Phase 6: no automatic FalsePositive closure. Always L2 for non-malicious. ----
    if v != "malicious":
        note = ""
        if alert is not None and is_attack_signature(alert):
            note = (" Note: the alert also matches a known ATTACK_SIGNATURE_VETO keyword — "
                    "would have been vetoed from auto-close even under the old logic.")
        code = l1_policy.Reason.NOVEL_CASE if v == "inconclusive" else l1_policy.Reason.UNKNOWN_RULE
        return {"tier": "L2", "action": "escalate", "status": None,
                "reason_codes": [code],
                "reason": f"{v or 'unassessed'} verdict — automatic FalsePositive closure is "
                          f"disabled pending an approved positive allowlist (Phase 6); "
                          f"escalated for human review.{note}"}

    # ---- malicious: eligible + INDEPENDENTLY-VERIFIED contained -> close TruePositive ----
    if containment.get("executed"):
        return {"tier": "L1", "action": "close_true_positive", "status": "TruePositive",
                "reason_codes": [l1_policy.Reason.L1_TRUE_POSITIVE_CONTAINED],
                "reason": "malicious, eligible under the Phase 1 policy, and INDEPENDENTLY "
                          "VERIFIED contained — the exact attacker IP was confirmed present in "
                          "pfSense's own EasyRuleBlockHostsWAN table directly (Phase 2), not "
                          "just Cortex's self-reported status — auto-closed at L1."}

    # ---- malicious but the Phase 1 eligibility gate refused it ----
    if eligibility is not None and not eligibility.get("eligible", False):
        codes = eligibility.get("reason_codes") or [l1_policy.Reason.RULE_NOT_L1_ELIGIBLE]
        return {"tier": "L2", "action": "escalate", "status": None,
                "reason_codes": codes,
                "reason": f"malicious but NOT eligible for L1 auto-containment under policy "
                          f"{eligibility.get('policy_version')}: {', '.join(codes)}"}

    # ---- malicious, eligible (or eligibility not evaluated), but not confirmed contained ----
    if containment.get("allowed"):
        # Phase 2's execute_and_verify_containment() supplies a specific reason
        # code (CONTAINMENT_UNVERIFIED / PFSTATE_QUERY_FAILED / NOT_ARMED / ...)
        # when it ran; fall back to the coarser Phase-1-era heuristic only if
        # containment was never actually attempted through that path.
        code = containment.get("reason_code") or (
            l1_policy.Reason.NOT_ARMED if AGENT_DRY_RUN else l1_policy.Reason.CONTAINMENT_UNVERIFIED)
        why = ("containment-eligible, but not executed (agent dry-run / not armed)"
              if AGENT_DRY_RUN else
              f"containment-eligible, attempted, but not independently verified ({code})")
        return {"tier": "L2", "action": "escalate", "status": None,
                "reason_codes": [code],
                "reason": f"malicious and {why} — escalated rather than closed"}

    return {"tier": "L2", "action": "escalate", "status": None,
            "reason_codes": [l1_policy.Reason.CONTAINMENT_REFUSED, l1_policy.Reason.PROTECTED_ASSET],
            "reason": f"malicious but the guard refused containment: {containment.get('reason')}"}


def close_case_l1(api, case_id: str, status: str, summary: str) -> bool:
    """
    Close a case at L1 with a disposition. Mutates the shared TheHive, so it obeys the
    dry-run gate and the kill switch exactly like containment does. Reversible.
    """
    if orch.kill_switch_active():
        print(f"   [L1-close] kill switch active — NOT closing {case_id}")
        return False
    if AGENT_DRY_RUN:
        print(f"   [L1-close] DRY RUN — would close {case_id} as {status}")
        orch.audit("agent_l1_close_dryrun", case_id=case_id, status=status, summary=summary)
        return False
    try:
        resp = requests.patch(
            f"{orch.THEHIVE_URL}/api/v1/case/{case_id}",
            headers={"Authorization": f"Bearer {orch.THEHIVE_API_KEY}",
                     "Content-Type": "application/json"},
            json={"status": status, "stage": "Closed", "summary": summary},
            timeout=20)
        resp.raise_for_status()
        print(f"   [L1-close] case {case_id} closed as {status}")
        orch.audit("agent_l1_closed", case_id=case_id, status=status, summary=summary)
        return True
    except Exception as exc:
        print(f"   [L1-close] failed: {exc}")
        orch.audit("agent_l1_close_failed", case_id=case_id, error=str(exc))
        return False


def build_agent_comment(res: dict, disposition: dict) -> str:
    """Render the agent's investigation trace + tier decision as a labelled comment."""
    v = res.get("verdict") or {}
    lines = [
        "## 🤖 SOC Agent — autonomous investigation",
        "_Generated by the agentic SOAR loop (ReAct + tool use). **Not** a human note._",
        "",
        "### Investigation trace",
    ]
    for step in res.get("trace", []):
        act = step.get("action")
        if act == "conclude":
            lines.append(f"- **[{step['step']}] conclude** — {step.get('thought','')[:140]}")
        else:
            r = step.get("result", {})
            rs = r.get("hint") or r.get("name") or r.get("playbook") or \
                 r.get("total_matches") or r.get("error") or "ok"
            lines.append(f"- **[{step['step']}] {act}(`{step.get('arg','')}`)** → {rs}")
    lines += [
        "",
        "### Verdict",
        f"- **Verdict:** `{str(v.get('verdict')).upper()}`  ·  **Confidence:** `{v.get('confidence')}`",
        f"- **Severity:** `{v.get('severity')}`  ·  **MITRE:** `{v.get('mitre_technique')}`",
        f"- **Reasoning:** {v.get('reason','')}",
        f"- **Key evidence:** {v.get('key_evidence','')}",
        "",
        "### Containment (guard-decided)",
        f"- Target `{res.get('containment',{}).get('target')}` → "
        f"**{res.get('containment',{}).get('disposition')}** "
        f"({res.get('containment',{}).get('reason')})",
        "",
        "### SOC tier",
        f"- **{disposition['tier']} · {disposition['action']}** — {disposition['reason']}",
        f"- **Reason code(s):** `{', '.join(disposition.get('reason_codes', []))}`",
        f"_{'DRY RUN — no case state changed' if AGENT_DRY_RUN else 'applied'}_",
    ]
    return "\n".join(lines)


# ==============================================================================
# PROCESS ONE ALERT THROUGH THE AGENT
# ==============================================================================

def process_alert_agent(api, alert: dict):
    alert_id = alert.get("_id") or alert.get("id")
    title = alert.get("title", "<untitled>")
    print(f"\n{'='*70}\n[AGENT] ALERT {alert_id} — {title}\n{'='*70}")
    orch.audit("agent_alert_received", alert_id=alert_id, title=title)

    if orch.is_operational_alert(alert):
        print("   operational/watchdog alert — not for the agent")
        return

    # ---- promote to a case FIRST — the agent needs real case-observable ids for
    # run_analyzer to trigger live Cortex enrichment mid-investigation. (Previously
    # this happened after investigate(), so run_analyzer had nothing real to act on
    # and always degraded to "not_wired".) ----
    try:
        case = api.alert.promote_to_case(alert_id)
        case_id = case.get("_id") or case.get("id")
        print(f"   promoted to case {case_id}")
        orch.audit("agent_case_created", alert_id=alert_id, case_id=case_id)
    except Exception as exc:
        print(f"   could not promote: {exc} — treating as L2 escalation, no close")
        orch.audit("agent_promote_failed", alert_id=alert_id, error=str(exc))
        return

    # Observables are copied to a promoted case ASYNCHRONOUSLY — same retry the
    # proven pipeline uses (see e2e_soc_orchestrator.process_single_alert).
    observables = []
    for attempt in range(orch.OBSERVABLE_FETCH_ATTEMPTS):
        try:
            observables = api.case.find_observables(case_id)
        except Exception:
            observables = []
        if observables:
            break
        if attempt < orch.OBSERVABLE_FETCH_ATTEMPTS - 1:
            time.sleep(orch.OBSERVABLE_FETCH_DELAY_SECONDS)
    if not observables:
        print(f"   no case observables after {orch.OBSERVABLE_FETCH_ATTEMPTS} attempts "
              f"— run_analyzer will degrade to not_wired")

    # ---- run the agent (investigation only; api+observables enable run_analyzer) ----
    res = soc_agent.investigate(alert, observables, verbose=True, api=api)
    if not res.get("verdict"):
        # The case already exists (promoted above, before the LLM call, so
        # run_analyzer has real observable ids to act on) — an LLM failure here
        # would otherwise leave a silent, unexplained open case. Post the failure
        # reason so a human sees why, not just an unexplained bare case (same
        # "always leave the reasoning visible" principle as the main pipeline).
        print(f"   agent failed ({res.get('error')}) — leaving for human (L2)")
        orch.audit("agent_failed", alert_id=alert_id, case_id=case_id, error=res.get("error"))
        orch.post_case_comment(case_id,
            "## SOC Agent — investigation failed\n"
            "_Generated automatically. **Not** a human analyst note._\n\n"
            f"The agent could not complete its investigation: `{res.get('error')}`\n\n"
            "No verdict was produced and no automated action was taken. "
            "Escalated to L2 for manual review.")
        return

    v = res["verdict"]
    print(f"\n   VERDICT: {v['verdict'].upper()} conf={v['confidence']} "
          f"sev={v['severity']} tech={v['mitre_technique']}")
    orch.audit("agent_verdict", alert_id=alert_id, case_id=case_id, verdict=v["verdict"],
               confidence=v["confidence"], mitre=v["mitre_technique"],
               tools=res.get("tools_used"))

    # ---- Idempotency: the decision key for this case (Phase 2 addendum). Every
    # side effect below (containment/closure/email) claims an action key derived
    # from this SAME decision key, from the SAME shared idempotency store. ----
    execution_mode = "armed" if AGENT_ARMED else "dry_run"
    dkey = idempotency.decision_key(alert_id, case_id, l1_policy.POLICY_VERSION, execution_mode)

    # ---- Phase 1: evaluate positive eligibility BEFORE attempting containment ----
    # (previously any malicious+guard-allowed verdict attempted containment; now it
    # must also clear the narrow allowlist, evidence-completeness, corroboration,
    # conflict, idempotency, and explicit-arm gates in l1_policy.py)
    allowed = res.get("containment", {}).get("allowed")
    eligibility = None
    if v["verdict"] == "malicious" and allowed:
        eligibility = l1_policy.evaluate_l1_malicious_eligibility(
            v, res, alert, alert_id, case_id, armed=AGENT_ARMED)
        print(f"   L1 ELIGIBILITY: {eligibility['eligible']} "
              f"(policy {eligibility['policy_version']}) "
              f"reason_codes={eligibility['reason_codes']}")
        orch.audit("agent_l1_eligibility", case_id=case_id, eligible=eligibility["eligible"],
                   reason_codes=eligibility["reason_codes"], gates=eligibility["gates"],
                   policy_version=eligibility["policy_version"])

    # ---- Phase 2: containment + INDEPENDENT pfSense verification. A Cortex
    # "Success" status alone is never sufficient — see execute_and_verify_
    # containment()'s own docstring for the full pre/post-check flow. ----
    containment = {"attempted": False, "executed": False, "allowed": allowed,
                   "target": res.get("containment", {}).get("target"),
                   "reason": res.get("containment", {}).get("reason")}
    cv = None
    if v["verdict"] == "malicious" and allowed and eligibility and eligibility["eligible"]:
        containment["attempted"] = True
        cv = execute_and_verify_containment(
            api, alert_id, case_id, containment["target"], v["confidence"],
            execution_mode, AGENT_DRY_RUN)
        containment["executed"] = cv["executed"]
        containment["reason_code"] = cv["reason_code"]
        orch.audit("agent_containment_verification", **cv["audit"])
        print(f"   CONTAINMENT VERIFICATION: executed={cv['executed']} "
              f"reason={cv['reason_code']} (precheck={cv['audit'].get('precheck_result')}, "
              f"postcheck={cv['audit'].get('postcheck_result')})")
    elif v["verdict"] == "malicious" and allowed:
        print(f"   containment NOT attempted — Phase 1 eligibility gate refused it")

    # ---- deterministic tier decision + action ----
    disposition = l1_disposition(v, containment, alert, eligibility)
    print(f"   TIER: {disposition['tier']} — {disposition['action']} ({disposition['reason']})")
    orch.audit("agent_tier_decision", case_id=case_id, tier=disposition["tier"],
               action=disposition["action"], reason=disposition["reason"],
               reason_codes=disposition.get("reason_codes", []),
               policy_version=l1_policy.POLICY_VERSION)

    # ---- Record the tier decision itself, IMMUTABLY, before any closure/
    # assignment/email side effect. Requirement 7: an L2 decision can never later
    # be auto-flipped to an L1 close by a retry — record_tier_decision() will
    # simply refuse to overwrite an existing decision on this exact key. ----
    tier_record = idempotency.record_tier_decision(dkey, disposition["tier"],
                                                    detail={"reason": disposition["reason"]})
    if not tier_record["recorded_now"] and tier_record["tier"] != disposition["tier"]:
        # Should be structurally impossible given the eligibility idempotency gate
        # already refuses re-processing — but if it ever happens, the immutable
        # record wins, not the freshly (re-)computed disposition.
        print(f"   ⚠ tier-decision mismatch: already recorded as "
              f"{tier_record['tier']}, this run computed {disposition['tier']} — "
              f"the RECORDED decision is authoritative, refusing to act further")
        orch.audit("agent_tier_decision_conflict", case_id=case_id,
                   recorded_tier=tier_record["tier"], computed_tier=disposition["tier"])
        return

    comment = build_agent_comment(res, disposition)
    orch.post_case_comment(case_id, comment)

    if disposition["action"] == "close_true_positive":
        # Phase 3: verified closure — never trust close_case_l1()'s HTTP-success
        # alone, independently re-query the case before marking it done.
        l1_closed_verified = close_l1_verified(api, dkey, alert_id, case_id, v, res, cv, tier_record)
        if l1_closed_verified:
            # Phase 5: L1 containment notification — ONLY reachable once
            # closure has been INDEPENDENTLY VERIFIED, never on a bare PATCH
            # success. L2 still receives this for awareness/review.
            l2_user = resolve_l2_user(api)
            case_state = _default_case_state_fn(api, case_id)
            send_l1_contained_notification(api, dkey, alert_id, case_id, execution_mode, res,
                                           disposition, cv, case_state,
                                           l2_user.get("login") or SOAR_L2_LOGIN,
                                           observables=observables)
        else:
            # Phase 5: verified closure FAILED — switch to the L2 escalation
            # path instead of ever sending an "L1 contained" email for an
            # unverified close. l1_fallback=True is the one narrow, explicit
            # exception to "assignment requires a recorded L2 tier".
            _run_l2_escalation(api, dkey, alert_id, case_id, execution_mode, res, disposition,
                               containment, tier_record, observables=observables, l1_fallback=True)
    elif disposition["action"].startswith("close_"):
        close_l1_idempotent(api, dkey, case_id, disposition, tier_record)
    else:
        # Phase 4/5: verified L2 assignment + the L2 escalation notification —
        # two independent idempotent actions, bundled by _run_l2_escalation().
        _run_l2_escalation(api, dkey, alert_id, case_id, execution_mode, res, disposition,
                           containment, tier_record, observables=observables)

    print(f"\n{'='*70}\n[AGENT] ALERT {alert_id} COMPLETE — {disposition['tier']}\n{'='*70}")


def close_l1_idempotent(api, dkey: str, case_id: str, disposition: dict,
                        tier_record: dict, store_dir: str = None) -> bool:
    """
    Close the case at L1, idempotently. Extracted as its own function so the
    ignored-return-value fix (audit finding) is independently testable without
    mocking the entire alert-processing pipeline: monkeypatch `close_case_l1`
    and `orch.trigger_mailer_responder`, call this directly.

    `store_dir` defaults to the real shared idempotency store
    (idempotency.DEFAULT_STORE_DIR) in production; tests pass a throwaway temp
    directory so nothing here ever touches real on-disk state.

    Returns True if the case ends up closed (now or previously), False if it
    was refused/failed and escalated instead.
    """
    store_dir = store_dir or idempotency.DEFAULT_STORE_DIR
    # Belt-and-braces: only ever close if the immutable tier record we just
    # wrote/confirmed genuinely says L1 — never trust the locally-computed
    # `disposition` alone for something this consequential.
    if tier_record["tier"] != "L1":
        print(f"   refusing to close — recorded tier is {tier_record['tier']}, not L1")
        orch.trigger_mailer_responder(api, case_id)
        return False

    close_key = idempotency.action_key(dkey, "closure", disposition["status"].lower())
    claimed = idempotency.claim(close_key, store_dir=store_dir)
    if not claimed["claimed"]:
        print(f"   closure already {claimed['record']['status']} for this decision "
              f"key — not repeating close_case_l1()")
        return claimed["record"]["status"] == idempotency.STATUS_COMPLETED

    # Fix (audit finding, ignored-return-value bug): the return value is now
    # checked, completed in the idempotency store either way, and a FAILED
    # close is escalated rather than silently dropped.
    closed_ok = close_case_l1(api, case_id, disposition["status"],
                              summary=f"[SOC Agent] {disposition['reason']}")
    if closed_ok:
        idempotency.complete(close_key, idempotency.STATUS_COMPLETED,
                             detail={"status": disposition["status"]}, store_dir=store_dir)
        return True
    idempotency.complete(close_key, idempotency.STATUS_FAILED,
                         detail={"status": disposition["status"]}, store_dir=store_dir)
    print(f"   close_case_l1() FAILED — case {case_id} remains open; "
          f"escalating instead of leaving it silently unresolved")
    orch.audit("agent_close_failed_escalating", case_id=case_id, status=disposition["status"])
    orch.trigger_mailer_responder(api, case_id)
    return False


def notify_l2_idempotent(api, dkey: str, case_id: str, store_dir: str = None) -> bool:
    """
    L2: leave the case open for a human; notify — idempotent, one email per
    decision key. Placeholder single action name ("l2-notify"); Phase 5 will
    split this into the full l1-contained / l2-action-required / containment-
    unverified email matrix, each with its own action key on this same decision
    key. Extracted as its own function for the same testability reason as
    close_l1_idempotent.
    """
    store_dir = store_dir or idempotency.DEFAULT_STORE_DIR
    email_key = idempotency.action_key(dkey, "email", "l2-notify")
    claimed = idempotency.claim(email_key, store_dir=store_dir)
    if not claimed["claimed"]:
        print(f"   L2 notification already {claimed['record']['status']} for this "
              f"decision key — not re-sending")
        return claimed["record"]["status"] == idempotency.STATUS_COMPLETED
    sent = orch.trigger_mailer_responder(api, case_id)
    idempotency.complete(email_key,
                         idempotency.STATUS_COMPLETED if sent else idempotency.STATUS_FAILED,
                         detail={"case_id": case_id}, store_dir=store_dir)
    return sent


# ==============================================================================
# Phase 4 — verified L2 assignment
# ==============================================================================
# Assignment and email are DELIBERATELY separate idempotent actions (per spec):
# this module never sends email itself — process_alert_agent() still calls
# notify_l2_idempotent() separately, unconditionally, on the escalate branch.
# The full email CONTENT MATRIX (Phase 5) is not built here — assign_l2_
# verified() only returns a rich result dict for that future phase to consume.

_l2_user_cache = {}


def _default_l2_user_find_fn(api, login: str):
    return api.user.find(filters=Eq("login", login))


def resolve_l2_user(api, login: str = None, user_find_fn=None, force_refresh: bool = False) -> dict:
    """
    Resolve the configured L2 analyst login to TheHive's own internal user id
    via a LIVE API lookup — never a hardcoded database id, never a guess at
    whether assignment uses login/user-id/owner/assignee (confirmed from the
    actual thehive4py schema: `OutputCase.assignee` is a user id string, set
    via `api.case.update(case_id, {"assignee": <user _id>})`).

    Cached only within the CURRENT PROCESS (`_l2_user_cache`); pass
    `force_refresh=True` to bypass the cache and re-verify. A transient QUERY
    FAILURE (exception) is never cached — only a definitive answer (found /
    not-found / ambiguous / disabled) is remembered, so a later call can
    still retry after a blip.

    Requires EXACTLY ONE ACTIVE (`locked is False`) matching user:
      - zero matches at all               -> L2_USER_NOT_FOUND
      - more than one ACTIVE match        -> L2_USER_AMBIGUOUS
      - matches exist but all are locked  -> L2_USER_DISABLED
      - exactly one active match          -> resolved

    Returns {"resolved": bool, "user_id": str|None, "login": str,
             "reason_code": str|None}.
    """
    login = login or SOAR_L2_LOGIN
    if not force_refresh and login in _l2_user_cache:
        return _l2_user_cache[login]

    user_find_fn = user_find_fn or (lambda lg: _default_l2_user_find_fn(api, lg))
    try:
        matches = user_find_fn(login) or []
    except Exception as exc:
        print(f"   [l2-user] WARNING could not resolve L2 user {login!r}: {exc}")
        return {"resolved": False, "user_id": None, "login": login,
                "reason_code": l1_policy.Reason.L2_USER_NOT_FOUND, "error": str(exc)}

    active = [u for u in matches if not u.get("locked")]
    if len(matches) == 0:
        result = {"resolved": False, "user_id": None, "login": login,
                  "reason_code": l1_policy.Reason.L2_USER_NOT_FOUND}
    elif len(active) > 1:
        result = {"resolved": False, "user_id": None, "login": login,
                  "reason_code": l1_policy.Reason.L2_USER_AMBIGUOUS}
    elif len(active) == 0:
        result = {"resolved": False, "user_id": None, "login": login,
                  "reason_code": l1_policy.Reason.L2_USER_DISABLED}
    else:
        result = {"resolved": True, "user_id": active[0].get("_id"), "login": login,
                  "reason_code": None}

    _l2_user_cache[login] = result
    return result


def build_l2_escalation_comment(res: dict, disposition: dict, containment: dict) -> str:
    """Structured L2 escalation comment — posted BEFORE the assignment PATCH,
    same "no evidence, no action" discipline as Phase 3's closure comment."""
    v = res.get("verdict") or {}
    trace = res.get("trace") or []
    tools_used = res.get("tools_used") or []
    tool_failures = [f"{s.get('action')}: {(s.get('result') or {}).get('error')}"
                     for s in trace if isinstance(s.get("result"), dict) and (s["result"] or {}).get("error")]
    rag_hits = [str((s.get("result") or {}).get("hint")) for s in trace
               if s.get("action") == "search_past_cases" and s.get("result")]
    analyzer_hits = [str((s.get("result") or {}).get("name") or (s.get("result") or {}).get("hint"))
                     for s in trace if s.get("action") == "run_analyzer" and s.get("result")]
    conflicting = "none detected"
    for s in trace:
        if s.get("action") == "search_past_cases":
            hint = str((s.get("result") or {}).get("hint", ""))
            if hint.startswith("prior FalsePositive"):
                conflicting = "yes — prior FalsePositive history found"
                break
    missing = ("none" if all(t in tools_used for t in l1_policy.REQUIRED_TOOLS_FOR_L1_CONTAIN)
              else "required investigation tools not completed")

    containment = containment or {}
    if containment.get("attempted"):
        pf_line = f"executed={containment.get('executed')}  reason_code=`{containment.get('reason_code')}`"
    else:
        pf_line = "not applicable — no containment attempted"

    lines = [
        "## ⚠️ SOC Agent — L2 escalation",
        "_Generated automatically by the agentic SOAR loop. **Not** a human note._",
        "",
        "### Why this was escalated",
        f"- **Reason:** {disposition.get('reason','')}",
        f"- **Reason code(s):** `{', '.join(disposition.get('reason_codes', []))}`",
        "",
        "### Verdict",
        f"- **Verdict:** `{str(v.get('verdict')).upper()}`  ·  **Confidence:** `{v.get('confidence')}`",
        f"- **Severity:** `{v.get('severity')}`  ·  **MITRE technique:** `{v.get('mitre_technique')}`",
        f"- **Detection rule / reasoning:** {v.get('reason','')}",
        "",
        "### Evidence",
        f"- **Supporting evidence:** {v.get('key_evidence','')}",
        f"- **Conflicting evidence:** {conflicting}",
        f"- **Missing evidence:** {missing}",
        f"- **Tools used:** {', '.join(tools_used) or 'none'}",
        f"- **Tool failures:** {'; '.join(tool_failures) or 'none'}",
        f"- **Past cases (RAG) consulted:** {'; '.join(rag_hits) or 'none'}",
        f"- **Analyzer results:** {'; '.join(analyzer_hits) or 'none'}",
        "",
        "### Containment",
        f"- **Containment / pfSense verification status:** {pf_line}",
        "",
        "### Recommended L2 investigation steps",
        "1. Review the agent's investigation trace and verdict above for soundness.",
        "2. Independently confirm the indicator/attacker IP against threat intel.",
        "3. If containment was attempted but unverified, manually confirm pfSense "
        "state before assuming the host is blocked.",
        "4. Decide the final disposition — this case will **not** auto-close.",
        "",
        "### Policy",
        f"- **Policy version:** `{l1_policy.POLICY_VERSION}`",
        f"- **Escalation time:** `{datetime.now(timezone.utc).isoformat()}`",
    ]
    return "\n".join(lines)


def l2_escalation_tags(disposition: dict) -> list:
    """Deterministic, BOUNDED tag set (never grows unbounded across repeated
    calls — always exactly 2 or 3 tags: the escalation marker, the policy
    version, and at most one reason-category tag). TheHive's addTags itself
    de-duplicates identical tag strings, so a repeat call is a safe no-op."""
    tags = ["ai-escalated-l2", f"ai-policy-{l1_policy.POLICY_VERSION}"]
    codes = disposition.get("reason_codes") or []
    if codes:
        safe = codes[0].lower().replace("_", "-")
        tags.append(f"ai-reason-{safe}")
    return tags


def _post_l2_comment_and_tags(api, case_id: str, res: dict, disposition: dict,
                              containment: dict) -> bool:
    """Comment is the authoritative evidence trail — its failure aborts
    escalation. Tags are best-effort supplementary evidence alongside it — a
    tag-add failure is logged but does not itself abort the assignment."""
    comment_body = build_l2_escalation_comment(res, disposition, containment)
    if not orch.post_case_comment(case_id, comment_body):
        return False
    try:
        api.case.update(case_id, {"addTags": l2_escalation_tags(disposition)})
    except Exception as exc:
        print(f"   [l2-assign] WARNING could not add escalation tags: {exc}")
    return True


def _apply_l2_assignment(api, case_id: str, user_id: str) -> bool:
    try:
        api.case.update(case_id, {"assignee": user_id})
        return True
    except Exception as exc:
        print(f"   [l2-assign] assignment PATCH failed: {exc}")
        return False


_L2_CRITICAL_REASON_CODES = {
    l1_policy.Reason.CASE_STATE_QUERY_FAILED, l1_policy.Reason.L2_USER_NOT_FOUND,
    l1_policy.Reason.L2_USER_AMBIGUOUS, l1_policy.Reason.L2_USER_DISABLED,
}


def assign_l2_verified(api, dkey: str, alert_id: str, case_id: str, execution_mode: str,
                       res: dict, disposition: dict, containment: dict, tier_record: dict,
                       case_state_fn=None, user_find_fn=None, store_dir: str = None,
                       l1_fallback: bool = False) -> dict:
    """
    Phase 4 — verified L2 assignment. Same "never trust the mutation's own
    success alone" philosophy as Phases 2 and 3: `api.case.update()`'s own
    lack of an exception is never sufficient — an independent re-query must
    confirm `assignee` actually landed before the assignment idempotency
    record is marked COMPLETED.

    Deliberately returns a RICH RESULT DICT rather than a bool — Phase 5's
    email layer needs case id/link, who ended up assigned, whether it was
    verified, the reason codes, a human-readable summary, and a
    `critical_failure` flag (set when the automated escalation machinery
    ITSELF is broken — e.g. the L2 account can't be resolved, or the case
    state can't even be queried — situations where email must still be able
    to send a critical notification even though nothing here mutated
    TheHive).

    `l1_fallback=True` (Phase 5): the ONE legitimate exception to "only
    assign when the recorded tier is L2" — the tier decision genuinely IS L1
    (never retroactively changed), but the verified TruePositive closure that
    decision was supposed to produce FAILED verification, so the case must
    still reach a human. The caller (process_alert_agent) passes this ONLY in
    that exact fallback path, never as a general override.

    `case_state_fn`/`user_find_fn` are injectable; tests always supply fakes,
    so no live TheHive call is ever made by a test. `store_dir` defaults to
    the real shared idempotency store.
    """
    store_dir = store_dir or idempotency.DEFAULT_STORE_DIR
    case_state_fn = case_state_fn or (lambda cid: _default_case_state_fn(api, cid))
    case_link = f"{orch.THEHIVE_URL}/index.html#!/case/{case_id}/details"

    def _rich(verified, reason_codes, summary, assigned=None, critical=False):
        return {"case_id": case_id, "case_link": case_link, "assigned_analyst": assigned,
                "verified": verified, "reason_codes": reason_codes,
                "escalation_summary": summary, "critical_failure": critical}

    # Belt-and-braces: only ever attempt L2 assignment if the immutable tier
    # record genuinely says L2 — OR the explicit, narrow L1-fallback case.
    tier_ok = (tier_record["tier"] == "L2") or (l1_fallback and tier_record["tier"] == "L1")
    if not tier_ok:
        print(f"   [l2-assign] refusing — recorded tier is {tier_record['tier']}, not L2 "
              f"(l1_fallback={l1_fallback})")
        return _rich(False, [l1_policy.Reason.CASE_DISPOSITION_CONFLICT],
                    "tier record does not require L2 assignment", critical=True)

    l2_user = resolve_l2_user(api, user_find_fn=user_find_fn)
    eligibility = l1_policy.evaluate_l2_assignment_eligibility(
        alert_id, case_id, dkey, execution_mode, l2_user,
        case_state_fn=case_state_fn, store_dir=store_dir, allow_l1_fallback=l1_fallback)
    orch.audit("agent_l2_eligibility", case_id=case_id, eligible=eligibility["eligible"],
               already_satisfied=eligibility["already_satisfied"],
               reason_codes=eligibility["reason_codes"], gates=eligibility["gates"])

    assign_key = eligibility["assign_key"]

    if eligibility["already_satisfied"]:
        satisfied_by = eligibility["satisfied_by"]
        print(f"   [l2-assign] already satisfied ({satisfied_by}) — not repeating")
        prior = idempotency.get_status(assign_key, store_dir=store_dir)
        # Found live (Phase 5.6 checkpoint, 2026-08-21): "not yet COMPLETED"
        # is NOT the same fact as "no comment has been posted yet" — a prior
        # attempt can have posted the comment, then failed ONLY its
        # verification step (left INTENDED), and a later call reaching this
        # branch would re-post a duplicate evidence comment if it used
        # `needs_resolve` alone as the guard. Track comment-posting
        # explicitly via `meta["comment_posted"]`, set once, right after the
        # comment actually succeeds (see the fresh-claim path below) — that
        # is the only reliable signal for "already landed."
        already_commented = bool((prior or {}).get("meta", {}).get("comment_posted"))
        needs_resolve = prior is None or prior.get("status") != idempotency.STATUS_COMPLETED
        if needs_resolve:
            if prior is None:
                idempotency.claim(assign_key, store_dir=store_dir, meta={"satisfied_by": satisfied_by})
            idempotency.complete(assign_key, idempotency.STATUS_COMPLETED,
                                 detail={"satisfied_by": satisfied_by,
                                         "existing_assignee": eligibility.get("existing_assignee")},
                                 store_dir=store_dir)
        # Human ownership satisfies ASSIGNMENT, but the escalation evidence
        # trail is a separate concern — add it now ONLY if it hasn't landed yet.
        if satisfied_by == "existing_analyst" and needs_resolve and not already_commented:
            if _post_l2_comment_and_tags(api, case_id, res, disposition, containment):
                try:
                    idempotency.update_meta(assign_key, {"comment_posted": True}, store_dir=store_dir)
                except idempotency.IdempotencyError:
                    pass
            else:
                print(f"   [l2-assign] WARNING could not add escalation evidence to "
                      f"human-owned case {case_id}")
        assigned = (eligibility.get("existing_assignee")
                   or (l2_user.get("login") if satisfied_by in
                       ("this_workflow", "already_assigned_live") else None))
        return _rich(True, eligibility["reason_codes"], f"escalation already satisfied ({satisfied_by})",
                    assigned=assigned)

    if not eligibility["eligible"]:
        print(f"   [l2-assign] NOT eligible: {eligibility['reason_codes']} — leaving unresolved")
        orch.audit("agent_l2_assignment_refused", case_id=case_id, reason_codes=eligibility["reason_codes"])
        # A prior crashed attempt may have left this key AMBIGUOUS — resolve
        # it FAILED now rather than leaving it stuck INTENDED forever.
        prior = idempotency.get_status(assign_key, store_dir=store_dir)
        if prior is not None and prior.get("status") == idempotency.STATUS_INTENDED:
            idempotency.complete(assign_key, idempotency.STATUS_FAILED,
                                 detail={"reason_codes": eligibility["reason_codes"]}, store_dir=store_dir)
        critical = any(c in eligibility["reason_codes"] for c in _L2_CRITICAL_REASON_CODES)
        return _rich(False, eligibility["reason_codes"], "assignment refused — see reason codes",
                    critical=critical)

    claimed = idempotency.claim(assign_key, store_dir=store_dir,
                                meta={"case_id": case_id, "login": l2_user["login"]})
    if not claimed["claimed"]:
        status = claimed["record"]["status"]
        if status == idempotency.STATUS_COMPLETED:
            return _rich(True, [l1_policy.Reason.L2_ASSIGNMENT_VERIFIED], "already completed",
                        assigned=l2_user.get("login"))
        if status == idempotency.STATUS_FAILED:
            print(f"   [l2-assign] previously FAILED for this key — not retrying blindly")
            return _rich(False, [l1_policy.Reason.L2_ASSIGNMENT_FAILED], "previously failed", critical=True)

        # INTENDED — ambiguous (e.g. the assignment PATCH timed out after a
        # prior claim). Dedicated recovery, wired to a REAL TheHive
        # assignment-verification function: already soc-l2 -> completed;
        # already another human -> preserve, completed (human ownership
        # satisfies escalation); still unassigned -> the PATCH is idempotent,
        # safe to retry ONCE (bounded); unknown/query failure -> stays
        # unresolved, fail safe. NEVER overwrites a human assignment.
        def _verify_assignment():
            try:
                live = case_state_fn(case_id)
            except Exception:
                return "unknown"
            if not isinstance(live, dict):
                return "unknown"
            assignee = (live.get("raw") or {}).get("assignee")
            # CONFIRMED LIVE (Phase 5.6, 2026-08-21): the assignee field
            # round-trips as the user's LOGIN, not the internal `_id` used to
            # PATCH it — compare against login (see assign_l2_verified()'s
            # post-PATCH verification below for the same fix).
            if assignee == l2_user["login"]:
                return "completed"
            if assignee:
                return "completed"   # human-owned — preserved, satisfies escalation
            if not _apply_l2_assignment(api, case_id, l2_user["user_id"]):
                return "unknown"
            try:
                recheck = case_state_fn(case_id)
            except Exception:
                return "unknown"
            recheck_assignee = (recheck.get("raw") or {}).get("assignee") if isinstance(recheck, dict) else None
            return "completed" if recheck_assignee else "unknown"
        resolved = idempotency.resolve_ambiguous(
            assign_key, _verify_assignment, store_dir=store_dir,
            extra_detail={"resolved_via": "assignment_recovery_reapply"})
        if resolved["resolved"] and resolved["status"] == idempotency.STATUS_COMPLETED:
            print(f"   [l2-assign] ambiguous assignment resolved COMPLETED via re-query/re-apply")
            return _rich(True, [l1_policy.Reason.L2_ASSIGNMENT_VERIFIED], "resolved via recovery",
                        assigned=l2_user.get("login"))
        print(f"   [l2-assign] ambiguous assignment could not be resolved — leaving unresolved")
        return _rich(False, [l1_policy.Reason.L2_ASSIGNMENT_AMBIGUOUS], "ambiguous, unresolved",
                    critical=True)

    # ---- Fresh claim: structured comment + tags MUST succeed before the
    # assignment PATCH — same "no evidence, no action" rule as Phase 3. ----
    if not _post_l2_comment_and_tags(api, case_id, res, disposition, containment):
        idempotency.complete(assign_key, idempotency.STATUS_FAILED,
                             detail={"reason": l1_policy.Reason.L2_COMMENT_FAILED}, store_dir=store_dir)
        print(f"   [l2-assign] structured comment FAILED to post — refusing to assign")
        orch.audit("agent_l2_comment_failed", case_id=case_id)
        return _rich(False, [l1_policy.Reason.L2_COMMENT_FAILED], "comment failed", critical=True)
    # Record that the comment landed BEFORE the PATCH — if verification below
    # is later found ambiguous/mismatched, a subsequent call must not re-post it.
    try:
        idempotency.update_meta(assign_key, {"comment_posted": True}, store_dir=store_dir)
    except idempotency.IdempotencyError:
        pass

    applied = _apply_l2_assignment(api, case_id, l2_user["user_id"])
    if not applied:
        idempotency.complete(assign_key, idempotency.STATUS_FAILED,
                             detail={"reason": l1_policy.Reason.L2_ASSIGNMENT_FAILED}, store_dir=store_dir)
        print(f"   [l2-assign] assignment PATCH failed — escalating")
        orch.audit("agent_l2_assignment_patch_failed", case_id=case_id)
        return _rich(False, [l1_policy.Reason.L2_ASSIGNMENT_FAILED], "PATCH failed", critical=True)

    # ---- INDEPENDENT re-verification — the PATCH's own lack of an exception
    # is NEVER sufficient proof, same philosophy as Phase 2's pfSense post-
    # check and Phase 3's closure re-query. ----
    try:
        live = case_state_fn(case_id)
        query_error = None
    except Exception as exc:
        live = None
        query_error = str(exc)
    actual_assignee = ((live or {}).get("raw") or {}).get("assignee")
    # CONFIRMED LIVE (Phase 5.6 checkpoint, 2026-08-21): a case PATCHed with
    # `{"assignee": <user _id>}` reads back with `assignee` set to that
    # user's LOGIN, not the `_id` — a real false-negative was observed here
    # (a correct assignment reported as a verification mismatch) before this
    # fix. The PATCH itself still sends `_id` (confirmed to correctly
    # resolve to the right account); only the READ-side comparison changes.
    expected_login = l2_user["login"]
    orch.audit("agent_l2_assignment_verification", case_id=case_id,
               expected=expected_login, actual=actual_assignee, query_error=query_error)

    if actual_assignee == expected_login:
        idempotency.complete(assign_key, idempotency.STATUS_COMPLETED,
                             detail={"assignee": actual_assignee,
                                     "verified_at": datetime.now(timezone.utc).isoformat()},
                             store_dir=store_dir)
        print(f"   [l2-assign] case {case_id} assigned to {l2_user['login']} — INDEPENDENTLY VERIFIED")
        return _rich(True, [l1_policy.Reason.L2_ASSIGNMENT_VERIFIED], "assigned and verified",
                    assigned=expected_login)

    # Genuinely unknown/mismatched — leave the record INTENDED (the PATCH may
    # well have worked and this is a read lag or a transient query failure)
    # so a later ambiguous-resolve re-checks rather than inventing an answer.
    print(f"   [l2-assign] POST-ASSIGNMENT VERIFICATION MISMATCH — expected "
          f"{expected_login!r}, got {actual_assignee!r} — leaving ambiguous")
    orch.audit("agent_l2_assignment_unverified", case_id=case_id,
               expected=expected_login, actual=actual_assignee)
    return _rich(False, [l1_policy.Reason.L2_ASSIGNMENT_VERIFY_FAILED], "verification mismatch",
                critical=True)


def _default_case_state_fn(api, case_id: str) -> dict:
    """Production case-state reader — GET only, never mutates. Raises on
    failure (callers must handle: l1_policy treats an exception/non-dict the
    same as a query failure, fail closed)."""
    raw = api.case.get(case_id)
    return {"status": raw.get("status"), "stage": raw.get("stage"), "raw": raw}


def build_closure_comment(res: dict, containment_result: dict, eligibility: dict) -> str:
    """Structured pre-closure evidentiary comment (Phase 3) — posted BEFORE the
    PATCH, not after; a failure to post it aborts the closure entirely (see
    close_l1_verified). Distinct from build_agent_comment()'s investigation
    trace: this one is specifically the closure justification record."""
    v = res.get("verdict") or {}
    audit = (containment_result or {}).get("audit") or {}
    trace = res.get("trace") or []
    rag_hits = [str((s.get("result") or {}).get("hint")) for s in trace
               if s.get("action") == "search_past_cases" and s.get("result")]
    analyzer_hits = [str((s.get("result") or {}).get("name") or (s.get("result") or {}).get("hint"))
                     for s in trace if s.get("action") == "run_analyzer" and s.get("result")]
    lines = [
        "## 🔒 SOC Agent — verified TruePositive closure",
        "_Generated automatically. Pre-closure verification record — **not** a human note._",
        "",
        "### Disposition",
        f"- **Verdict:** `{str(v.get('verdict')).upper()}`  ·  **Confidence:** `{v.get('confidence')}`",
        f"- **MITRE technique:** `{v.get('mitre_technique')}`",
        f"- **Reasoning:** {v.get('reason','')}",
        f"- **Key evidence:** {v.get('key_evidence','')}",
        "",
        "### Containment",
        f"- **Target IP:** `{audit.get('target_ip')}`",
        f"- **Cortex job ID:** `{audit.get('job_id')}`  ·  **Cortex status:** `{audit.get('cortex_status')}`",
        f"- **pfSense verification:** precheck=`{audit.get('precheck_result')}` "
        f"postcheck=`{audit.get('postcheck_result')}` at `{audit.get('verification_timestamp')}`",
        "",
        "### Evidence trail",
        f"- **Tools used:** {', '.join(res.get('tools_used') or [])}",
        f"- **Past cases (RAG) consulted:** {'; '.join(rag_hits) or 'none'}",
        f"- **Analyzer results:** {'; '.join(analyzer_hits) or 'none'}",
        "",
        "### Closure verification",
        f"- **Policy version:** `{eligibility.get('policy_version')}`",
        f"- **Gates:** " + ", ".join(f"{k}={gv}" for k, gv in (eligibility.get('gates') or {}).items()),
        f"- **Reason code(s):** `{', '.join(eligibility.get('reason_codes', []))}`",
        f"- **Verification time:** `{datetime.now(timezone.utc).isoformat()}`",
    ]
    return "\n".join(lines)


def close_l1_verified(api, dkey: str, alert_id: str, case_id: str, verdict: dict,
                      res: dict, containment_result: dict, tier_record: dict,
                      case_state_fn=None, store_dir: str = None) -> bool:
    """
    Phase 3 — verified TruePositive closure. Mirrors execute_and_verify_
    containment()'s shape: a positive-eligibility gate (l1_policy.evaluate_
    l1_closure_eligibility — 10 gates) decides whether closure is even
    attempted; close_case_l1()'s PATCH (reused unchanged) is never trusted on
    its own HTTP-success alone — an independent re-query of the live case
    must confirm the disposition actually stuck before the closure
    idempotency record is marked COMPLETED. Same "never trust the
    subsystem's self-report" philosophy Phase 2 applied to Cortex.

    `case_state_fn` is injectable (production default wraps `api.case.get`
    via `_default_case_state_fn`); tests always supply a fake, so no live
    TheHive call is ever made by a test. `store_dir` defaults to the real
    shared idempotency store.

    Returns True only if the case is confirmed closed TruePositive (now or
    previously adopted); False if refused/failed/ambiguous — in every False
    case the case is left open (or in whatever state it was already in) and
    escalated to L2 via the mailer.
    """
    store_dir = store_dir or idempotency.DEFAULT_STORE_DIR
    case_state_fn = case_state_fn or (lambda cid: _default_case_state_fn(api, cid))

    # Belt-and-braces: only ever attempt a TruePositive close if the immutable
    # tier record genuinely says L1 (same discipline as close_l1_idempotent).
    if tier_record["tier"] != "L1":
        print(f"   [verified-close] refusing — recorded tier is {tier_record['tier']}, not L1")
        orch.trigger_mailer_responder(api, case_id)
        return False

    eligibility = l1_policy.evaluate_l1_closure_eligibility(
        alert_id, case_id, dkey, verdict, containment_result,
        case_state_fn=case_state_fn, store_dir=store_dir)
    orch.audit("agent_closure_eligibility", case_id=case_id,
               eligible=eligibility["eligible"], already_closed=eligibility["already_closed"],
               reason_codes=eligibility["reason_codes"], gates=eligibility["gates"],
               policy_version=eligibility["policy_version"])

    close_key = eligibility["close_key"]

    if eligibility["already_closed"]:
        print(f"   [verified-close] already TruePositive ({eligibility['already_closed_by']}) "
              f"— not repeating")
        # Resolve regardless of the record's current state — no record yet
        # (claim then complete), or a STALE/AMBIGUOUS INTENDED record from a
        # crashed prior attempt (complete it now rather than leaving it stuck
        # forever): the live case state is a confirmed fact either way.
        prior = idempotency.get_status(close_key, store_dir=store_dir)
        if prior is None or prior.get("status") != idempotency.STATUS_COMPLETED:
            if prior is None:
                idempotency.claim(close_key, store_dir=store_dir,
                                  meta={"adopted": eligibility["already_closed_by"]})
            idempotency.complete(close_key, idempotency.STATUS_COMPLETED,
                                 detail={"status": "TruePositive",
                                         "adopted_from": eligibility["already_closed_by"]},
                                 store_dir=store_dir)
        return True

    if not eligibility["eligible"]:
        print(f"   [verified-close] NOT eligible for verified closure: "
              f"{eligibility['reason_codes']} — escalating instead")
        orch.audit("agent_closure_refused", case_id=case_id, reason_codes=eligibility["reason_codes"])
        # A prior crashed attempt may have left this key AMBIGUOUS (claimed,
        # never completed) — since the live state has since turned out to be
        # genuinely ineligible (e.g. a human set a conflicting disposition),
        # resolve it FAILED now rather than leaving it stuck INTENDED forever.
        prior = idempotency.get_status(close_key, store_dir=store_dir)
        if prior is not None and prior.get("status") == idempotency.STATUS_INTENDED:
            idempotency.complete(close_key, idempotency.STATUS_FAILED,
                                 detail={"reason_codes": eligibility["reason_codes"]},
                                 store_dir=store_dir)
        orch.trigger_mailer_responder(api, case_id)
        return False

    claimed = idempotency.claim(close_key, store_dir=store_dir, meta={"case_id": case_id})
    if not claimed["claimed"]:
        status = claimed["record"]["status"]
        if status == idempotency.STATUS_COMPLETED:
            print(f"   [verified-close] closure already completed for this key")
            return True
        if status == idempotency.STATUS_FAILED:
            print(f"   [verified-close] closure previously FAILED for this key — not retrying blindly")
            orch.trigger_mailer_responder(api, case_id)
            return False

        # INTENDED — ambiguous (a prior attempt claimed but never recorded an
        # outcome). Closure's own PATCH is naturally idempotent (re-applying
        # the same status/stage/summary is safe, unlike re-triggering Cortex)
        # — resolve via a DEDICATED closure-specific recovery function, not
        # the pfSense-shaped verify_fn from containment: it re-queries the
        # live case, and if the case is not yet TruePositive and carries no
        # conflicting human disposition, it safely RE-APPLIES the idempotent
        # PATCH as the recovery action itself, then re-verifies.
        def _verify_closure():
            try:
                live = case_state_fn(case_id)
            except Exception:
                return "unknown"
            if not isinstance(live, dict) or not live.get("status"):
                return "unknown"
            if live["status"] == "TruePositive":
                return "completed"
            if live["status"] in l1_policy.CASE_STATUS_CONFLICTING:
                return "failed"  # a human set a different disposition — never overwrite it
            summary = f"[SOC Agent] verified TruePositive (recovered) — {eligibility['policy_version']}"
            if not close_case_l1(api, case_id, "TruePositive", summary=summary):
                return "unknown"
            try:
                recheck = case_state_fn(case_id)
            except Exception:
                return "unknown"
            return ("completed" if isinstance(recheck, dict) and recheck.get("status") == "TruePositive"
                    else "unknown")
        resolved = idempotency.resolve_ambiguous(
            close_key, _verify_closure, store_dir=store_dir,
            extra_detail={"resolved_via": "closure_recovery_reapply"})
        if resolved["resolved"] and resolved["status"] == idempotency.STATUS_COMPLETED:
            print(f"   [verified-close] ambiguous closure resolved COMPLETED via re-query/re-apply")
            return True
        print(f"   [verified-close] ambiguous closure could not be resolved — escalating "
              f"(PATCH is idempotent, a future run may still resolve it)")
        orch.audit("agent_closure_ambiguous", case_id=case_id, reason=l1_policy.Reason.CASE_CLOSE_AMBIGUOUS)
        orch.trigger_mailer_responder(api, case_id)
        return False

    # ---- Structured pre-closure comment MUST succeed before the destructive
    # PATCH — a closed case with no evidentiary trail is not acceptable. ----
    comment_body = build_closure_comment(res, containment_result, eligibility)
    if not orch.post_case_comment(case_id, comment_body):
        idempotency.complete(close_key, idempotency.STATUS_FAILED,
                             detail={"reason": l1_policy.Reason.CASE_COMMENT_FAILED},
                             store_dir=store_dir)
        print(f"   [verified-close] structured comment FAILED to post — refusing to close")
        orch.audit("agent_closure_comment_failed", case_id=case_id)
        orch.trigger_mailer_responder(api, case_id)
        return False

    # ---- Apply the PATCH (reused, unchanged low-level primitive) ----
    summary = f"[SOC Agent] verified TruePositive — {eligibility['policy_version']}"
    applied = close_case_l1(api, case_id, "TruePositive", summary=summary)
    if not applied:
        idempotency.complete(close_key, idempotency.STATUS_FAILED,
                             detail={"reason": l1_policy.Reason.CASE_CLOSE_FAILED},
                             store_dir=store_dir)
        print(f"   [verified-close] close_case_l1() reported failure — case remains open, escalating")
        orch.audit("agent_closure_patch_failed", case_id=case_id)
        orch.trigger_mailer_responder(api, case_id)
        return False

    # ---- INDEPENDENT re-verification — the PATCH's own HTTP-success is NEVER
    # sufficient proof, same philosophy as Phase 2's pfSense post-check. ----
    try:
        live = case_state_fn(case_id)
        query_error = None
    except Exception as exc:
        live = None
        query_error = str(exc)
    expected, actual = "TruePositive", (live or {}).get("status")
    orch.audit("agent_closure_verification", case_id=case_id, expected=expected, actual=actual,
               query_error=query_error)

    if actual == expected:
        idempotency.complete(close_key, idempotency.STATUS_COMPLETED,
                             detail={"status": "TruePositive",
                                     "verified_at": datetime.now(timezone.utc).isoformat()},
                             store_dir=store_dir)
        print(f"   [verified-close] case {case_id} closed TruePositive — INDEPENDENTLY VERIFIED")
        return True

    # Genuinely unknown/mismatched — leave the record INTENDED (do not mark
    # FAILED: the PATCH may well have worked and this is a read lag or a
    # transient query failure) so a later ambiguous-resolve re-checks rather
    # than the system inventing an answer now.
    print(f"   [verified-close] POST-CLOSE VERIFICATION MISMATCH — expected {expected!r}, "
          f"got {actual!r} — leaving ambiguous, escalating")
    orch.audit("agent_closure_unverified", case_id=case_id, expected=expected, actual=actual)
    orch.trigger_mailer_responder(api, case_id)
    return False



# ==============================================================================
# Phase 5 — verified, idempotent L1/L2 email notifications
# ==============================================================================
# Reuses the EXISTING Cortex Mailer responder (same tag-then-fire mechanism
# already proven in orch.trigger_mailer_responder()) — no second SMTP/mail
# implementation is built here.
#
# CORRECTED (Phase 5.5) against the VERIFIED live behavior of the installed
# Mailer_1_0 worker — confirmed by inspecting a real successful Cortex job
# AND the email it produced, not by reading the upstream/public source (the
# installed worker's behavior differs from that public implementation):
#   - Mailer_1_0 is invoked on a complete `thehive:case` object and composes
#     the email ENTIRELY from the case's own fields (title, description,
#     status/stage, TLP/PAP, owner, assignee, creator, non-mail tags, case
#     link) — it does NOT read `parameters.subject`/`parameters.body`.
#   - Recipients are resolved SOLELY from `mail=<address>` case tags.
#   - A structured AI comment on the case is NOT reflected in the email body.
# This module therefore NEVER passes `parameters` to create_responder_
# action(), and NEVER claims the deterministic templates below control the
# received email's content. The templates are preserved as SANITIZED CASE
# COMMENTS and audit evidence only — the actual email a human receives is
# the native Mailer_1_0 case summary. Deterministic, non-sensitive `soc-ai:`
# tags are added to the case (see _l1_contained_routing_tags()/
# _l2_escalated_routing_tags()) so the routing decision is visible even in
# that native summary.
#
# TERMINOLOGY — never conflate these two:
#   NOTIFICATION_ACCEPTED — the Cortex responder JOB ITSELF reported Success.
#                            This is the ONLY status this module can ever
#                            complete a notification record with.
#   DELIVERY_VERIFIED     — actual MAILBOX RECEIPT, confirmed programmatically
#                            (e.g. IMAP polling). NOT implemented anywhere in
#                            this module — no code path here ever produces
#                            this value. For the live demo, mailbox receipt is
#                            captured as external, manual evidence; the code
#                            and audit trail never claim it themselves.

# Redaction/sanitization primitives now live in the side-effect-free
# `sanitization.py` module (Phase 7A) so dataset-build tooling can reuse the
# SAME proven logic without importing this whole orchestrator. Re-exported
# under their original names — every call site below is unchanged, and this
# extraction is proven behavior-preserving by the full existing test suite.
from sanitization import (
    SECRET_PATTERNS as _SECRET_PATTERNS,
    EMAIL_RE as _EMAIL_RE,
    redact_secrets as _redact_secrets,
    sanitize_for_email as _sanitize_for_email,
    validate_email_address as _validate_email_address,
    mask_email as _mask_email,
    correlation_id as _correlation_id,
)


def _case_number(case_state: dict) -> str:
    raw = (case_state or {}).get("raw") or {}
    n = raw.get("number")
    return str(n) if n is not None else "?"


def _observable_summary(observables: list) -> str:
    parts = []
    for o in (observables or []):
        if o.get("dataType") != "ip":
            continue
        tags = o.get("tags") or []
        role = "src" if "src" in tags else ("dst" if "dst" in tags else "ip")
        parts.append(f"{role}={_sanitize_for_email(o.get('data'))}")
    return "; ".join(parts) or "none captured"


def _configured_recipients() -> list:
    """The notification recipient set — never guessed or invented, and always
    returned as a CANONICAL form (validated, de-duplicated, sorted) so the
    same configuration always produces the same order regardless of env-var
    whitespace/formatting/ordering — audit output and idempotency-adjacent
    behavior stay deterministic across runs.

    `SOAR_L2_EMAILS` (comma-separated) takes priority when set — the
    explicit, operator-configured recipient set for this deployment; falls
    back to the existing `e2e_soc_orchestrator.MAILER_RECIPIENTS` list
    otherwise (unchanged, still reused, not reinvented). An empty/unset
    configuration (or one where every candidate fails validation) must cause
    callers to refuse and report the gap, never to send to nobody or a
    made-up address.
    """
    raw = os.environ.get("SOAR_L2_EMAILS", "").strip()
    candidates = ([a.strip() for a in raw.split(",") if a.strip()] if raw
                 else list(orch.MAILER_RECIPIENTS or []))
    valid = {addr for addr in candidates if _validate_email_address(addr)}
    return sorted(valid, key=str.lower)


def _sanitize_tag_component(code: str) -> str:
    return str(code or "").lower().replace("_", "-")


def _l1_contained_routing_tags(disposition: dict) -> list:
    """Deterministic, non-sensitive tags visible on the case even though the
    native Mailer email itself won't show our template — a human glancing at
    the case's tag list can tell at a glance this was an L1 auto-containment."""
    tags = ["soc-ai:l1-contained"]
    codes = (disposition or {}).get("reason_codes") or []
    if codes:
        tags.append(f"soc-ai:reason-{_sanitize_tag_component(codes[0])}")
    return tags


def _l2_escalated_routing_tags(disposition: dict) -> list:
    tags = ["soc-ai:l2-escalated"]
    codes = (disposition or {}).get("reason_codes") or []
    if codes:
        tags.append(f"soc-ai:reason-{_sanitize_tag_component(codes[0])}")
    return tags


def _ensure_case_tags(api, case_id: str, recipients: list, routing_tags: list) -> dict:
    """
    Idempotently merges BOTH the `mail=<address>` recipient tags (Mailer_1_0's
    ONLY recipient-selection mechanism, confirmed live) and the deterministic
    `soc-ai:` routing tags into the case's existing tag list — preserving
    every non-mail tag already present, never creating a duplicate — THEN
    INDEPENDENTLY RE-QUERIES the case to confirm every expected tag actually
    landed. The Mailer is never invoked if this verification fails.

    Recipients are validated first (a strict email-shape check); an empty/
    all-invalid configured recipient list refuses immediately — recipient
    addresses are never guessed.

    Returns {"ok": bool, "masked_recipients": [str,...], "missing_tags": [str,...],
             "error": str|None}. NEVER includes a raw, unmasked address.
    """
    valid = [r for r in (recipients or []) if _validate_email_address(r)]
    if not valid:
        return {"ok": False, "masked_recipients": [], "missing_tags": [],
                "error": "no valid configured recipients"}
    mail_tags = [f"mail={addr}" for addr in valid]
    expected_new_tags = mail_tags + list(routing_tags or [])
    masked = [_mask_email(a) for a in valid]

    try:
        existing = api.case.get(case_id).get("tags", [])
    except Exception as exc:
        return {"ok": False, "masked_recipients": masked, "missing_tags": [],
                "error": f"could not query case tags: {exc}"}

    merged = list(dict.fromkeys(existing + expected_new_tags))   # de-dup, order-preserving
    try:
        api.case.update(case_id, {"tags": merged})
    except Exception as exc:
        return {"ok": False, "masked_recipients": masked, "missing_tags": [],
                "error": f"could not tag case: {exc}"}

    try:
        live_tags = api.case.get(case_id).get("tags", []) or []
    except Exception as exc:
        return {"ok": False, "masked_recipients": masked, "missing_tags": [],
                "error": f"could not verify case tags: {exc}"}

    missing = [t for t in expected_new_tags if t not in live_tags]
    masked_missing = [(_mask_email(m.split("=", 1)[1]) if m.startswith("mail=") else m) for m in missing]
    ok = not missing
    return {"ok": ok, "masked_recipients": masked, "missing_tags": masked_missing,
            "error": None if ok else "tag verification failed"}


def _fetch_action_record(case_id: str, job_id: str = None) -> dict:
    """
    Independent, READ-ONLY query of TheHive's own action record for this
    case — deliberately NOT reusing e2e_soc_orchestrator.wait_for_responder_
    action() (which only returns (status, report), discarding responderId/
    objectId) so responder identity and objectId can be verified from data
    TheHive itself recorded, not merely from what THIS process requested. A
    small, new, read-only function — not a modification of the shared,
    armed-pipeline-used orchestrator module.
    """
    try:
        resp = requests.post(
            f"{orch.THEHIVE_URL}/api/v1/query",
            json={"query": [{"_name": "listAction"},
                            {"_name": "sort", "_fields": [{"startDate": "desc"}]},
                            {"_name": "page", "from": 0, "to": 20}]},
            headers={"Authorization": f"Bearer {orch.THEHIVE_API_KEY}"},
            timeout=15,
        )
        resp.raise_for_status()
        actions = resp.json()
    except Exception:
        return {}
    for a in actions or []:
        if a.get("objectId") != case_id:
            continue
        if job_id and a.get("cortexJobId") not in (job_id, None):
            continue
        return a
    return {}


def _validate_mailer_report(status: str, report: dict, actual_responder_id: str = None,
                            expected_responder_id: str = None, actual_object_id: str = None,
                            expected_object_id: str = None) -> dict:
    """
    NOTIFICATION_ACCEPTED requires ALL of: a terminal successful Cortex
    status, `report['success'] is True`, `report['full']['message'] ==
    'message sent'`, and — only when the report actually carries an
    `operations` list — an `AddTagToCase` op for `mail sent` within it
    (confirmed live: `success: true`, `full.message: "message sent"`, an
    `AddTagToCase` operation for `mail sent`). Identity/objectId checks are
    OPT-IN (only enforced when the caller supplies expected values) so this
    same validator serves both the full post-send verification (with
    independently re-queried identity) and the lighter ambiguous-recovery
    re-poll (content-only). Missing/malformed report fields NEVER produce
    acceptance — fail closed.
    """
    checks = {"status_success": status == "Success"}
    if expected_responder_id is not None:
        checks["responder_identity_ok"] = actual_responder_id == expected_responder_id
    if expected_object_id is not None:
        checks["object_id_ok"] = actual_object_id == expected_object_id

    # Confirmed live: TheHive's `report` (and its nested `full`/`operations`
    # fields) can arrive as JSON-encoded STRINGS rather than already-parsed
    # objects, depending on API path/version — never assumed to be a dict.
    # A string that fails to parse is treated as malformed (fails closed),
    # never as a crash.
    def _as_dict(value):
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except (ValueError, TypeError):
                return {}
        return value if isinstance(value, dict) else {}

    report = _as_dict(report)
    checks["report_success_true"] = report.get("success") is True
    full = _as_dict(report.get("full"))
    checks["report_message_ok"] = full.get("message") == "message sent"
    ops = report.get("operations")
    if isinstance(ops, str):
        try:
            ops = json.loads(ops)
        except (ValueError, TypeError):
            ops = None
    if isinstance(ops, list) and ops:
        checks["add_tag_op_ok"] = any(
            isinstance(op, dict) and op.get("type") == "AddTagToCase" and
            "mail sent" in str(op.get("tag") or op.get("value") or "")
            for op in ops)
    else:
        checks["add_tag_op_ok"] = True   # not present in this report shape — not required
    accepted = all(checks.values())
    return {"accepted": accepted, "checks": checks}


def build_l1_contained_email(res: dict, disposition: dict, containment_result: dict,
                             case_state: dict, case_id: str, case_link: str,
                             execution_mode: str, notification_key: str,
                             observables: list = None) -> dict:
    """Deterministic template — Python string formatting only, NEVER an LLM
    call. The template STRUCTURE and WORDING are fixed code; every inserted
    VALUE (even ones the agent itself produced earlier, like the verdict
    reasoning) passes through _sanitize_for_email() first.

    NOT the literal received email (Phase 5.5 correction) — Mailer_1_0
    composes the actual email from the case's own fields. This is posted as
    a sanitized case comment: audit evidence and a human-readable escalation
    record, not email body content."""
    v = res.get("verdict") or {}
    audit = (containment_result or {}).get("audit") or {}
    case_number = _case_number(case_state)
    severity = _sanitize_for_email(v.get("severity") or "unknown")
    technique = _sanitize_for_email(v.get("mitre_technique") or "unspecified")
    subject = f"[SOC-AI][L1 CONTAINED][{severity}] Case {case_number} - {technique}"

    target = _sanitize_for_email(audit.get("target_ip") or (res.get("containment") or {}).get("target"))
    body_lines = [
        f"Case: #{case_number}",
        f"Link: {case_link}",
        "Notification type: L1 containment (automated)",
        f"Severity: {severity}",
        f"Verdict: {_sanitize_for_email(v.get('verdict'))}   "
        f"Confidence: {_sanitize_for_email(v.get('confidence'))}",
        f"MITRE technique: {technique}",
        f"Observables (source/destination): {_observable_summary(observables)}",
        f"Selected containment target: {target or 'none'}",
        f"Eligibility reason codes: "
        f"{_sanitize_for_email(', '.join(disposition.get('reason_codes', [])) or 'none')}",
        f"Evidence summary: {_sanitize_for_email(v.get('key_evidence') or 'none')}",
        f"Cortex responder/job identifier: {_sanitize_for_email(audit.get('job_id') or 'none')}",
        f"pfSense exact-membership verification: {_sanitize_for_email(audit.get('postcheck_result') or 'none')}",
        "TheHive closure status: TruePositive",
        f"Policy version: {_sanitize_for_email(l1_policy.POLICY_VERSION)}",
        f"Execution mode: {_sanitize_for_email(execution_mode)}",
        f"Timestamp: {datetime.now(timezone.utc).isoformat()}",
        f"Correlation id: {_correlation_id(notification_key)}",
        "",
        "This containment was applied and independently verified fully autonomously.",
        "L2: please review the automated containment above.",
    ]
    return {"subject": subject, "body": "\n".join(body_lines)}


def build_l2_escalation_email(res: dict, disposition: dict, containment: dict,
                              assignment_result: dict, case_state: dict, case_id: str,
                              case_link: str, execution_mode: str, notification_key: str,
                              observables: list = None) -> dict:
    """Deterministic template — same discipline as build_l1_contained_email()
    (posted as a sanitized case comment, NOT the literal received email — see
    that function's docstring). NEVER implies a successful assignment when
    verification failed — the assignment line branches explicitly on
    assignment_result['verified']."""
    v = res.get("verdict") or {}
    case_number = _case_number(case_state)
    severity = _sanitize_for_email(v.get("severity") or "unknown")
    reason_codes = disposition.get("reason_codes") or []
    primary_code = _sanitize_for_email(reason_codes[0]) if reason_codes else "UNSPECIFIED"
    subject = f"[SOC-AI][L2 ESCALATION][{severity}] Case {case_number} - {primary_code}"

    stage = _sanitize_for_email((case_state or {}).get("stage") or "unknown")
    status = _sanitize_for_email((case_state or {}).get("status") or "unknown")

    containment = containment or {}
    if containment.get("attempted"):
        containment_status = ("verified" if containment.get("executed") else
                              f"unverified/failed ({_sanitize_for_email(containment.get('reason_code'))})")
    elif containment.get("allowed") is False:
        containment_status = f"refused ({_sanitize_for_email(containment.get('reason'))})"
    else:
        containment_status = "not attempted"

    assignment_result = assignment_result or {}
    if assignment_result.get("verified"):
        assign_line = (f"verified — assigned to "
                       f"{_sanitize_for_email(assignment_result.get('assigned_analyst') or 'unknown')}")
    else:
        assign_line = (
            f"NOT VERIFIED — {_sanitize_for_email(assignment_result.get('escalation_summary') or 'unknown failure')} "
            f"(reason codes: {_sanitize_for_email(', '.join(assignment_result.get('reason_codes', [])) or 'none')})")

    body_lines = [
        f"Case: #{case_number}",
        f"Link: {case_link}",
        "Notification type: L2 escalation (automated)",
        f"Case stage: {stage}   Disposition: {status}",
        f"Severity: {severity}",
        f"Agent verdict: {_sanitize_for_email(v.get('verdict') or 'unassessed')}   "
        f"Confidence: {_sanitize_for_email(v.get('confidence') if v.get('confidence') is not None else 'n/a')}",
        f"MITRE technique: {_sanitize_for_email(v.get('mitre_technique') or 'n/a')}",
        f"Observables: {_observable_summary(observables)}",
        f"Escalation reason codes: {_sanitize_for_email(', '.join(reason_codes) or 'none')}",
        f"Evidence summary: {_sanitize_for_email(v.get('key_evidence') or disposition.get('reason') or 'none')}",
        f"Containment status: {containment_status}",
        f"L2 assignment result: {assign_line}",
        "This case REMAINS OPEN and requires human review.",
        "Recommended action: review the agent's investigation trace and the escalation "
        "comment on this case, then independently confirm the final disposition "
        "(this case will not auto-close).",
        f"Policy version: {_sanitize_for_email(l1_policy.POLICY_VERSION)}",
        f"Execution mode: {_sanitize_for_email(execution_mode)}",
        f"Timestamp: {datetime.now(timezone.utc).isoformat()}",
        f"Correlation id: {_correlation_id(notification_key)}",
    ]
    return {"subject": subject, "body": "\n".join(body_lines)}


def _trigger_mailer_verified(api, case_id: str, recipients: list, routing_tags: list,
                             idempotency_key=None, store_dir=None, action_record_fn=None) -> dict:
    """
    Fire the EXISTING Cortex Mailer responder — reused, not re-implemented.

    CORRECTED (Phase 5.5): passes NO `parameters` to create_responder_action
    (the installed Mailer_1_0 doesn't consume them, confirmed live) —
    instead it idempotently tags the case with the configured recipients'
    `mail=` tags plus deterministic `soc-ai:` routing tags via
    _ensure_case_tags(), and INDEPENDENTLY RE-QUERIES the case to confirm
    every expected tag actually landed BEFORE the responder is ever invoked.
    If tag verification fails, the Mailer is never called at all.

    Mirrors _execute_containment()'s shape otherwise: captures the job id
    and persists it via idempotency.update_meta() BEFORE the (potentially
    slow) wait for a terminal status. After a successful terminal status, an
    INDEPENDENT read-only query (_fetch_action_record()) re-derives the
    action's own recorded responderId/objectId and the full report, which
    _validate_mailer_report() checks against the exact confirmed-live
    acceptance criteria (report.success, report.full.message, the
    AddTagToCase op when present) — Cortex's own "Success" status alone is
    NEVER sufficient.

    Returns {"mailer_reported_success": bool, "responder_id": str|None,
             "job_id": str|None, "mailer_status": str|None, "error": str|None,
             "report_checks": dict|None, "mail_sent_tag_confirmed_live": bool|None,
             "masked_recipients": [str,...], "tag_verification": dict}.
    Never itself decides NOTIFICATION_ACCEPTED vs DELIVERY_VERIFIED — that
    terminology decision belongs to the caller, which never has grounds to
    claim DELIVERY_VERIFIED from this result alone. Never includes a raw,
    unmasked recipient address anywhere in the returned dict.
    """
    store_dir = store_dir or idempotency.DEFAULT_STORE_DIR
    tag_result = _ensure_case_tags(api, case_id, recipients, routing_tags)
    if not tag_result["ok"]:
        return {"mailer_reported_success": False, "responder_id": None, "job_id": None,
                "mailer_status": None,
                "error": f"recipient/routing tag verification failed: {tag_result['error']}",
                "report_checks": None, "mail_sent_tag_confirmed_live": None,
                "masked_recipients": tag_result["masked_recipients"], "tag_verification": tag_result}

    responder_id, rerr = orch.resolve_case_responder_id(api, case_id, orch.MAILER_RESPONDER_NAME)
    if responder_id is None:
        return {"mailer_reported_success": False, "responder_id": None, "job_id": None,
                "mailer_status": None, "error": f"responder unavailable: {rerr}",
                "report_checks": None, "mail_sent_tag_confirmed_live": None,
                "masked_recipients": tag_result["masked_recipients"], "tag_verification": tag_result}
    try:
        action = api.cortex.create_responder_action({
            "responderId": responder_id, "cortexId": orch.CORTEX_ID,
            "objectType": "case", "objectId": case_id,
        })
        job_id = (action or {}).get("_id") or (action or {}).get("id")
    except Exception as exc:
        return {"mailer_reported_success": False, "responder_id": responder_id, "job_id": None,
                "mailer_status": None, "error": f"mailer call failed: {exc}",
                "report_checks": None, "mail_sent_tag_confirmed_live": None,
                "masked_recipients": tag_result["masked_recipients"], "tag_verification": tag_result}

    if idempotency_key:
        try:
            idempotency.update_meta(idempotency_key, {
                "mailer_job_id": job_id, "mailer_responder_id": responder_id,
                "triggered_at": datetime.now(timezone.utc).isoformat(),
                "last_mailer_status": "Waiting",
                "masked_recipients": tag_result["masked_recipients"],
            }, store_dir=store_dir)
        except idempotency.IdempotencyError as exc:
            print(f"   [notify] WARNING could not persist mailer job metadata: {exc}")

    status, report = orch.wait_for_responder_action(case_id)

    if idempotency_key:
        try:
            idempotency.update_meta(idempotency_key, {
                "last_mailer_status": status,
                "last_status_checked_at": datetime.now(timezone.utc).isoformat(),
            }, store_dir=store_dir)
        except idempotency.IdempotencyError as exc:
            print(f"   [notify] WARNING could not persist mailer status update: {exc}")

    action_record_fn = action_record_fn or _fetch_action_record
    action_record = action_record_fn(case_id, job_id)
    actual_responder_id = action_record.get("responderId") or responder_id
    actual_object_id = action_record.get("objectId") or case_id
    validation = _validate_mailer_report(status, report, actual_responder_id, responder_id,
                                         actual_object_id, case_id)

    if validation["accepted"]:
        try:
            live_tags = api.case.get(case_id).get("tags", []) or []
        except Exception:
            live_tags = []
        mail_sent_confirmed_live = "mail sent" in live_tags   # SUPPORTING evidence only, never gating
        orch.audit("agent_notification_mailer_accepted", case_id=case_id, job_id=job_id,
                  masked_recipients=tag_result["masked_recipients"],
                  mail_sent_tag_confirmed_live=mail_sent_confirmed_live)
        return {"mailer_reported_success": True, "responder_id": responder_id, "job_id": job_id,
                "mailer_status": status, "error": None, "report_checks": validation["checks"],
                "mail_sent_tag_confirmed_live": mail_sent_confirmed_live,
                "masked_recipients": tag_result["masked_recipients"], "tag_verification": tag_result}

    return {"mailer_reported_success": False, "responder_id": responder_id, "job_id": job_id,
            "mailer_status": status, "error": f"mailer report validation failed: {validation['checks']}",
            "report_checks": validation["checks"], "mail_sent_tag_confirmed_live": None,
            "masked_recipients": tag_result["masked_recipients"], "tag_verification": tag_result}


def _resolve_ambiguous_notification(nkey: str, case_id: str, store_dir: str) -> dict:
    """
    Dedicated notification-specific ambiguous recovery. UNLIKE Phase 3/4's
    recovery (which safely re-APPLY an idempotent PATCH), sending an email is
    NOT naturally idempotent — resending really does send a second email. So
    this recovery NEVER re-triggers the mailer; it only RE-CHECKS the
    existing job's own terminal status AND re-validates the SAME report
    content criteria as _validate_mailer_report() (content-only — identity/
    objectId re-derivation isn't repeated here) via a fresh, short poll.
    "Retry only when duplicate delivery cannot already be confirmed" is
    satisfied by never retrying the SEND at all here — only the read.
    """
    def _verify():
        status, report = orch.wait_for_responder_action(case_id, timeout_s=10, poll_s=3)
        if status not in ("Success", "Failure"):
            return "unknown"
        validation = _validate_mailer_report(status, report)
        return "completed" if validation["accepted"] else "failed"
    return idempotency.resolve_ambiguous(nkey, _verify, store_dir=store_dir,
                                         extra_detail={"resolved_via": "notification_status_recheck"})


def send_l1_contained_notification(api, dkey: str, alert_id: str, case_id: str, execution_mode: str,
                                   res: dict, disposition: dict, containment_result: dict,
                                   case_state: dict, l2_login: str, observables: list = None,
                                   mailer_fn=None, store_dir: str = None) -> dict:
    """
    Phase 5 — the L1_CONTAINED notification. Callers MUST only invoke this
    AFTER close_l1_verified() has returned True (independently verified
    TruePositive closure) — this function trusts that gate, same as
    containment trusts policy_guard() having already run; it does not
    re-verify closure itself. process_alert_agent() only reaches this call
    inside the `if l1_closed_verified:` branch — a failed verification
    switches to send_l2_escalation_notification() instead.

    Returns {"sent": bool, "result": <Reason code>, "notification_key": str,
    "correlation_id": str}. NEVER returns/sets DELIVERY_VERIFIED.
    """
    store_dir = store_dir or idempotency.DEFAULT_STORE_DIR
    mailer_fn = mailer_fn or _trigger_mailer_verified
    target = ((containment_result or {}).get("audit") or {}).get("target_ip") or ""
    nkey = idempotency.notification_action_key(alert_id, case_id, "L1_CONTAINED", l2_login,
                                               execution_mode, target=target)
    corr = _correlation_id(nkey)

    def _rich(sent, result):
        return {"sent": sent, "result": result, "notification_key": nkey, "correlation_id": corr}

    recipients = _configured_recipients()
    if not recipients:
        print(f"   [notify-l1] NO configured recipients (MAILER_RECIPIENTS empty) — refusing to send")
        return _rich(False, l1_policy.Reason.NOTIFICATION_RECIPIENT_CONFIG_MISSING)

    claimed = idempotency.claim(nkey, store_dir=store_dir, meta={"case_id": case_id})
    if not claimed["claimed"]:
        status = claimed["record"]["status"]
        if status == idempotency.STATUS_COMPLETED:
            print(f"   [notify-l1] already sent for this decision — not resending")
            return _rich(True, l1_policy.Reason.NOTIFICATION_ACCEPTED)
        if status == idempotency.STATUS_FAILED:
            print(f"   [notify-l1] previously FAILED — not retrying blindly")
            return _rich(False, l1_policy.Reason.NOTIFICATION_FAILED)
        resolved = _resolve_ambiguous_notification(nkey, case_id, store_dir)
        if resolved["resolved"] and resolved["status"] == idempotency.STATUS_COMPLETED:
            return _rich(True, l1_policy.Reason.NOTIFICATION_ACCEPTED)
        if resolved["resolved"] and resolved["status"] == idempotency.STATUS_FAILED:
            return _rich(False, l1_policy.Reason.NOTIFICATION_FAILED)
        print(f"   [notify-l1] ambiguous, could not confirm — NOT resending, leaving unresolved")
        return _rich(False, l1_policy.Reason.NOTIFICATION_AMBIGUOUS)

    case_link = f"{orch.THEHIVE_URL}/index.html#!/case/{case_id}/details"
    email = build_l1_contained_email(res, disposition, containment_result, case_state, case_id,
                                     case_link, execution_mode, nkey, observables=observables)
    orch.post_case_comment(case_id,
        "## 📧 SOC Agent — L1 containment notification (audit record)\n\n"
        "_NOT the literal received email — Mailer_1_0 composes the actual email from this "
        "case's own title/description/status/tags. This is the deterministic audit trail._\n\n"
        f"**Reference subject:** {email['subject']}\n\n```\n{email['body']}\n```")
    routing_tags = _l1_contained_routing_tags(disposition)
    result = mailer_fn(api, case_id, recipients, routing_tags,
                       idempotency_key=nkey, store_dir=store_dir)

    if result["mailer_reported_success"]:
        idempotency.complete(nkey, idempotency.STATUS_COMPLETED,
                             detail={"result": l1_policy.Reason.NOTIFICATION_ACCEPTED,
                                     "job_id": result.get("job_id"),
                                     "masked_recipients": result.get("masked_recipients")},
                             store_dir=store_dir)
        print(f"   [notify-l1] L1 containment notification ACCEPTED by the mailer responder")
        return _rich(True, l1_policy.Reason.NOTIFICATION_ACCEPTED)

    if result.get("job_id") is None or result.get("mailer_status") in ("Success", "Failure"):
        # A confirmed, resolvable outcome either way: never even reached
        # Cortex (tag verification / responder resolution failed, or the
        # trigger call itself raised) — no job exists, so nothing to poll —
        # OR a job DID run and reached a terminal state but failed our report
        # validation. Neither case is "we don't know"; both are FAILED.
        idempotency.complete(nkey, idempotency.STATUS_FAILED,
                             detail={"result": l1_policy.Reason.NOTIFICATION_FAILED,
                                     "error": result.get("error")}, store_dir=store_dir)
        print(f"   [notify-l1] L1 containment notification FAILED: {result.get('error')}")
        return _rich(False, l1_policy.Reason.NOTIFICATION_FAILED)

    # A job EXISTS but its terminal status is still unknown (Timeout) —
    # genuinely AMBIGUOUS. Leave the claimed record INTENDED (never call
    # complete()): a crash here must never be reported as a confirmed
    # failure OR a confirmed send.
    print(f"   [notify-l1] mailer result ambiguous ({result.get('error')}) — leaving unresolved, NOT resending")
    orch.audit("agent_notification_ambiguous", case_id=case_id, notification_type="L1_CONTAINED",
              error=result.get("error"))
    return _rich(False, l1_policy.Reason.NOTIFICATION_AMBIGUOUS)


def send_l2_escalation_notification(api, dkey: str, alert_id: str, case_id: str, execution_mode: str,
                                    res: dict, disposition: dict, containment: dict,
                                    assignment_result: dict, case_state: dict, l2_login: str,
                                    observables: list = None, mailer_fn=None,
                                    store_dir: str = None) -> dict:
    """
    Phase 5 — the L2_ESCALATED notification. A SEPARATE idempotent action
    from assign_l2_verified() — an assignment failure never blocks this call
    (it must still be attempted and must clearly report the failure), and an
    email failure never causes assignment to repeat.

    Returns {"sent": bool, "result": <Reason code>, "notification_key": str,
    "correlation_id": str}. NEVER returns/sets DELIVERY_VERIFIED.
    """
    store_dir = store_dir or idempotency.DEFAULT_STORE_DIR
    mailer_fn = mailer_fn or _trigger_mailer_verified
    target = (containment or {}).get("target") or ""
    nkey = idempotency.notification_action_key(alert_id, case_id, "L2_ESCALATED", l2_login,
                                               execution_mode, target=target)
    corr = _correlation_id(nkey)

    def _rich(sent, result):
        return {"sent": sent, "result": result, "notification_key": nkey, "correlation_id": corr}

    recipients = _configured_recipients()
    if not recipients:
        print(f"   [notify-l2] NO configured recipients (MAILER_RECIPIENTS empty) — refusing to send")
        return _rich(False, l1_policy.Reason.NOTIFICATION_RECIPIENT_CONFIG_MISSING)

    claimed = idempotency.claim(nkey, store_dir=store_dir, meta={"case_id": case_id})
    if not claimed["claimed"]:
        status = claimed["record"]["status"]
        if status == idempotency.STATUS_COMPLETED:
            print(f"   [notify-l2] already sent for this decision — not resending")
            return _rich(True, l1_policy.Reason.NOTIFICATION_ACCEPTED)
        if status == idempotency.STATUS_FAILED:
            print(f"   [notify-l2] previously FAILED — not retrying blindly")
            return _rich(False, l1_policy.Reason.NOTIFICATION_FAILED)
        resolved = _resolve_ambiguous_notification(nkey, case_id, store_dir)
        if resolved["resolved"] and resolved["status"] == idempotency.STATUS_COMPLETED:
            return _rich(True, l1_policy.Reason.NOTIFICATION_ACCEPTED)
        if resolved["resolved"] and resolved["status"] == idempotency.STATUS_FAILED:
            return _rich(False, l1_policy.Reason.NOTIFICATION_FAILED)
        print(f"   [notify-l2] ambiguous, could not confirm — NOT resending, leaving unresolved")
        return _rich(False, l1_policy.Reason.NOTIFICATION_AMBIGUOUS)

    case_link = f"{orch.THEHIVE_URL}/index.html#!/case/{case_id}/details"
    email = build_l2_escalation_email(res, disposition, containment, assignment_result, case_state,
                                      case_id, case_link, execution_mode, nkey, observables=observables)
    orch.post_case_comment(case_id,
        "## 📧 SOC Agent — L2 escalation notification (audit record)\n\n"
        "_NOT the literal received email — Mailer_1_0 composes the actual email from this "
        "case's own title/description/status/tags. This is the deterministic audit trail, "
        "including the assignment result so a human never mistakes an unverified assignment "
        "for a successful one._\n\n"
        f"**Reference subject:** {email['subject']}\n\n```\n{email['body']}\n```")
    routing_tags = _l2_escalated_routing_tags(disposition)
    result = mailer_fn(api, case_id, recipients, routing_tags,
                       idempotency_key=nkey, store_dir=store_dir)

    if result["mailer_reported_success"]:
        idempotency.complete(nkey, idempotency.STATUS_COMPLETED,
                             detail={"result": l1_policy.Reason.NOTIFICATION_ACCEPTED,
                                     "job_id": result.get("job_id"),
                                     "masked_recipients": result.get("masked_recipients")},
                             store_dir=store_dir)
        print(f"   [notify-l2] L2 escalation notification ACCEPTED by the mailer responder")
        return _rich(True, l1_policy.Reason.NOTIFICATION_ACCEPTED)

    if result.get("job_id") is None or result.get("mailer_status") in ("Success", "Failure"):
        idempotency.complete(nkey, idempotency.STATUS_FAILED,
                             detail={"result": l1_policy.Reason.NOTIFICATION_FAILED,
                                     "error": result.get("error")}, store_dir=store_dir)
        print(f"   [notify-l2] L2 escalation notification FAILED: {result.get('error')}")
        return _rich(False, l1_policy.Reason.NOTIFICATION_FAILED)

    print(f"   [notify-l2] mailer result ambiguous ({result.get('error')}) — leaving unresolved, NOT resending")
    orch.audit("agent_notification_ambiguous", case_id=case_id, notification_type="L2_ESCALATED",
              error=result.get("error"))
    return _rich(False, l1_policy.Reason.NOTIFICATION_AMBIGUOUS)


def _run_l2_escalation(api, dkey: str, alert_id: str, case_id: str, execution_mode: str, res: dict,
                       disposition: dict, containment: dict, tier_record: dict,
                       observables: list = None, l1_fallback: bool = False,
                       store_dir: str = None) -> dict:
    """
    Bundles verified L2 assignment (Phase 4) + the L2 escalation notification
    (Phase 5) — reused by BOTH the normal escalate branch and the
    verification-failed L1 fallback branch (process_alert_agent). Assignment
    and email remain two fully independent idempotent actions: an assignment
    failure does not block the email — the email must instead clearly report
    the failure — and an email failure never causes assignment to repeat.
    """
    store_dir = store_dir or idempotency.DEFAULT_STORE_DIR
    assignment_result = assign_l2_verified(api, dkey, alert_id, case_id, execution_mode, res,
                                           disposition, containment, tier_record,
                                           store_dir=store_dir, l1_fallback=l1_fallback)
    l2_user = resolve_l2_user(api)
    case_state = _default_case_state_fn(api, case_id)
    send_l2_escalation_notification(api, dkey, alert_id, case_id, execution_mode, res, disposition,
                                    containment, assignment_result, case_state,
                                    l2_user.get("login") or SOAR_L2_LOGIN,
                                    observables=observables, store_dir=store_dir)
    return assignment_result


def _armed_mode_preflight_check(api, store_dir: str = None, force: bool = False) -> dict:
    """
    'Do not silently fall back to dry-run during the live demo': when the
    agent is ARMED, required configuration is validated BEFORE any alert or
    notification is processed, failing startup clearly (sys.exit) rather
    than discovering a broken dependency mid-run. No-op (no network call at
    all) when not armed and `force` is not set — dry-run/test runs never
    reach this by default; `force=True` is for the explicit, authorized live
    checkpoint that validates this function itself outside the normal armed
    alert-processing entry point.

    Checks, IN ORDER (first failure exits immediately — no later check is
    ever silently skipped over a false green):
      1. TheHive authentication/connectivity (`api.user.get_current()`).
      2. Cortex connectivity (`api.cortex.list_analyzers()` — an entity-free
         endpoint, confirms the Cortex connector itself is reachable/
         configured; `Mailer_1_0`'s own resolution is inherently
         entity(case)-scoped in this API, so it is confirmed as part of the
         actual notification call itself, not duplicated here).
      3. Configured notification recipients (`_configured_recipients()` —
         already validated/de-duplicated/canonically sorted; non-empty).
      4. L2 user resolution (`resolve_l2_user()`, forced fresh — exactly one
         active match required).
      5. Idempotency-store writability — a throwaway claim+complete in the
         GIVEN `store_dir` (defaults to the real shared store; the live
         checkpoint passes its own isolated directory).

    Returns a dict of individual check results — `masked_recipients` only,
    NEVER raw addresses — so a caller can build a sanitized report. Never
    raises itself beyond `sys.exit()` on a genuine hard failure.
    """
    if not AGENT_ARMED and not force:
        return {"skipped": True, "reason": "not armed"}

    results = {}

    try:
        current_user = api.user.get_current()
        results["thehive_auth"] = bool(current_user and current_user.get("login"))
    except Exception as exc:
        sys.exit(f"ARMED preflight FAILED: TheHive authentication/connectivity: {exc}")
    if not results["thehive_auth"]:
        sys.exit("ARMED preflight FAILED: TheHive authentication returned no current user")

    try:
        analyzers = api.cortex.list_analyzers()
        results["cortex_connectivity"] = isinstance(analyzers, list)
    except Exception as exc:
        sys.exit(f"ARMED preflight FAILED: Cortex connectivity: {exc}")

    recipients = _configured_recipients()
    results["recipient_count"] = len(recipients)
    results["masked_recipients"] = [_mask_email(r) for r in recipients]
    if not recipients:
        sys.exit("ARMED preflight FAILED: no valid configured notification recipients")

    l2_user = resolve_l2_user(api, force_refresh=True)
    results["l2_user_resolved"] = l2_user["resolved"]
    results["l2_user_id_present"] = bool(l2_user.get("user_id"))
    if not l2_user["resolved"]:
        sys.exit(f"ARMED preflight FAILED: could not resolve L2 user "
                 f"{SOAR_L2_LOGIN!r} ({l2_user['reason_code']}) — refusing to start")

    sd = store_dir or idempotency.DEFAULT_STORE_DIR
    probe_key = f"__preflight_probe__:{datetime.now(timezone.utc).isoformat()}"
    try:
        idempotency.claim(probe_key, store_dir=sd)
        idempotency.complete(probe_key, idempotency.STATUS_COMPLETED, detail={"probe": True}, store_dir=sd)
        results["idempotency_store_writable"] = True
    except Exception as exc:
        sys.exit(f"ARMED preflight FAILED: idempotency store not writable at {sd}: {exc}")

    print(f"   [preflight] TheHive auth OK, Cortex reachable, L2 user resolved "
         f"({SOAR_L2_LOGIN} -> {l2_user.get('user_id')}), "
         f"{results['recipient_count']} recipient(s) configured, idempotency store writable")
    return results


def _execute_containment(api, case_id, target_ip, confidence,
                         idempotency_key=None, store_dir=None) -> dict:
    """
    Find the target observable on the case and run the proven pfSense blocker.

    Returns a rich detail dict — NOT just a bool — so the caller (Phase 2's
    execute_and_verify_containment) can audit the responder id, the action's own
    id ("job id" for the audit trail), and the exact terminal Cortex status,
    per the audit-field requirements. `cortex_reported_success` is Cortex's OWN
    claim only — the caller must NOT treat this as proof of containment; that
    requires the independent pfSense check.

    Phase 2.5: if `idempotency_key` is given, the job id + responder id are
    persisted into that idempotency record via `idempotency.update_meta()`
    IMMEDIATELY after the responder returns them — before the (potentially
    slow, up-to-120s) wait for a terminal status. A crash during the wait must
    not lose the job id.

    Returns {"cortex_reported_success": bool, "responder_id": str|None,
             "job_id": str|None, "cortex_status": str|None, "error": str|None}
    """
    # Observables are copied to a promoted case ASYNCHRONOUSLY — the same retry the
    # proven orchestrator uses (fetching once returns an empty list and the block is
    # skipped, which is exactly what failed the first armed capture).
    observables = []
    for attempt in range(orch.OBSERVABLE_FETCH_ATTEMPTS):
        try:
            observables = api.case.find_observables(case_id)
        except Exception:
            observables = []
        if observables:
            break
        if attempt < orch.OBSERVABLE_FETCH_ATTEMPTS - 1:
            time.sleep(orch.OBSERVABLE_FETCH_DELAY_SECONDS)
    target_obs, _ = orch.select_containment_target(observables)
    if not target_obs or target_obs.get("data") != target_ip:
        # fall back to any IP observable matching the target
        target_obs = next((o for o in observables
                           if o.get("dataType") == "ip" and o.get("data") == target_ip), target_obs)
    if not target_obs:
        print("   containment: target observable not found on case")
        return {"cortex_reported_success": False, "responder_id": None, "job_id": None,
                "cortex_status": None, "error": "target observable not found on case"}
    obs_id = target_obs.get("_id") or target_obs.get("id")
    responder_id, rerr = orch.resolve_responder_id(api, obs_id, orch.RESPONDER_NAME)
    if responder_id is None:
        print(f"   containment: responder unavailable: {rerr}")
        return {"cortex_reported_success": False, "responder_id": None, "job_id": None,
                "cortex_status": None, "error": f"responder unavailable: {rerr}"}
    try:
        action = api.cortex.create_responder_action({
            "responderId": responder_id, "cortexId": orch.CORTEX_ID,
            "objectType": "case_artifact", "objectId": obs_id})
        job_id = (action or {}).get("_id") or (action or {}).get("id")
    except Exception as exc:
        print(f"   containment call failed: {exc}")
        return {"cortex_reported_success": False, "responder_id": responder_id, "job_id": None,
                "cortex_status": None, "error": f"containment call failed: {exc}"}

    # ---- Phase 2.5: persist job metadata NOW, before the (up to 120s) wait —
    # a crash during the wait must not lose the job id. Best-effort: a failure
    # to persist metadata must not abort a containment attempt already in
    # flight against a real firewall. ----
    if idempotency_key:
        now = datetime.now(timezone.utc).isoformat()
        try:
            idempotency.update_meta(idempotency_key, {
                "cortex_job_id": job_id, "responder_id": responder_id,
                "target_ip": target_ip, "triggered_at": now,
                "last_cortex_status": "Waiting", "last_status_checked_at": now,
            }, store_dir=store_dir or idempotency.DEFAULT_STORE_DIR)
        except idempotency.IdempotencyError as exc:
            print(f"   [containment] WARNING could not persist job metadata: {exc}")

    status, _ = orch.wait_for_responder_action(obs_id)

    if idempotency_key:
        try:
            idempotency.update_meta(idempotency_key, {
                "last_cortex_status": status,
                "last_status_checked_at": datetime.now(timezone.utc).isoformat(),
            }, store_dir=store_dir or idempotency.DEFAULT_STORE_DIR)
        except idempotency.IdempotencyError as exc:
            print(f"   [containment] WARNING could not persist status update: {exc}")

    if status == "Success":
        print(f"   Cortex reported CONTAINMENT SUCCESS against {target_ip} "
              f"(independent pfSense verification still pending)")
        orch.audit("agent_containment_cortex_success", case_id=case_id, target=target_ip,
                   confidence=confidence, cortex_status=status, job_id=job_id,
                   responder_id=responder_id)
        return {"cortex_reported_success": True, "responder_id": responder_id, "job_id": job_id,
                "cortex_status": status, "error": None}
    print(f"   containment not confirmed by Cortex (status={status})")
    return {"cortex_reported_success": False, "responder_id": responder_id, "job_id": job_id,
            "cortex_status": status, "error": f"Cortex status: {status}"}


def _peek_cortex_job_status(api, case_id, target_ip):
    """
    Best-effort, SHORT peek at the most recent responder action's status for
    this target — reuses the EXISTING `orch.wait_for_responder_action` with a
    short timeout rather than inventing a second TheHive query mechanism.
    Diagnostic/supplementary only (Phase 2.5 item 6): never the sole basis for
    a completed/failed decision — pfSense exact membership remains mandatory
    and authoritative for that. Returns a status string, or None if it can't
    be determined quickly (never raises).
    """
    try:
        observables = api.case.find_observables(case_id)
    except Exception:
        return None
    target_obs = next((o for o in (observables or [])
                       if o.get("dataType") == "ip" and o.get("data") == target_ip), None)
    if not target_obs:
        return None
    obs_id = target_obs.get("_id") or target_obs.get("id")
    try:
        status, _ = orch.wait_for_responder_action(obs_id, timeout_s=5, poll_s=5)
    except Exception:
        return None
    return status


def execute_and_verify_containment(api, alert_id: str, case_id: str, target_ip: str,
                                   confidence: float, execution_mode: str, dry_run: bool,
                                   pfsense_check_fn=None, execute_fn=None,
                                   store_dir: str = None) -> dict:
    """
    Phase 2 — the full containment-with-independent-verification flow. A Cortex
    "Success" status is NEVER, by itself, sufficient to mark containment
    executed; this function requires an independent pfSense table check before
    and (when Cortex was actually invoked) after the responder call.

    `pfsense_check_fn` / `execute_fn` are injectable — production defaults to
    `pfsense_verify.check_ip_in_pfsense_table` / the module's own
    `_execute_containment`; every test supplies fakes, so no live pfSense/Cortex
    call is ever made by a test.

    The containment action's idempotency identity is `idempotency
    .containment_action_key(alert_id, case_id, target_ip, execution_mode)` —
    DELIBERATELY independent of policy_version (see idempotency.py docstring):
    a policy upgrade must never cause the same IP to be blocked twice.

    Returns {"executed": bool, "reason_code": str|None, "precheck": {...},
             "postcheck": {...}|None, "cortex_result": {...}|None,
             "audit": {...full field set for the audit trail...}}
    """
    pfsense_check_fn = pfsense_check_fn or pfsense_verify.check_ip_in_pfsense_table
    execute_fn = execute_fn or _execute_containment
    store_dir = store_dir or idempotency.DEFAULT_STORE_DIR

    audit_fields = {"alert_id": alert_id, "case_id": case_id,
                    "policy_version": l1_policy.POLICY_VERSION, "target_ip": target_ip}

    # ---- Gate 1: validate the target BEFORE anything else. Never construct a
    # command from an unvalidated raw string; never even ask pfSense about an
    # IP that doesn't parse. ----
    try:
        pfsense_verify.validate_target_ip(target_ip)
    except ValueError as exc:
        audit_fields.update(precheck_result="INVALID_TARGET", error=str(exc))
        return {"executed": False, "reason_code": l1_policy.Reason.AMBIGUOUS_TARGET,
                "precheck": None, "postcheck": None, "cortex_result": None,
                "audit": audit_fields}

    # Defense in depth: re-run the SAME unchanged guard checks right before the
    # destructive action, not just trust the eligibility-time result — cheap,
    # pure, and closes the window between eligibility evaluation and execution.
    guard_ok, guard_reason = orch.policy_guard(target_ip)
    if not guard_ok:
        audit_fields.update(precheck_result="GUARD_REFUSED", error=guard_reason)
        return {"executed": False, "reason_code": l1_policy.Reason.PROTECTED_ASSET,
                "precheck": None, "postcheck": None, "cortex_result": None,
                "audit": audit_fields}

    c_key = idempotency.containment_action_key(alert_id, case_id, target_ip, execution_mode)
    audit_fields["idempotency_key"] = c_key

    # ---- Step 2: pre-containment read-only check ----
    precheck = pfsense_check_fn(target_ip)
    audit_fields["precheck_result"] = precheck["result"]

    if precheck["result"] == pfsense_verify.RESULT_PRESENT:
        # ALREADY_PRESENT — do not trigger Cortex again; resolve through the
        # existing idempotency state (claim it now if nothing owns it yet).
        claimed = idempotency.claim(c_key, store_dir=store_dir, meta={"target": target_ip})
        if claimed["claimed"]:
            idempotency.complete(c_key, idempotency.STATUS_COMPLETED,
                                 detail={"executed": True, "target": target_ip,
                                         "resolved_via": "precheck_already_present",
                                         "verified_at": precheck["checked_at"]},
                                 store_dir=store_dir)
        executed = claimed["claimed"] or claimed["record"].get("status") == idempotency.STATUS_COMPLETED
        audit_fields.update(final_state="CONTAINMENT_ALREADY_PRESENT" if executed else "AMBIGUOUS",
                            verification_timestamp=precheck["checked_at"])
        return {"executed": executed, "reason_code": l1_policy.Reason.CONTAINMENT_ALREADY_PRESENT,
                "precheck": precheck, "postcheck": None, "cortex_result": None,
                "audit": audit_fields}

    if precheck["result"] in (pfsense_verify.RESULT_QUERY_FAILED, pfsense_verify.RESULT_AMBIGUOUS):
        audit_fields.update(final_state="PFSTATE_QUERY_FAILED", error=precheck.get("error"))
        return {"executed": False, "reason_code": l1_policy.Reason.PFSTATE_QUERY_FAILED,
                "precheck": precheck, "postcheck": None, "cortex_result": None,
                "audit": audit_fields}

    # precheck == ABSENT — safe to continue toward the responder.
    claimed = idempotency.claim(c_key, store_dir=store_dir, meta={"target": target_ip})

    if not claimed["claimed"]:
        status = claimed["record"]["status"]
        if status == idempotency.STATUS_COMPLETED:
            prior_ok = (claimed["record"].get("detail") or {}).get("executed") is True
            audit_fields.update(final_state="REUSED_COMPLETED", idempotency_status=status)
            return {"executed": prior_ok, "reason_code": l1_policy.Reason.L1_TRUE_POSITIVE_CONTAINED
                   if prior_ok else l1_policy.Reason.CONTAINMENT_UNVERIFIED,
                   "precheck": precheck, "postcheck": None, "cortex_result": None,
                   "audit": audit_fields}
        if status == idempotency.STATUS_SKIPPED:
            audit_fields.update(final_state="PRIOR_DRY_RUN_SKIP", idempotency_status=status)
            return {"executed": False, "reason_code": l1_policy.Reason.NOT_ARMED,
                    "precheck": precheck, "postcheck": None, "cortex_result": None,
                    "audit": audit_fields}
        # INTENDED — ambiguous. Resolve via the REAL independent pfSense check
        # (item 5): present -> completed, absent -> failed (do NOT assume the
        # original action never happened, but do NOT retry either), query
        # failure -> stays unresolved, fail closed. Phase 2.5: also peek at the
        # persisted Cortex job id/status, if one exists, as SUPPLEMENTARY
        # diagnostic evidence recorded alongside the resolution — pfSense
        # membership remains the sole authoritative decision input regardless
        # ("never rerun Cortex solely because the job ID is missing" — the
        # inverse holds too: a job id existing doesn't override pfSense either).
        prior_meta = (claimed.get("record") or {}).get("meta") or {}
        job_id = prior_meta.get("cortex_job_id")
        cortex_status_hint = _peek_cortex_job_status(api, case_id, target_ip) if job_id else None

        def _verify():
            recheck = pfsense_check_fn(target_ip)
            if recheck["result"] == pfsense_verify.RESULT_PRESENT:
                return "completed"
            if recheck["result"] == pfsense_verify.RESULT_ABSENT:
                return "failed"
            return "unknown"
        resolved = idempotency.resolve_ambiguous(
            c_key, _verify, store_dir=store_dir,
            extra_detail={"job_id_on_record": job_id, "cortex_status_hint": cortex_status_hint})
        audit_fields.update(final_state="RESOLVED_AMBIGUOUS", resolved=resolved,
                            job_id=job_id, cortex_status_hint=cortex_status_hint)
        executed = resolved["resolved"] and resolved["status"] == idempotency.STATUS_COMPLETED
        return {"executed": executed,
               "reason_code": (l1_policy.Reason.L1_TRUE_POSITIVE_CONTAINED if executed
                               else l1_policy.Reason.CONTAINMENT_UNVERIFIED),
               "precheck": precheck, "postcheck": None, "cortex_result": None,
               "audit": audit_fields}

    if dry_run:
        idempotency.complete(c_key, idempotency.STATUS_SKIPPED, detail={"reason": "dry_run"},
                             store_dir=store_dir)
        audit_fields.update(final_state="DRY_RUN_SKIP")
        return {"executed": False, "reason_code": l1_policy.Reason.NOT_ARMED,
                "precheck": precheck, "postcheck": None, "cortex_result": None,
                "audit": audit_fields}

    # ---- Step 3: trigger Cortex, capture job id + terminal status. Pass the
    # idempotency key through so job metadata is persisted mid-flight (Phase 2.5). ----
    cortex_result = execute_fn(api, case_id, target_ip, confidence,
                               idempotency_key=c_key, store_dir=store_dir)
    audit_fields.update(responder_id=cortex_result.get("responder_id"),
                        job_id=cortex_result.get("job_id"),
                        cortex_status=cortex_result.get("cortex_status"))

    if not cortex_result.get("cortex_reported_success"):
        # Phase 2.5 item 8: even on a Cortex-reported failure, check pfSense —
        # a failure report while the IP is nonetheless present (blocked via
        # another path, or the failure report was itself wrong) is a genuine
        # state CONFLICT, not an ordinary "nothing happened" refusal, and gets
        # its own distinct code so a human sees the anomaly, not a generic one.
        conflict_check = pfsense_check_fn(target_ip)
        audit_fields["failure_path_pfsense_check"] = conflict_check["result"]
        if conflict_check["result"] == pfsense_verify.RESULT_PRESENT:
            idempotency.complete(c_key, idempotency.STATUS_FAILED,
                                 detail={"executed": False, "target": target_ip,
                                         "cortex_status": cortex_result.get("cortex_status"),
                                         "pfsense_result": conflict_check["result"],
                                         "conflict": "cortex_failure_but_ip_present"},
                                 store_dir=store_dir)
            audit_fields.update(final_state="CONTAINMENT_STATE_CONFLICT")
            return {"executed": False, "reason_code": l1_policy.Reason.CONTAINMENT_STATE_CONFLICT,
                    "precheck": precheck, "postcheck": conflict_check, "cortex_result": cortex_result,
                    "audit": audit_fields}
        idempotency.complete(c_key, idempotency.STATUS_FAILED,
                             detail={"executed": False, "target": target_ip,
                                     "cortex_status": cortex_result.get("cortex_status"),
                                     "error": cortex_result.get("error")},
                             store_dir=store_dir)
        audit_fields.update(final_state="CORTEX_NOT_SUCCESS")
        return {"executed": False, "reason_code": l1_policy.Reason.CONTAINMENT_REFUSED,
                "precheck": precheck, "postcheck": conflict_check, "cortex_result": cortex_result,
                "audit": audit_fields}

    # ---- Step 4: Cortex says success — the INDEPENDENT pfSense post-check ----
    postcheck = pfsense_check_fn(target_ip)
    audit_fields.update(postcheck_result=postcheck["result"],
                        verification_timestamp=postcheck["checked_at"])

    if postcheck["result"] == pfsense_verify.RESULT_PRESENT:
        idempotency.complete(c_key, idempotency.STATUS_COMPLETED,
                             detail={"executed": True, "target": target_ip,
                                     "cortex_status": cortex_result.get("cortex_status"),
                                     "job_id": cortex_result.get("job_id"),
                                     "pfsense_verified_at": postcheck["checked_at"]},
                             store_dir=store_dir)
        audit_fields["final_state"] = "CONTAINMENT_VERIFIED"
        return {"executed": True, "reason_code": l1_policy.Reason.L1_TRUE_POSITIVE_CONTAINED,
               "precheck": precheck, "postcheck": postcheck, "cortex_result": cortex_result,
               "audit": audit_fields}

    if postcheck["result"] == pfsense_verify.RESULT_ABSENT:
        # A confident, verified negative — Cortex claimed success, pfSense
        # disagrees. Do not retry automatically; record and escalate.
        idempotency.complete(c_key, idempotency.STATUS_FAILED,
                             detail={"executed": False, "target": target_ip,
                                     "cortex_status": cortex_result.get("cortex_status"),
                                     "pfsense_result": postcheck["result"]},
                             store_dir=store_dir)
        audit_fields["final_state"] = "CONTAINMENT_UNVERIFIED"
        return {"executed": False, "reason_code": l1_policy.Reason.CONTAINMENT_UNVERIFIED,
               "precheck": precheck, "postcheck": postcheck, "cortex_result": cortex_result,
               "audit": audit_fields}

    # postcheck QUERY_FAILED/AMBIGUOUS — genuinely unknown. Do NOT complete the
    # record (leave it INTENDED so a future run resolves it via the real
    # verifier rather than assuming an answer); escalate now regardless.
    audit_fields["final_state"] = "PFSTATE_QUERY_FAILED"
    return {"executed": False, "reason_code": l1_policy.Reason.PFSTATE_QUERY_FAILED,
           "precheck": precheck, "postcheck": postcheck, "cortex_result": cortex_result,
           "audit": audit_fields}


def main():
    if not orch.THEHIVE_API_KEY:
        sys.exit("THEHIVE_API_KEY not set")
    print("=" * 70)
    print("  AGENT-MODE ORCHESTRATOR  (parallel to the armed pipeline)")
    print(f"  Agent dry-run : {AGENT_DRY_RUN}  (case-close + block gated)")
    print(f"  Kill switch   : {'ACTIVE' if orch.kill_switch_active() else 'inactive'}")
    print(f"  L1 close conf : ≥ {MIN_CONF_L1_CLOSE}")
    print("=" * 70)
    if not AGENT_DRY_RUN:
        print("  *** ARMED — the agent can BLOCK and CLOSE cases on the shared TheHive ***")
        print("=" * 70)

    from thehive4py.client import TheHiveApi
    api = TheHiveApi(orch.THEHIVE_URL, apikey=orch.THEHIVE_API_KEY)
    _armed_mode_preflight_check(api)

    target = os.environ.get("SOAR_ALERT_ID", "").strip()
    if target:
        alert = api.alert.get(target)
        process_alert_agent(api, alert)
        return
    print("no SOAR_ALERT_ID given — this entry point processes one alert by id for now.")


if __name__ == "__main__":
    main()
