#!/usr/bin/env python3
"""
Deterministic demo allow-list — Phase 8F.

An ADDITIONAL, separate gate for controlled live demonstrations. Does not
replace l1_policy.py's eligibility gates or the containment guard
(containment_allowed()) — both still apply in full afterward. This module
only ever REFUSES; it never authorizes anything the existing gates wouldn't
already have allowed.

Activation is opt-in: every check here is a no-op (unrestricted, prior
behavior preserved exactly) unless SOAR_DEMO_ACTION_MODE is explicitly set
for the process. A normal armed run with that variable unset is completely
unaffected by this module.

Two independent checks:
  - check_run(alert_id, action_mode): must be called once, early, before any
    mutation is attempted. Refuses unless this exact (alert_id, action_mode)
    was pre-registered via SOAR_DEMO_ALLOWED_ALERT_ID / SOAR_DEMO_ACTION_MODE,
    and claims a single-use idempotency key so a replay of the same
    (alert_id, action_mode) is refused, not silently repeated.
  - containment_permitted(ioc, action_mode): a separate, side-effect-free
    check, called right before a containment attempt. "l2-only" mode always
    returns False (containment is deterministically forbidden in that mode,
    independent of anything the guard/eligibility gates would otherwise
    allow). "l1-containment" mode requires the target IP to exactly match
    SOAR_DEMO_ALLOWED_IOC.
"""
import os

import idempotency

ACTION_MODES = ("l2-only", "l1-containment")


def _configured_mode():
    return os.environ.get("SOAR_DEMO_ACTION_MODE", "").strip() or None


def check_run(alert_id: str, action_mode: str, store_dir: str = None) -> dict:
    """
    Returns {"allowed": bool, "reason": str, "claim_key": str|None}.
    Call once, early, before any mutation. Never raises — the caller decides
    what to do with a refusal, same veto-only philosophy as the rest of this
    project's guards.
    """
    allowed_id = os.environ.get("SOAR_DEMO_ALLOWED_ALERT_ID", "").strip()
    allowed_mode = _configured_mode()

    if not allowed_id or not allowed_mode:
        return {"allowed": False, "claim_key": None,
                "reason": "no demo allow-list configured for this process "
                          "(SOAR_DEMO_ALLOWED_ALERT_ID / SOAR_DEMO_ACTION_MODE unset)"}

    if action_mode not in ACTION_MODES:
        return {"allowed": False, "claim_key": None,
                "reason": f"unknown action_mode {action_mode!r}, expected one of {ACTION_MODES}"}

    if allowed_mode not in ACTION_MODES:
        return {"allowed": False, "claim_key": None,
                "reason": f"configured SOAR_DEMO_ACTION_MODE {allowed_mode!r} is not a valid mode"}

    if alert_id != allowed_id:
        return {"allowed": False, "claim_key": None,
                "reason": f"alert {alert_id!r} is not the allow-listed alert ({allowed_id!r})"}

    if action_mode != allowed_mode:
        return {"allowed": False, "claim_key": None,
                "reason": f"action_mode {action_mode!r} does not match the configured "
                          f"mode {allowed_mode!r}"}

    if allowed_mode == "l1-containment":
        allowed_ioc = os.environ.get("SOAR_DEMO_ALLOWED_IOC", "").strip()
        if not allowed_ioc:
            return {"allowed": False, "claim_key": None,
                    "reason": "l1-containment mode requires SOAR_DEMO_ALLOWED_IOC to be set"}

    store_dir = store_dir or idempotency.DEFAULT_STORE_DIR
    claim_key = f"demo-allowlist-run:{alert_id}:{action_mode}"
    claimed = idempotency.claim(claim_key, store_dir=store_dir, meta={"action_mode": action_mode})
    if not claimed["claimed"]:
        prior_status = claimed["record"]["status"]
        return {"allowed": False, "claim_key": claim_key,
                "reason": f"replay refused — {claim_key} already used (status={prior_status})"}

    idempotency.complete(claim_key, idempotency.STATUS_COMPLETED,
                         detail={"action_mode": action_mode}, store_dir=store_dir)
    return {"allowed": True, "claim_key": claim_key, "reason": "allow-listed and claimed"}


def containment_permitted(ioc, action_mode) -> bool:
    """
    Side-effect-free. Call right before a containment attempt, in addition
    to (never instead of) l1_policy eligibility and containment_allowed().

    action_mode is None (SOAR_DEMO_ACTION_MODE unset) -> unrestricted, True
    ("not a demo run" — preserves prior behavior exactly).
    action_mode == "l2-only" -> always False, no exceptions.
    action_mode == "l1-containment" -> True only if ioc exactly matches
    SOAR_DEMO_ALLOWED_IOC.
    Any other value -> False (fail closed on an unrecognized mode).
    """
    if action_mode is None:
        return True
    if action_mode == "l2-only":
        return False
    if action_mode == "l1-containment":
        allowed_ioc = os.environ.get("SOAR_DEMO_ALLOWED_IOC", "").strip()
        return bool(allowed_ioc) and bool(ioc) and ioc == allowed_ioc
    return False
