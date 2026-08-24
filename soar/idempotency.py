#!/usr/bin/env python3
"""
Composite idempotency store — the shared safety foundation for containment,
pfSense verification, TruePositive closure, L2 assignment, and every email
notification. Built generically: every side effect (Phase 2-5) claims an
action key from the SAME store using the SAME two-phase protocol.

Disk-persisted, NOT in-memory — a fresh process reading the same store directory
sees exactly the state a prior process left behind, including after a crash or
restart. Cross-process-safe via `os.O_CREAT | os.O_EXCL` (atomic at the OS level:
exactly one of two racing processes can create the same file).

State machine per action key:

    (no file)  --claim()-->  INTENDED  --complete(status)-->  COMPLETED | FAILED | SKIPPED
                                  |
                                  '--- ambiguous: a prior attempt claimed the
                                       action but never recorded an outcome
                                       (crash/timeout/restart mid-action). This
                                       module NEVER assumes INTENDED means either
                                       "it happened" or "it didn't" — the caller
                                       MUST independently verify against the live
                                       external system via resolve_ambiguous().

Decision key = stable identity for ONE case's tier decision:
    alert_id | case_id | policy_version | execution_mode
Deliberately includes policy_version and execution_mode: a policy upgrade or a
dry_run->armed transition gets its OWN key space — recorded fresh rather than
either being silently blocked by, or silently reusing, a decision made under a
different policy/mode.

Action key = decision_key + ":" + action-type (+ optional detail, e.g. the IP):
    <decision-key>:containment:<ip>
    <decision-key>:closure:true-positive
    <decision-key>:assignment:soc-l2
    <decision-key>:email:l1-contained
    <decision-key>:email:l2-action-required
    <decision-key>:email:containment-unverified
    <decision-key>:tier-decision              <- the decision itself, recorded
                                                  BEFORE any side effect, so an
                                                  L2 verdict can never later be
                                                  auto-flipped to an L1 close by
                                                  a retry (requirement 7).
"""
import hashlib
import json
import os
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
# SOAR_IDEMPOTENCY_STORE_DIR (Phase 8D.1 hardening): the previous hardcoded
# release-relative default meant a read-only-deployed release (systemd
# ProtectSystem=strict) had nowhere writable to put this store. Same
# env-var-override pattern already used for SOAR_AUDIT_LOG / SOAR_KILL_SWITCH
# in e2e_soc_orchestrator.py; unset behavior is unchanged.
DEFAULT_STORE_DIR = os.environ.get("SOAR_IDEMPOTENCY_STORE_DIR") or os.path.join(_HERE, "idempotency_store")

STATUS_INTENDED = "intended"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"


class IdempotencyError(Exception):
    """The store exists but a specific record is corrupted/unreadable. Callers
    MUST fail closed (treat as ambiguous/escalate) — never proceed as if nothing
    was recorded, and never silently ignore this."""


# ==============================================================================
# Key construction
# ==============================================================================

def decision_key(alert_id: str, case_id: str, policy_version: str, execution_mode: str) -> str:
    return f"{alert_id}|{case_id}|{policy_version}|{execution_mode}"


def action_key(dkey: str, action: str, detail: str = "") -> str:
    return dkey + f":{action}" + (f":{detail}" if detail else "")


def containment_action_key(alert_id: str, case_id: str, target_ip: str,
                           execution_mode: str) -> str:
    """
    The identity of a DESTRUCTIVE containment action — deliberately built from
    (alert_id, case_id, target_ip, execution_mode) and NOT from decision_key()/
    policy_version. A policy upgrade must never cause the same IP to be blocked
    twice for the same case: policy_version governs whether an action is
    ELIGIBLE, not the identity of the physical action itself once taken. Using
    action_key(decision_key(...), "containment", ip) here would be a real bug —
    confirmed live: two different policy versions produce two different keys for
    the exact same case+IP, which would let a policy bump re-trigger a real
    firewall block. execution_mode IS kept: a dry-run "would block" record must
    not block a later genuinely-armed attempt at the same IP.
    """
    return f"{alert_id}|{case_id}|{execution_mode}:containment:{target_ip}"


def assignment_action_key(alert_id: str, case_id: str, analyst_login: str,
                          execution_mode: str) -> str:
    """
    The identity of an L2 ASSIGNMENT action — built from (alert_id, case_id,
    analyst_login, execution_mode) and NOT from decision_key()/policy_version,
    same reasoning as containment_action_key(): a policy upgrade must never
    cause the same case to be (re-)assigned to the same analyst twice. Keyed
    on the analyst's login (not any internal user id) so the key is stable
    even if TheHive's internal id for that account changes.
    """
    return f"{alert_id}|{case_id}|{execution_mode}:assignment:{analyst_login}"


def notification_action_key(alert_id: str, case_id: str, notification_type: str,
                            recipient: str, execution_mode: str, target: str = "") -> str:
    """
    The identity of an EMAIL NOTIFICATION action — built from (alert_id,
    case_id, notification_type, recipient, execution_mode, [target]) and NOT
    from decision_key()/policy_version, same reasoning as containment_action_
    key()/assignment_action_key(): a policy upgrade, process restart, or
    replayed alert must never cause the same semantic notification to be
    resent. `notification_type` is expected to be "L1_CONTAINED" or
    "L2_ESCALATED" — the two key spaces stay fully distinct by construction
    (the type string is part of the key), so a failed L1 containment that
    falls back to an L2 escalation can never collide with, or be blocked by,
    a genuine L1_CONTAINED record for the same case.
    """
    base = f"{alert_id}|{case_id}|{execution_mode}:notification:{notification_type}:{recipient}"
    return base + (f":{target}" if target else "")


def _store_path(store_dir: str, akey: str) -> str:
    # Hash for a guaranteed-safe, bounded-length filename; keep a truncated
    # human-readable prefix alongside it purely for debuggability when scanning
    # the store directory by eye.
    h = hashlib.sha256(akey.encode("utf-8")).hexdigest()[:16]
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in akey)[:80]
    return os.path.join(store_dir, f"{safe}__{h}.json")


# ==============================================================================
# Core two-phase primitives
# ==============================================================================

def claim(akey: str, store_dir: str = DEFAULT_STORE_DIR, meta: dict = None) -> dict:
    """
    Attempt to become the exclusive owner of `akey`.

    Returns {"claimed": True, "record": {...}}  — you now own this action;
             perform it, then call complete().
    Returns {"claimed": False, "record": {...}} — someone (this run or a prior
             one, possibly a different process) already has or had this key.
             Inspect record["status"]:
               COMPLETED/FAILED/SKIPPED -> already resolved. Do not repeat.
               INTENDED                 -> AMBIGUOUS. Call resolve_ambiguous().

    Raises IdempotencyError if an existing record file is corrupted.
    """
    os.makedirs(store_dir, exist_ok=True)
    path = _store_path(store_dir, akey)
    record = {
        "action_key": akey, "status": STATUS_INTENDED,
        "claimed_at": datetime.now(timezone.utc).isoformat(),
        "pid": os.getpid(), "meta": meta or {},
    }
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        return {"claimed": False, "record": _read_record(path)}
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(record, fh)
    except Exception:
        # Could not persist the claim — don't leave a half-written file that
        # falsely claims ownership we can't actually stand behind.
        try:
            os.unlink(path)
        except Exception:
            pass
        raise
    return {"claimed": True, "record": record}


def _read_record(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        raise IdempotencyError(f"idempotency record unreadable/corrupted: {path}: {exc}")


def complete(akey: str, status: str, detail: dict = None,
            store_dir: str = DEFAULT_STORE_DIR) -> None:
    """Record the outcome of a claimed action. Atomic replace — no torn writes
    visible to a concurrent reader."""
    if status not in (STATUS_COMPLETED, STATUS_FAILED, STATUS_SKIPPED):
        raise ValueError(f"invalid status: {status!r}")
    path = _store_path(store_dir, akey)
    record = _read_record(path) if os.path.exists(path) else {
        "action_key": akey, "claimed_at": datetime.now(timezone.utc).isoformat(),
        "pid": os.getpid(), "meta": {}}
    record["status"] = status
    record["completed_at"] = datetime.now(timezone.utc).isoformat()
    record["detail"] = detail or {}
    tmp = path + f".tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(record, fh)
    os.replace(tmp, path)


def update_meta(akey: str, updates: dict, store_dir: str = DEFAULT_STORE_DIR) -> dict:
    """
    Atomically MERGE `updates` into an existing record's `meta` dict, WITHOUT
    changing its `status` — does not replace claim()/complete() semantics, adds
    a third primitive for "I have new information but the outcome isn't known
    yet" (Phase 2.5: persisting a Cortex job id the moment it's known, well
    before the responder action's terminal status is known).

    Requires the record to already exist (i.e. claim() succeeded first) — this
    is deliberately not a way to create a record. Atomic via the same
    write-tmp-then-os.replace pattern as complete(); a reader never observes a
    torn/partial write, and concurrent update_meta() calls on the same key
    (only possible from the SAME process that owns the claim, or a stale/buggy
    caller) can race on which write lands last, but never corrupt the file.

    Raises IdempotencyError if the record doesn't exist yet or is corrupted —
    fail closed, same as every other read in this module.
    """
    path = _store_path(store_dir, akey)
    if not os.path.exists(path):
        raise IdempotencyError(f"cannot update meta: no record exists for {akey}")
    record = _read_record(path)
    record.setdefault("meta", {}).update(updates)
    record["meta_updated_at"] = datetime.now(timezone.utc).isoformat()
    tmp = path + f".tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(record, fh)
    os.replace(tmp, path)
    return record


def get_status(akey: str, store_dir: str = DEFAULT_STORE_DIR):
    """Read-only lookup. Returns the record dict, or None if never claimed.
    Raises IdempotencyError if the file exists but is corrupted (fail closed —
    the caller must treat this the same as an ambiguous/ intended state, not as
    'nothing recorded')."""
    path = _store_path(store_dir, akey)
    if not os.path.exists(path):
        return None
    return _read_record(path)


def resolve_ambiguous(akey: str, verify_fn, store_dir: str = DEFAULT_STORE_DIR,
                      extra_detail: dict = None) -> dict:
    """
    Resolve an INTENDED-but-unconfirmed record. `verify_fn` is a zero-arg
    callable the CALLER supplies that independently checks the live external
    system (Cortex+pfSense for containment, TheHive for closure/assignment/
    email) and returns "completed", "failed", or "unknown".

    This function makes no network call itself — it only enforces that an
    ambiguous record can never be silently treated as resolved without an
    explicit, independent check. "unknown" means STILL ambiguous: the caller
    must fail closed (escalate), never retry blindly and never skip blindly.

    `extra_detail` (optional) is merged into the completion record — e.g. a
    diagnostic Cortex-job-status hint gathered alongside the authoritative
    pfSense check (Phase 2.5: supplementary evidence, never the deciding
    factor on its own).
    """
    outcome = verify_fn()
    if outcome not in ("completed", "failed", "unknown"):
        raise ValueError(f"verify_fn must return completed/failed/unknown, got {outcome!r}")
    if outcome == "unknown":
        return {"resolved": False, "status": STATUS_INTENDED}
    status = STATUS_COMPLETED if outcome == "completed" else STATUS_FAILED
    detail = {"resolved_via": "independent_verification"}
    detail.update(extra_detail or {})
    complete(akey, status, detail=detail, store_dir=store_dir)
    return {"resolved": True, "status": status}


# ==============================================================================
# Tier-decision helpers (requirement 7: L2 can never be auto-flipped to L1 close)
# ==============================================================================

def record_tier_decision(dkey: str, tier: str, detail: dict = None,
                         store_dir: str = DEFAULT_STORE_DIR) -> dict:
    """
    Record the tier decision (L1/L2) for a decision key. A decision, once made,
    is IMMUTABLE: if a record already exists, it is returned as-is — this call
    never overwrites a prior decision, so a later run can never retroactively
    change an already-escalated L2 case into an L1 close.

    Returns {"recorded_now": bool, "tier": <the tier now on record>}.
    """
    akey = action_key(dkey, "tier-decision")
    result = claim(akey, store_dir=store_dir, meta={"tier": tier, **(detail or {})})
    if result["claimed"]:
        complete(akey, STATUS_COMPLETED, detail={"tier": tier, **(detail or {})},
                store_dir=store_dir)
        return {"recorded_now": True, "tier": tier}
    existing = result["record"]
    existing_tier = (existing.get("detail") or {}).get("tier") or (existing.get("meta") or {}).get("tier")
    return {"recorded_now": False, "tier": existing_tier}


def get_tier_decision(dkey: str, store_dir: str = DEFAULT_STORE_DIR):
    """Returns the previously-recorded tier ("L1"/"L2") for this decision key,
    or None if no decision has been recorded yet. Raises IdempotencyError if the
    record is corrupted (fail closed)."""
    rec = get_status(action_key(dkey, "tier-decision"), store_dir=store_dir)
    if rec is None:
        return None
    return (rec.get("detail") or {}).get("tier") or (rec.get("meta") or {}).get("tier")
