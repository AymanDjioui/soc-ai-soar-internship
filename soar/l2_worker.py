#!/usr/bin/env python3
"""
l2_worker.py — Phase 8G permanent L2-only worker.

Polls TheHive for eligible NEW alerts and, for each one, invokes the
existing, already-tested, already-audited one-shot entry point
(agent_orchestrator.py, via subprocess — never reimplemented) in strict
`l2-only` demo-allowlist mode. This worker itself never calls a
TheHive/Cortex MUTATION endpoint directly — it only polls (read-only
listAlert) and claims (local idempotency); all investigation and every
actual mutation happens inside the unchanged one-shot orchestrator,
exactly as already tested and live-verified in Phase 8F.

Containment is impossible from this worker by construction, twice over:
  1. It always launches the orchestrator with SOAR_DEMO_ACTION_MODE=l2-only
     set, which agent_orchestrator.demo_allowlist.containment_permitted()
     forbids unconditionally, regardless of model/policy/config.
  2. It never sets RESPONDER_NAME/PFSENSE_* in the subprocess environment
     — those variables simply do not exist in this process's env by
     deployment design (see the systemd unit: no pfSense/responder
     variables are ever placed in the worker's EnvironmentFile).

Concurrency is exactly 1 (sequential, one alert claimed and fully
processed — success, retry, or dead-letter — before the next poll cycle
considers another). Batch size is fixed at 1 alert per claim cycle; this
is a stated requirement, not a tunable.

Env (all optional except SOAR_WORKER_WATERMARK_ISO, which is REQUIRED —
the worker refuses to start without an explicit deployment watermark):
    SOAR_WORKER_WATERMARK_ISO     REQUIRED. ISO-8601 UTC. Alerts created
                                   before this instant are NEVER processed,
                                   for the lifetime of this watermark.
    SOAR_WORKER_POLL_INTERVAL     default 60 (seconds)
    SOAR_WORKER_TRUSTED_SOURCES   default "elastalert2" (comma-separated)
    SOAR_WORKER_EXCLUDED_TAGS     default "synthetic,test,demo,watchdog,pipeline"
    SOAR_WORKER_MAX_CASES_HOUR    default 3  (circuit breaker)
    SOAR_WORKER_MAX_EMAILS_HOUR   default 3  (circuit breaker)
    SOAR_WORKER_MAX_RETRIES       default 5  (bounded exponential retry)
    SOAR_WORKER_STATE_DIR         default idempotency.DEFAULT_STORE_DIR
    SOAR_WORKER_ONE_CYCLE         if "1", process at most one poll cycle
                                   then exit (used by the controlled soak
                                   test and by tests; never set in the
                                   installed systemd unit)
"""
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests

import e2e_soc_orchestrator as orch
import idempotency
import sanitization

_HERE = os.path.dirname(os.path.abspath(__file__))
ORCHESTRATOR_PATH = os.path.join(_HERE, "agent_orchestrator.py")

SUPPORTED_OBSERVABLE_TYPES = {"ip", "domain", "fqdn", "url", "other"}

POLL_INTERVAL_SECONDS = int(os.environ.get("SOAR_WORKER_POLL_INTERVAL", "60"))
TRUSTED_SOURCES = {s.strip() for s in
                   os.environ.get("SOAR_WORKER_TRUSTED_SOURCES", "elastalert2").split(",") if s.strip()}
EXCLUDED_TAG_SUBSTRINGS = [s.strip().lower() for s in
                           os.environ.get("SOAR_WORKER_EXCLUDED_TAGS",
                                         "synthetic,test,demo,watchdog,pipeline").split(",") if s.strip()]
MAX_CASES_PER_HOUR = int(os.environ.get("SOAR_WORKER_MAX_CASES_HOUR", "3"))
MAX_EMAILS_PER_HOUR = int(os.environ.get("SOAR_WORKER_MAX_EMAILS_HOUR", "3"))
MAX_RETRIES = int(os.environ.get("SOAR_WORKER_MAX_RETRIES", "5"))
ONE_CYCLE_ONLY = os.environ.get("SOAR_WORKER_ONE_CYCLE", "") == "1"

WORKER_STATE_DIR = os.environ.get("SOAR_WORKER_STATE_DIR") or idempotency.DEFAULT_STORE_DIR
BREAKER_FILE = os.path.join(WORKER_STATE_DIR, "CIRCUIT_BREAKER_TRIPPED")
HEALTH_FILE = os.path.join(WORKER_STATE_DIR, "l2_worker_health.json")

CLAIM_PREFIX = "l2-worker-claim"


def _parse_watermark(raw: str):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


# ==============================================================================
# Graceful shutdown
# ==============================================================================

class _ShutdownState:
    def __init__(self):
        self.requested = False


_shutdown_state = _ShutdownState()


def _handle_signal(signum, frame):
    _shutdown_state.requested = True


def install_signal_handlers():
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)


def is_shutdown_requested() -> bool:
    return _shutdown_state.requested


def reset_shutdown_state_for_tests():
    _shutdown_state.requested = False


# ==============================================================================
# Eligibility filtering — pure, network-free, independently testable
# ==============================================================================

def _created_at_seconds(alert: dict):
    v = alert.get("createdAt") or alert.get("date")
    if v is None:
        return None
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    # TheHive represents dates as epoch MILLIseconds.
    return v / 1000.0


def is_eligible_alert(alert: dict, watermark_ts: float) -> dict:
    """
    Pure. Returns {"eligible": bool, "reason": str}. Every exclusion
    listed in the Phase 8G spec is checked here, in a fixed order, before
    any claim is attempted.
    """
    alert_id = alert.get("_id") or alert.get("id")
    if not alert_id:
        return {"eligible": False, "reason": "missing alert id"}

    created_ts = _created_at_seconds(alert)
    if created_ts is None:
        return {"eligible": False, "reason": "missing/unparseable createdAt — fail closed, never guess"}
    if created_ts < watermark_ts:
        return {"eligible": False,
               "reason": "created before the deployment watermark — historical backlog, excluded"}

    if alert.get("status") != "New":
        return {"eligible": False, "reason": f"status is {alert.get('status')!r}, not New"}

    source = alert.get("source")
    if source not in TRUSTED_SOURCES:
        return {"eligible": False, "reason": f"source {source!r} is not in the trusted-source allow-list"}

    if orch.is_operational_alert(alert):
        return {"eligible": False, "reason": "operational/pipeline-watchdog alert"}

    if alert.get("caseId"):
        return {"eligible": False, "reason": "already promoted to a case"}

    tags = [str(t).lower() for t in (alert.get("tags") or [])]
    title = str(alert.get("title") or "").lower()
    for bad in EXCLUDED_TAG_SUBSTRINGS:
        if bad and (any(bad in t for t in tags) or bad in title):
            return {"eligible": False, "reason": f"excluded tag/title substring matched: {bad!r}"}

    observables = alert.get("observables") or alert.get("artifacts")
    if isinstance(observables, list) and observables:
        types = {o.get("dataType") for o in observables if isinstance(o, dict)}
        if types and not (types & SUPPORTED_OBSERVABLE_TYPES):
            return {"eligible": False, "reason": f"no supported observable type among {sorted(types)}"}

    if not str(alert.get("description") or "").strip():
        return {"eligible": False, "reason": "missing required evidence (empty description)"}

    return {"eligible": True, "reason": "eligible"}


# ==============================================================================
# TheHive polling — read-only
# ==============================================================================

def fetch_candidate_alerts(thehive_url, thehive_api_key, limit=50, session=None):
    """
    Read-only. Sorts NEWEST FIRST (descending createdAt) — REQUIRED, not
    cosmetic. A live soak test found the bug this guards against: with
    ascending sort and a backlog of 25+ pre-watermark "New" alerts already
    sitting unprocessed (they always will be — this worker never touches
    them, by design), an ascending, capped page NEVER reaches a
    newly-created alert at all, no matter how long the worker runs. It
    would starve forever. Descending sort guarantees the newest alerts —
    the only ones this worker can ever be eligible to process — are
    always inside the fetched window.
    """
    s = session or requests
    r = s.post(f"{thehive_url}/api/v1/query",
              headers={"Authorization": f"Bearer {thehive_api_key}", "Content-Type": "application/json"},
              json={"query": [{"_name": "listAlert"},
                              {"_name": "filter", "_field": "status", "_value": "New"},
                              {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
                              {"_name": "page", "from": 0, "to": limit}]},
              timeout=20)
    r.raise_for_status()
    return r.json()


# ==============================================================================
# Atomic claim
# ==============================================================================

def claim_alert(alert_id: str, store_dir: str = None) -> dict:
    store_dir = store_dir or WORKER_STATE_DIR
    return idempotency.claim(f"{CLAIM_PREFIX}:{alert_id}", store_dir=store_dir)


def complete_claim(alert_id: str, status: str, detail: dict = None, store_dir: str = None):
    store_dir = store_dir or WORKER_STATE_DIR
    idempotency.complete(f"{CLAIM_PREFIX}:{alert_id}", status, detail=detail or {}, store_dir=store_dir)


def claim_status(alert_id: str, store_dir: str = None):
    store_dir = store_dir or WORKER_STATE_DIR
    return idempotency.get_status(f"{CLAIM_PREFIX}:{alert_id}", store_dir=store_dir)


# ==============================================================================
# Circuit breaker
#
# Phase 8G.1 redesign. Two problems found live in production:
#   1. The counting window was a bare rolling hour with NO floor at the
#      current activation watermark — a fresh production epoch could
#      inherit trip-worthy history from a PRIOR epoch (e.g. a soak test)
#      that has nothing to do with the new epoch's own behavior.
#   2. Every poll cycle re-announced "tripped" as its own audit event —
#      noisy, and made a genuine NEW trip indistinguishable in the log
#      from "still tripped, nothing changed."
#
# Fix: the counting window is now max(now - window, activation_watermark)
# — never reaches back past the current epoch's own start, so a fresh
# watermark always starts the breaker's memory at zero. Still fail-closed
# and sticky: a genuine trip within the CURRENT epoch behaves exactly as
# before (marker file, manual-reset-only, no silent auto-clear). Exactly
# one l2_worker_circuit_breaker_tripped event fires on the actual
# untripped->tripped transition; subsequent cycles emit a rate-limited
# l2_worker_circuit_breaker_heartbeat instead of repeating the trip event.
# ==============================================================================

HEARTBEAT_INTERVAL_SECONDS = int(os.environ.get("SOAR_WORKER_BREAKER_HEARTBEAT_INTERVAL", str(15 * 60)))

_breaker_runtime_state = {"last_heartbeat_ts": 0.0}


def reset_breaker_runtime_state_for_tests():
    _breaker_runtime_state["last_heartbeat_ts"] = 0.0


def _heartbeat_due(now: float) -> bool:
    if now - _breaker_runtime_state["last_heartbeat_ts"] >= HEARTBEAT_INTERVAL_SECONDS:
        _breaker_runtime_state["last_heartbeat_ts"] = now
        return True
    return False


def _counting_floor_ts(watermark_ts, window_seconds=3600, now=None):
    now = now if now is not None else time.time()
    floor_candidates = [now - window_seconds]
    if watermark_ts is not None:
        floor_candidates.append(watermark_ts)
    return max(floor_candidates)


def _count_recent_events(event_names, audit_log_path, since_ts):
    count = 0
    try:
        with open(audit_log_path, encoding="utf-8") as f:
            for line in f:
                try:
                    d = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if d.get("event") not in event_names:
                    continue
                ts = d.get("ts")
                if not ts:
                    continue
                try:
                    t = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
                except ValueError:
                    continue
                if t >= since_ts:
                    count += 1
    except FileNotFoundError:
        return 0
    return count


def circuit_breaker_tripped(store_dir: str = None) -> bool:
    store_dir = store_dir or WORKER_STATE_DIR
    return os.path.exists(os.path.join(store_dir, "CIRCUIT_BREAKER_TRIPPED"))


def _breaker_counts(audit_log_path, watermark_ts) -> dict:
    since_ts = _counting_floor_ts(watermark_ts)
    cases = _count_recent_events({"agent_case_created"}, audit_log_path, since_ts)
    emails = _count_recent_events({"agent_notification_mailer_accepted"}, audit_log_path, since_ts)
    return {"cases": cases, "emails": emails, "since_ts": since_ts}


def circuit_breaker_status(audit_log_path, store_dir: str = None, watermark_ts=None) -> dict:
    """Read-only. Never mutates state, never audits. Safe to call as often as needed."""
    store_dir = store_dir or WORKER_STATE_DIR
    breaker_file = os.path.join(store_dir, "CIRCUIT_BREAKER_TRIPPED")
    counts = _breaker_counts(audit_log_path, watermark_ts)
    tripped = os.path.exists(breaker_file)
    trip_detail = None
    if tripped:
        try:
            with open(breaker_file, encoding="utf-8") as f:
                trip_detail = json.load(f)
        except (OSError, json.JSONDecodeError):
            trip_detail = {"error": "trip marker unreadable"}
    return {
        "tripped": tripped, "trip_detail": trip_detail,
        "cases_in_window": counts["cases"], "emails_in_window": counts["emails"],
        "max_cases_per_window": MAX_CASES_PER_HOUR, "max_emails_per_window": MAX_EMAILS_PER_HOUR,
        "counting_since_iso": datetime.fromtimestamp(counts["since_ts"], tz=timezone.utc).isoformat(),
    }


def check_circuit_breaker(audit_log_path, store_dir: str = None, watermark_ts=None) -> dict:
    """
    Returns {"tripped": bool, "reason": str|None, "cases_last_hour": int|None,
    "emails_last_hour": int|None, "is_new_trip": bool, "heartbeat_due": bool}.

    Counting window is max(now - 1h, watermark_ts) — never reaches into a
    prior activation epoch. If the limits are exceeded and the breaker was
    not already tripped, WRITES the trip marker (persistent — survives
    restart) and requires an explicit administrative reset (never a
    manual file deletion) to resume. `is_new_trip` is True ONLY on the
    exact untripped->tripped transition, so the caller can audit exactly
    once per genuine trip rather than once per poll cycle.
    """
    store_dir = store_dir or WORKER_STATE_DIR
    breaker_file = os.path.join(store_dir, "CIRCUIT_BREAKER_TRIPPED")
    now = time.time()

    if os.path.exists(breaker_file):
        return {"tripped": True, "reason": "circuit breaker already tripped — administrative reset required",
               "cases_last_hour": None, "emails_last_hour": None,
               "is_new_trip": False, "heartbeat_due": _heartbeat_due(now)}

    counts = _breaker_counts(audit_log_path, watermark_ts)
    cases, emails = counts["cases"], counts["emails"]

    if cases >= MAX_CASES_PER_HOUR or emails >= MAX_EMAILS_PER_HOUR:
        reason = (f"circuit breaker tripped: {cases} case(s)/{emails} email(s) since "
                 f"{datetime.fromtimestamp(counts['since_ts'], tz=timezone.utc).isoformat()} "
                 f"(limits {MAX_CASES_PER_HOUR}/{MAX_EMAILS_PER_HOUR})")
        os.makedirs(store_dir, exist_ok=True)
        with open(breaker_file, "w", encoding="utf-8") as f:
            f.write(json.dumps({"tripped_at": datetime.now(timezone.utc).isoformat(),
                               "cases_in_window": cases, "emails_in_window": emails,
                               "counting_since_iso": datetime.fromtimestamp(
                                   counts["since_ts"], tz=timezone.utc).isoformat()}))
        _breaker_runtime_state["last_heartbeat_ts"] = now  # next heartbeat waits a full interval
        return {"tripped": True, "reason": reason, "cases_last_hour": cases, "emails_last_hour": emails,
               "is_new_trip": True, "heartbeat_due": False}

    return {"tripped": False, "reason": None, "cases_last_hour": cases, "emails_last_hour": emails,
           "is_new_trip": False, "heartbeat_due": False}


def reset_circuit_breaker(reason: str, audit_log_path, store_dir: str = None,
                          watermark_ts=None) -> dict:
    """
    Administrative reset — the ONLY sanctioned way to clear a trip; never
    delete the marker file by hand. Requires a non-empty reason, and
    REFUSES if the current rolling/epoch-bounded count is still at or
    above threshold (a reset can only ever confirm conditions have
    genuinely improved, never override an active real trip). Writes a
    sanitized audit event on both success and refusal.

    Returns {"reset": bool, "error": str|None, "cases_in_window": int,
    "emails_in_window": int}.
    """
    store_dir = store_dir or WORKER_STATE_DIR
    breaker_file = os.path.join(store_dir, "CIRCUIT_BREAKER_TRIPPED")
    reason = (reason or "").strip()

    if not reason:
        orch.audit("l2_worker_circuit_breaker_reset_refused", detail="empty reason provided")
        return {"reset": False, "error": "a non-empty reason is required",
               "cases_in_window": None, "emails_in_window": None}

    if not os.path.exists(breaker_file):
        return {"reset": False, "error": "circuit breaker is not currently tripped — nothing to reset",
               "cases_in_window": None, "emails_in_window": None}

    status = circuit_breaker_status(audit_log_path, store_dir=store_dir, watermark_ts=watermark_ts)
    if status["cases_in_window"] >= MAX_CASES_PER_HOUR or status["emails_in_window"] >= MAX_EMAILS_PER_HOUR:
        orch.audit("l2_worker_circuit_breaker_reset_refused",
                  reason=sanitization.redact_secrets(reason),
                  cases_in_window=status["cases_in_window"], emails_in_window=status["emails_in_window"])
        return {"reset": False,
               "error": f"rolling count still at/above threshold "
                        f"({status['cases_in_window']} case(s)/{status['emails_in_window']} email(s), "
                        f"limits {MAX_CASES_PER_HOUR}/{MAX_EMAILS_PER_HOUR}) — refusing to override an "
                        f"active trip",
               "cases_in_window": status["cases_in_window"], "emails_in_window": status["emails_in_window"]}

    os.remove(breaker_file)
    reset_breaker_runtime_state_for_tests()
    orch.audit("l2_worker_circuit_breaker_reset", reason=sanitization.redact_secrets(reason),
              cases_in_window=status["cases_in_window"], emails_in_window=status["emails_in_window"])
    return {"reset": True, "error": None, "cases_in_window": status["cases_in_window"],
           "emails_in_window": status["emails_in_window"]}


# ==============================================================================
# Health reporting
# ==============================================================================

def write_health(status: str, extra: dict = None, health_file: str = None):
    health_file = health_file or HEALTH_FILE
    payload = {"status": status, "updated_at": datetime.now(timezone.utc).isoformat(),
              "pid": os.getpid(), **(extra or {})}
    try:
        os.makedirs(os.path.dirname(health_file), exist_ok=True)
        tmp = health_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, health_file)
    except OSError:
        pass  # health reporting must never crash the worker


# ==============================================================================
# Invoking the existing one-shot orchestrator — never reimplemented
# ==============================================================================

def build_subprocess_env(alert_id: str, base_env: dict = None) -> dict:
    """
    The env for ONE orchestrator subprocess invocation. Starts from a
    COPY of this process's own environment (so THEHIVE_*/ES_*/CORTEX_ID/
    MAILER_RESPONDER_NAME/SOAR_L2_* already present in the worker's own
    env — from its EnvironmentFile — pass through unchanged), then sets
    the per-alert targeting and demo-allowlist variables, and explicitly
    ensures no containment-capable variable is present regardless of what
    the worker's own environment happens to contain (defense in depth on
    top of the systemd unit never placing them there in the first place).
    """
    env = dict(base_env if base_env is not None else os.environ)
    env["SOAR_ALERT_ID"] = alert_id
    env["SOAR_DEMO_ALLOWED_ALERT_ID"] = alert_id
    env["SOAR_DEMO_ACTION_MODE"] = "l2-only"
    env.pop("SOAR_DEMO_ALLOWED_IOC", None)  # l2-only never uses/needs one
    for forbidden in ("RESPONDER_NAME", "PFSENSE_HOST", "PFSENSE_SSH_USER",
                     "PFSENSE_SSH_PASSWORD", "PFSENSE_SSH_TIMEOUT", "PFSENSE_BLOCK_TABLE"):
        env.pop(forbidden, None)
    # armed + l2-only, explicit — never inherited/assumed
    env["SOAR_AGENT_DRY_RUN"] = "0"
    env["SOAR_AGENT_MODE"] = "armed"
    env["SOAR_DRY_RUN"] = "0"
    return env


def run_orchestrator_once(alert_id: str, python_exe: str = None, timeout: int = 300,
                          run_fn=None) -> dict:
    """
    Invokes agent_orchestrator.py as a subprocess for exactly one alert.
    Returns {"ok": bool, "returncode": int|None, "stdout_tail": str,
    "timed_out": bool}. `run_fn` is injectable (tests never spawn a real
    subprocess or touch a live TheHive/Ollama).
    """
    python_exe = python_exe or sys.executable
    env = build_subprocess_env(alert_id)
    run_fn = run_fn or subprocess.run
    try:
        proc = run_fn([python_exe, ORCHESTRATOR_PATH], env=env, capture_output=True,
                      text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "returncode": None, "stdout_tail": "", "timed_out": True}
    stdout_tail = sanitization.redact_secrets((proc.stdout or "")[-4000:])
    return {"ok": proc.returncode == 0, "returncode": proc.returncode,
           "stdout_tail": stdout_tail, "timed_out": False}


# ==============================================================================
# Retry classification
# ==============================================================================

TRANSIENT_EXCEPTIONS = (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
                        requests.exceptions.ChunkedEncodingError)


def is_transient_error(exc: Exception) -> bool:
    return isinstance(exc, TRANSIENT_EXCEPTIONS)


def retry_delay_seconds(attempt: int, base: float = 2.0, cap: float = 300.0) -> float:
    """Exponential backoff, bounded. attempt is 1-indexed."""
    return min(cap, base * (2 ** (attempt - 1)))


# ==============================================================================
# One full claim -> process -> resolve cycle for a single alert
# ==============================================================================

def process_one_alert(alert: dict, store_dir: str = None, run_fn=None, sleep_fn=None) -> dict:
    """
    Claims, invokes the orchestrator (with bounded exponential retry on
    transient failures), and resolves the claim. Returns a result dict
    for the caller's logging/audit. Never raises.
    """
    store_dir = store_dir or WORKER_STATE_DIR
    sleep_fn = sleep_fn or time.sleep
    alert_id = alert.get("_id") or alert.get("id")

    claimed = claim_alert(alert_id, store_dir=store_dir)
    if not claimed["claimed"]:
        prior = claimed["record"]
        return {"outcome": "skipped_duplicate", "alert_id": alert_id,
               "prior_status": prior.get("status")}

    orch.audit("l2_worker_claimed", alert_id=alert_id)

    attempt = 0
    last_error = None
    while attempt < MAX_RETRIES:
        attempt += 1
        try:
            result = run_orchestrator_once(alert_id, run_fn=run_fn)
        except Exception as exc:  # noqa: BLE001 — classify below, never crash the worker loop
            last_error = exc
            if is_transient_error(exc) and attempt < MAX_RETRIES:
                delay = retry_delay_seconds(attempt)
                orch.audit("l2_worker_retry", alert_id=alert_id, attempt=attempt,
                          delay_seconds=delay, error=type(exc).__name__)
                sleep_fn(delay)
                continue
            break
        else:
            if result["ok"]:
                complete_claim(alert_id, idempotency.STATUS_COMPLETED,
                              detail={"attempts": attempt}, store_dir=store_dir)
                orch.audit("l2_worker_processed", alert_id=alert_id, attempts=attempt)
                return {"outcome": "processed", "alert_id": alert_id, "attempts": attempt}
            # non-zero exit / timeout — could be transient (Ollama warmup,
            # a momentary TheHive blip) or permanent (a real code error).
            # Treat as transient up to MAX_RETRIES, same bounded backoff.
            if attempt < MAX_RETRIES:
                delay = retry_delay_seconds(attempt)
                orch.audit("l2_worker_retry", alert_id=alert_id, attempt=attempt,
                          delay_seconds=delay,
                          error=f"exit={result['returncode']} timed_out={result['timed_out']}")
                sleep_fn(delay)
                continue
            last_error = RuntimeError(f"orchestrator exit={result['returncode']}, "
                                      f"timed_out={result['timed_out']}")
            break

    # Retries exhausted — permanent failure, dead-letter. Never left as a
    # silently-stuck INTENDED claim: always resolved to FAILED so a human
    # (or a later, deliberate manual retry) has a clear signal.
    complete_claim(alert_id, idempotency.STATUS_FAILED,
                  detail={"attempts": attempt, "error": sanitization.redact_secrets(str(last_error))},
                  store_dir=store_dir)
    orch.audit("l2_worker_dead_letter", alert_id=alert_id, attempts=attempt,
              error=type(last_error).__name__ if last_error else "unknown")
    return {"outcome": "dead_letter", "alert_id": alert_id, "attempts": attempt}


# ==============================================================================
# One poll cycle
# ==============================================================================

def run_one_poll_cycle(thehive_url, thehive_api_key, watermark_ts, store_dir=None,
                       audit_log_path=None, session=None, run_fn=None, sleep_fn=None) -> dict:
    store_dir = store_dir or WORKER_STATE_DIR
    audit_log_path = audit_log_path or orch.AUDIT_LOG

    # Note: the kill switch does not gate the WORKER's own polling/claim
    # loop — it gates CONTAINMENT inside each orchestrator subprocess,
    # freshly re-checked by that subprocess on every single invocation.
    # l2-only mode never attempts containment regardless, so there is
    # nothing here for the kill switch to additionally block.

    breaker = check_circuit_breaker(audit_log_path, store_dir=store_dir, watermark_ts=watermark_ts)
    if breaker["tripped"]:
        if breaker["is_new_trip"]:
            orch.audit("l2_worker_circuit_breaker_tripped", reason=breaker["reason"])
        elif breaker["heartbeat_due"]:
            orch.audit("l2_worker_circuit_breaker_heartbeat", reason=breaker["reason"])
        write_health("circuit_breaker_tripped", {"reason": breaker["reason"]})
        return {"outcome": "circuit_breaker_tripped", "reason": breaker["reason"]}

    try:
        alerts = fetch_candidate_alerts(thehive_url, thehive_api_key, session=session)
    except Exception as exc:
        orch.audit("l2_worker_poll_failed", error=sanitization.redact_secrets(str(exc)))
        write_health("poll_failed", {"error": type(exc).__name__})
        return {"outcome": "poll_failed", "error": type(exc).__name__}

    orch.audit("l2_worker_poll", candidates=len(alerts))

    # Fetched newest-first (see fetch_candidate_alerts) so new alerts are
    # never starved by backlog; processed oldest-first within that window
    # so a burst of several new eligible alerts still resolves in FIFO
    # order rather than newest-always-wins.
    for alert in sorted(alerts, key=lambda a: _created_at_seconds(a) or 0):
        elig = is_eligible_alert(alert, watermark_ts)
        if not elig["eligible"]:
            continue
        result = process_one_alert(alert, store_dir=store_dir, run_fn=run_fn, sleep_fn=sleep_fn)
        write_health("processed_one", {"last_result": result["outcome"]})
        return {"outcome": "processed_one", "detail": result}

    write_health("idle", {"candidates_seen": len(alerts)})
    return {"outcome": "idle", "candidates_seen": len(alerts)}


# ==============================================================================
# Main loop
# ==============================================================================

def main():
    if not orch.THEHIVE_API_KEY:
        sys.exit("THEHIVE_API_KEY not set")

    watermark_raw = os.environ.get("SOAR_WORKER_WATERMARK_ISO", "")
    watermark_ts = _parse_watermark(watermark_raw)
    if watermark_ts is None:
        sys.exit("SOAR_WORKER_WATERMARK_ISO is required and must be a valid ISO-8601 timestamp — "
                "refusing to start without an explicit deployment watermark (never guess a default, "
                "never silently fall back to processing the entire backlog)")

    print("=" * 70)
    print("  L2-ONLY WORKER (Phase 8G) — permanent action mode: l2-only")
    print(f"  Watermark      : {watermark_raw}")
    print(f"  Poll interval  : {POLL_INTERVAL_SECONDS}s")
    print(f"  Trusted sources: {sorted(TRUSTED_SOURCES)}")
    print(f"  Excluded tags  : {EXCLUDED_TAG_SUBSTRINGS}")
    print(f"  Circuit breaker: {MAX_CASES_PER_HOUR} case(s)/hr, {MAX_EMAILS_PER_HOUR} email(s)/hr")
    print(f"  Kill switch    : {'ACTIVE' if orch.kill_switch_active() else 'inactive'}")
    print("=" * 70)

    install_signal_handlers()
    orch.audit("l2_worker_started", watermark=watermark_raw)

    try:
        while True:
            if is_shutdown_requested():
                break
            run_one_poll_cycle(orch.THEHIVE_URL, orch.THEHIVE_API_KEY, watermark_ts)
            if ONE_CYCLE_ONLY:
                break
            for _ in range(POLL_INTERVAL_SECONDS):
                if is_shutdown_requested():
                    break
                time.sleep(1)
    finally:
        orch.audit("l2_worker_shutdown", graceful=True)
        write_health("stopped")
        print("L2 worker shut down cleanly.")


if __name__ == "__main__":
    main()
