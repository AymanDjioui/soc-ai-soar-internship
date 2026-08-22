#!/usr/bin/env python3
"""
Independent pfSense containment verification (Phase 2).

A Cortex responder status of "Success" is NOT sufficient proof that an IP is
actually blocked — this module queries pfSense's own `EasyRuleBlockHostsWAN`
table directly (the same table the existing, unchanged Cortex responder writes
to) and requires EXACT IP membership before anything downstream (TruePositive
closure, the L1 auto-contained email, or an "executed" audit record) is allowed
to trust that a block genuinely happened.

Does NOT touch e2e_soc_orchestrator.py, does NOT reimplement the Cortex
responder call, does NOT create a second containment mechanism — this module
only adds the missing independent read-only verification step, reusing the
project's existing sshpass/SSH access pattern (the same one used manually
throughout this project for pfSense queries), credentials read from env vars
only, never hardcoded.

Network I/O is isolated in `_ssh_pfctl_show()` — every other function here is
pure and unit-testable without touching a live host. Tests ALWAYS inject a fake
`ssh_runner`; production code never does (falls back to the real SSH call).
"""
import ipaddress
import os
import subprocess
from datetime import datetime, timezone

PFSENSE_HOST = os.environ.get("PFSENSE_HOST", "100.70.145.65")
PFSENSE_SSH_USER = os.environ.get("PFSENSE_SSH_USER", "admin")
# Never hardcoded — must be set in the environment for any LIVE query to work.
PFSENSE_SSH_PASSWORD = os.environ.get("PFSENSE_SSH_PASSWORD")
PFSENSE_SSH_TIMEOUT = int(os.environ.get("PFSENSE_SSH_TIMEOUT", "20"))
BLOCK_TABLE_NAME = os.environ.get("PFSENSE_BLOCK_TABLE", "EasyRuleBlockHostsWAN")

RESULT_ABSENT = "ABSENT"
RESULT_PRESENT = "PRESENT"
RESULT_QUERY_FAILED = "QUERY_FAILED"
RESULT_AMBIGUOUS = "AMBIGUOUS"


class PfSenseQueryError(Exception):
    """Raised by the network layer only — callers must treat this as
    QUERY_FAILED, never as ABSENT (absence must be POSITIVELY confirmed by a
    successful query that didn't find the IP, not inferred from an error)."""


# ==============================================================================
# Gate 1 (the IP-validation piece) — pure, no network.
# ==============================================================================

def validate_target_ip(raw):
    """
    Parse `raw` with Python's `ipaddress` module. Raises ValueError on anything
    malformed. Never constructs a command from an unvalidated raw string — every
    caller in this module goes through this first.
    """
    if raw is None or not str(raw).strip():
        raise ValueError("empty target IP")
    return ipaddress.ip_address(str(raw).strip())


# ==============================================================================
# Table parsing — pure, no network. EXACT membership only, never substring.
# ==============================================================================

def parse_pfctl_table(raw_output: str) -> set:
    """
    Parse `pfctl -t <table> -T show` output into a set of normalized
    `ipaddress` objects (one per line; a `/32`-style CIDR suffix, which some pf
    builds emit, is tolerated and reduced to its network address). Unparseable
    lines are skipped, not fatal — a malformed line elsewhere in the table must
    not hide a normal legitimate entry.

    Deliberately returns real `ipaddress` OBJECTS, not strings — "is target in
    this set" is then true equality on parsed addresses, never a text
    substring/`in`-on-string check (which would wrongly match "202.61.130.16"
    against a query for "202.61.130.163").
    """
    ips = set()
    for line in (raw_output or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if "/" in line:
                net = ipaddress.ip_network(line, strict=False)
                ips.add(net.network_address)
            else:
                ips.add(ipaddress.ip_address(line))
        except ValueError:
            continue
    return ips


# ==============================================================================
# Network I/O — the ONLY function here that touches a live host.
# ==============================================================================

def _ssh_pfctl_show(host=None, user=None, password=None, timeout=None) -> str:
    """Real SSH call. Never invoked by any test — tests inject `ssh_runner` into
    check_ip_in_pfsense_table() instead. Uses the same sshpass+SSH pattern
    already used manually throughout this project; credentials come from env
    vars only (PFSENSE_SSH_PASSWORD), never hardcoded here."""
    host = host or PFSENSE_HOST
    user = user or PFSENSE_SSH_USER
    password = password if password is not None else PFSENSE_SSH_PASSWORD
    timeout = timeout or PFSENSE_SSH_TIMEOUT
    if not password:
        raise PfSenseQueryError("PFSENSE_SSH_PASSWORD not set — cannot query pfSense")
    # The pfctl command itself is a fixed literal (table name comes from an env
    # var meant for config, not attacker-controlled data) — no IP or other
    # unvalidated string is ever interpolated into this command.
    cmd = ["sshpass", "-p", password, "ssh",
           "-o", "StrictHostKeyChecking=accept-new", "-o", f"ConnectTimeout={timeout}",
           f"{user}@{host}", f"pfctl -t {BLOCK_TABLE_NAME} -T show"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    except subprocess.TimeoutExpired as exc:
        raise PfSenseQueryError(f"SSH to pfSense timed out: {exc}")
    except Exception as exc:
        raise PfSenseQueryError(f"SSH to pfSense failed: {exc}")
    if proc.returncode != 0:
        raise PfSenseQueryError(f"pfctl query failed (rc={proc.returncode}): {proc.stderr[:300]}")
    return proc.stdout


# ==============================================================================
# The public check — orchestrates validation + (injected or real) query + parse.
# ==============================================================================

def check_ip_in_pfsense_table(target_ip: str, ssh_runner=None) -> dict:
    """
    Independent, read-only check of whether `target_ip` is in the pfSense block
    table RIGHT NOW. `ssh_runner` is an injectable zero-arg callable returning
    raw pfctl output — defaults to the real `_ssh_pfctl_show`; every test
    supplies a fake so this function never touches a live host in a test run.

    Returns:
        {"result": ABSENT | PRESENT | QUERY_FAILED | AMBIGUOUS,
         "target_ip": <normalized str, or the raw input if unparseable>,
         "checked_at": <iso8601 timestamp>,
         "table_size": <int, or None if the query never completed>,
         "error": <str, or None>}

    AMBIGUOUS is reserved for a malformed target (can't even ask the question).
    QUERY_FAILED covers every network/SSH/parsing-level failure to get an
    answer. Only ABSENT/PRESENT come from a successful query that returned a
    parseable table.
    """
    checked_at = datetime.now(timezone.utc).isoformat()
    try:
        ip_obj = validate_target_ip(target_ip)
    except ValueError as exc:
        return {"result": RESULT_AMBIGUOUS, "target_ip": target_ip, "checked_at": checked_at,
                "table_size": None, "error": f"invalid target IP: {exc}"}

    runner = ssh_runner or _ssh_pfctl_show
    try:
        raw = runner()
    except PfSenseQueryError as exc:
        return {"result": RESULT_QUERY_FAILED, "target_ip": str(ip_obj), "checked_at": checked_at,
                "table_size": None, "error": str(exc)}
    except Exception as exc:
        return {"result": RESULT_QUERY_FAILED, "target_ip": str(ip_obj), "checked_at": checked_at,
                "table_size": None, "error": f"unexpected error querying pfSense: {exc}"}

    table = parse_pfctl_table(raw)
    present = ip_obj in table
    return {"result": RESULT_PRESENT if present else RESULT_ABSENT,
            "target_ip": str(ip_obj), "checked_at": checked_at,
            "table_size": len(table), "error": None}
