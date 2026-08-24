#!/usr/bin/env python3
"""
Administrative status/reset interface for the L2 worker's circuit
breaker (Phase 8G.1). This is the ONLY sanctioned way to clear a trip —
never delete the CIRCUIT_BREAKER_TRIPPED marker file by hand. A reset
requires an explicit --reason, is refused if the rolling/epoch-bounded
action count is still at or above threshold, and writes a sanitized
audit event either way.

Usage:
    python3 l2_worker_admin.py status
    python3 l2_worker_admin.py reset --reason "soak-test history aged out, verified below threshold"

Reads THEHIVE_API_KEY (existence only, not used here directly),
SOAR_WORKER_WATERMARK_ISO, SOAR_WORKER_STATE_DIR, and SOAR_AUDIT_LOG
from the environment — the same variables the worker service itself
uses, so run this with the same environment the unit has (e.g. via
`systemctl show soar-agent-l2-worker.service --property=Environment`
sourced, or as a companion ad-hoc invocation with the same exports).
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import e2e_soc_orchestrator as orch  # noqa: E402
import l2_worker as w  # noqa: E402


def _watermark_ts():
    raw = os.environ.get("SOAR_WORKER_WATERMARK_ISO", "")
    return w._parse_watermark(raw), raw


def main():
    parser = argparse.ArgumentParser(description="L2 worker circuit-breaker admin interface")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="Read-only circuit-breaker status")
    reset_p = sub.add_parser("reset", help="Administratively reset a tripped circuit breaker")
    reset_p.add_argument("--reason", required=True,
                         help="Required, non-empty justification, written to the audit log")
    args = parser.parse_args()

    watermark_ts, watermark_raw = _watermark_ts()
    if watermark_ts is None:
        sys.exit(f"SOAR_WORKER_WATERMARK_ISO={watermark_raw!r} is not set/valid — "
                "cannot determine the counting scope. Refusing to proceed.")

    store_dir = os.environ.get("SOAR_WORKER_STATE_DIR") or w.WORKER_STATE_DIR
    audit_log_path = os.environ.get("SOAR_AUDIT_LOG") or orch.AUDIT_LOG

    if args.cmd == "status":
        status = w.circuit_breaker_status(audit_log_path, store_dir=store_dir, watermark_ts=watermark_ts)
        print(json.dumps(status, indent=2))
        return

    if args.cmd == "reset":
        result = w.reset_circuit_breaker(args.reason, audit_log_path, store_dir=store_dir,
                                         watermark_ts=watermark_ts)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result.get("reset") else 1)


if __name__ == "__main__":
    main()
