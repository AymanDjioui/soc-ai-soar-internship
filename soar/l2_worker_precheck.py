#!/usr/bin/env python3
"""
ExecStartPre health/safety assertion for soar-agent-l2-worker.service.

Checks, in order (first failure exits nonzero, aborting the start):
  1. THEHIVE_API_KEY is present in the environment.
  2. SOAR_WORKER_WATERMARK_ISO is present and parses as a valid ISO-8601
     timestamp (the worker's own main() re-checks this too, but failing
     here means systemd never even attempts ExecStart).
  3. The kill switch PATH resolves to an absolute path (existence is not
     required here — an absent kill switch means "inactive", which is a
     valid, if less-safe, state the orchestrator itself checks fresh on
     every invocation; this script only guards against a broken/empty
     path configuration).
  4. Ollama is reachable at OLLAMA_BASE_URL (a real HTTP GET, no
     inference — read-only, matches Ollama's own health-check style).

Never touches TheHive/Cortex/pfSense. No secret value is ever printed.
"""
import os
import sys

import requests

errors = []

if not os.environ.get("THEHIVE_API_KEY"):
    errors.append("THEHIVE_API_KEY is not set")

watermark_raw = os.environ.get("SOAR_WORKER_WATERMARK_ISO", "")
if not watermark_raw:
    errors.append("SOAR_WORKER_WATERMARK_ISO is not set")
else:
    try:
        from datetime import datetime
        datetime.fromisoformat(watermark_raw.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"SOAR_WORKER_WATERMARK_ISO={watermark_raw!r} is not a valid ISO-8601 timestamp")

kill_switch = os.environ.get("SOAR_KILL_SWITCH", "")
if not kill_switch or not os.path.isabs(kill_switch):
    errors.append(f"SOAR_KILL_SWITCH must be an absolute path (got {kill_switch!r})")

ollama_base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
try:
    r = requests.get(f"{ollama_base.rstrip('/')}/api/tags", timeout=10)
    r.raise_for_status()
except Exception as exc:
    errors.append(f"Ollama not reachable at {ollama_base}: {type(exc).__name__}")

if errors:
    for e in errors:
        print(f"L2-WORKER PRECHECK FAILED: {e}", file=sys.stderr)
    sys.exit(1)

print(f"L2-WORKER PRECHECK PASSED: watermark={watermark_raw!r}, "
     f"kill_switch_path={kill_switch!r}, Ollama reachable")
sys.exit(0)
