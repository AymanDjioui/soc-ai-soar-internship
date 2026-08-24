#!/usr/bin/env python3
"""
Tests for demo_allowlist.py (Phase 8F) — the deterministic, opt-in gate for
controlled live demonstrations.

PURE. No network, no live TheHive/Cortex/pfSense/Ollama. All idempotency
state lives in a throwaway temp directory removed at the end of the run.

Run: ./.venv/bin/python3 test_demo_allowlist.py
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import demo_allowlist as da

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name); print(f"  PASS  {name}")
    else:
        FAIL.append(name); print(f"  FAIL  {name}  {detail}")


STORE = tempfile.mkdtemp(prefix="demo_allowlist_test_")


def fresh_dir():
    return tempfile.mkdtemp(prefix="demo_allowlist_test_", dir=STORE)


def clear_env():
    for k in ("SOAR_DEMO_ALLOWED_ALERT_ID", "SOAR_DEMO_ACTION_MODE", "SOAR_DEMO_ALLOWED_IOC"):
        os.environ.pop(k, None)


# ==============================================================================
# 1. Unconfigured process — no-op, refuses (not "unrestricted" for check_run)
# ==============================================================================

print("\n=== 1. unconfigured process ===")
clear_env()
r = da.check_run("~1", "l2-only", store_dir=fresh_dir())
check("check_run refuses when nothing is configured", r["allowed"] is False)
check("containment_permitted is unrestricted (True) when action_mode is None",
     da.containment_permitted("203.0.113.5", None) is True)


# ==============================================================================
# 2. Correctly configured — l2-only mode allows the run, forbids containment
# ==============================================================================

print("\n=== 2. correctly configured, l2-only ===")
clear_env()
os.environ["SOAR_DEMO_ALLOWED_ALERT_ID"] = "~204900001"
os.environ["SOAR_DEMO_ACTION_MODE"] = "l2-only"
d = fresh_dir()
r = da.check_run("~204900001", "l2-only", store_dir=d)
check("check_run allows the exact allow-listed alert+mode", r["allowed"] is True)
check("containment is forbidden in l2-only mode regardless of IOC",
     da.containment_permitted("203.0.113.5", "l2-only") is False)
check("containment is forbidden in l2-only mode even with no IOC",
     da.containment_permitted(None, "l2-only") is False)


# ==============================================================================
# 3. Incorrect alert — refused
# ==============================================================================

print("\n=== 3. incorrect alert id ===")
clear_env()
os.environ["SOAR_DEMO_ALLOWED_ALERT_ID"] = "~204900001"
os.environ["SOAR_DEMO_ACTION_MODE"] = "l2-only"
r = da.check_run("~999999999", "l2-only", store_dir=fresh_dir())
check("wrong alert id is refused", r["allowed"] is False)
check("refusal reason names the mismatch", "not the allow-listed alert" in r["reason"])


# ==============================================================================
# 4. Incorrect action mode — refused
# ==============================================================================

print("\n=== 4. incorrect action mode ===")
clear_env()
os.environ["SOAR_DEMO_ALLOWED_ALERT_ID"] = "~204900001"
os.environ["SOAR_DEMO_ACTION_MODE"] = "l2-only"
r = da.check_run("~204900001", "l1-containment", store_dir=fresh_dir())
check("mismatched action_mode is refused", r["allowed"] is False)

r2 = da.check_run("~204900001", "not-a-real-mode", store_dir=fresh_dir())
check("an unrecognized action_mode is refused", r2["allowed"] is False)


# ==============================================================================
# 5. Incorrect IOC in l1-containment mode — refused
# ==============================================================================

print("\n=== 5. incorrect IOC, l1-containment mode ===")
clear_env()
os.environ["SOAR_DEMO_ALLOWED_ALERT_ID"] = "~204900002"
os.environ["SOAR_DEMO_ACTION_MODE"] = "l1-containment"
os.environ["SOAR_DEMO_ALLOWED_IOC"] = "198.51.100.77"
check("wrong IOC is refused", da.containment_permitted("203.0.113.99", "l1-containment") is False)
check("correct IOC is permitted", da.containment_permitted("198.51.100.77", "l1-containment") is True)
check("empty/None IOC is refused even in l1-containment mode",
     da.containment_permitted(None, "l1-containment") is False)

# l1-containment mode with SOAR_DEMO_ALLOWED_IOC unset entirely -> check_run itself refuses
clear_env()
os.environ["SOAR_DEMO_ALLOWED_ALERT_ID"] = "~204900002"
os.environ["SOAR_DEMO_ACTION_MODE"] = "l1-containment"
r = da.check_run("~204900002", "l1-containment", store_dir=fresh_dir())
check("l1-containment mode with no IOC configured at all is refused at check_run",
     r["allowed"] is False)


# ==============================================================================
# 6. Replay — the second call on the same (alert_id, action_mode) is refused
# ==============================================================================

print("\n=== 6. replay protection ===")
clear_env()
os.environ["SOAR_DEMO_ALLOWED_ALERT_ID"] = "~204900003"
os.environ["SOAR_DEMO_ACTION_MODE"] = "l2-only"
d = fresh_dir()
r1 = da.check_run("~204900003", "l2-only", store_dir=d)
check("first claim succeeds", r1["allowed"] is True)
r2 = da.check_run("~204900003", "l2-only", store_dir=d)
check("replay of the exact same (alert_id, action_mode) is refused", r2["allowed"] is False)
check("replay refusal reason mentions replay", "replay" in r2["reason"].lower())

# a DIFFERENT alert_id is a distinct claim key — not blocked by the above
os.environ["SOAR_DEMO_ALLOWED_ALERT_ID"] = "~204900004"
r3 = da.check_run("~204900004", "l2-only", store_dir=d)
check("a different allow-listed alert id gets its own independent claim", r3["allowed"] is True)


# ==============================================================================
# 7. Missing variables — every combination of unset vars refuses cleanly
# ==============================================================================

print("\n=== 7. missing variables ===")
clear_env()
r = da.check_run("~1", "l2-only", store_dir=fresh_dir())
check("nothing set at all -> refused", r["allowed"] is False)

clear_env()
os.environ["SOAR_DEMO_ACTION_MODE"] = "l2-only"
r = da.check_run("~1", "l2-only", store_dir=fresh_dir())
check("only action_mode set, no alert id -> refused", r["allowed"] is False)

clear_env()
os.environ["SOAR_DEMO_ALLOWED_ALERT_ID"] = "~1"
r = da.check_run("~1", "l2-only", store_dir=fresh_dir())
check("only alert id set, no action_mode -> refused", r["allowed"] is False)


# ==============================================================================
# 8. Kill-switch behavior is untouched by this module (it is orthogonal —
#    demo_allowlist only ever adds an extra refusal, never bypasses the guard
#    or the kill switch, which live in e2e_soc_orchestrator/l1_policy).
# ==============================================================================

print("\n=== 8. kill switch remains an independent, unaffected control ===")
import e2e_soc_orchestrator as orch
_fd, _ks_path = tempfile.mkstemp(prefix="demo_allowlist_kill_switch_")
os.close(_fd)
_orig_ks = orch.KILL_SWITCH_FILE
try:
    orch.KILL_SWITCH_FILE = _ks_path
    check("kill switch detected active independent of demo_allowlist state",
         orch.kill_switch_active() is True)
    os.remove(_ks_path)
    check("kill switch detected inactive once removed", orch.kill_switch_active() is False)
finally:
    orch.KILL_SWITCH_FILE = _orig_ks
    if os.path.exists(_ks_path):
        os.remove(_ks_path)

# a passing demo_allowlist check does NOT itself touch or know about the kill
# switch — containment_allowed() (in e2e_soc_orchestrator.py) is what
# actually enforces it, unconditionally, regardless of demo_allowlist state.
check("demo_allowlist.containment_permitted has no kill-switch awareness by design "
     "(the guard enforces it separately, unconditionally)",
     "kill_switch" not in open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                            "demo_allowlist.py")).read().lower())


# ==============================================================================
# Summary
# ==============================================================================

if __name__ == "__main__":
    clear_env()
    print("\n" + "=" * 70)
    print(f"  DEMO ALLOW-LIST TESTS: {len(PASS)} passed, {len(FAIL)} failed")
    print("=" * 70)
    shutil.rmtree(STORE, ignore_errors=True)
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    sys.exit(0)
