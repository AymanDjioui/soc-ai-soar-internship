#!/usr/bin/env python3
"""
Tests for pfsense_verify.py — parsing, validation, and the check orchestration.

PURE. Every SSH-touching call is replaced with an injected fake `ssh_runner`.
No live pfSense is ever queried by this file.

Run: ./.venv/bin/python test_pfsense_verify.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pfsense_verify as pv

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name); print(f"  PASS  {name}")
    else:
        FAIL.append(name); print(f"  FAIL  {name}  {detail}")


# ==============================================================================
# 8. Exact matching prevents substring false positives
# ==============================================================================

print("\n=== 8. Exact matching — no substring false positives ===")
table = pv.parse_pfctl_table("202.61.130.16\n8.8.8.8\n")
r = pv.check_ip_in_pfsense_table("202.61.130.163", ssh_runner=lambda: "202.61.130.16\n8.8.8.8\n")
check("similar-but-different IP is NOT matched (would be a substring match bug)",
     r["result"] == pv.RESULT_ABSENT, r)
r2 = pv.check_ip_in_pfsense_table("202.61.130.16", ssh_runner=lambda: "202.61.130.16\n8.8.8.8\n")
check("the actually-present IP IS matched", r2["result"] == pv.RESULT_PRESENT, r2)


# ==============================================================================
# 9. IPv4 normalization
# ==============================================================================

print("\n=== 9. IPv4 normalization (whitespace, /32 CIDR suffix) ===")
r = pv.check_ip_in_pfsense_table("202.61.130.163",
                                 ssh_runner=lambda: "  202.61.130.163  \n8.8.8.8\n")
check("whitespace around table entries is stripped/normalized", r["result"] == pv.RESULT_PRESENT, r)
r2 = pv.check_ip_in_pfsense_table("202.61.130.163",
                                  ssh_runner=lambda: "202.61.130.163/32\n")
check("a /32 CIDR suffix normalizes to the bare address", r2["result"] == pv.RESULT_PRESENT, r2)
check("target_ip in the result is the normalized string",
     r["target_ip"] == "202.61.130.163")


# ==============================================================================
# 10. Malformed target is rejected
# ==============================================================================

print("\n=== 10. Malformed target IP is rejected ===")
raised = False
try:
    pv.validate_target_ip("not-an-ip-at-all")
except ValueError:
    raised = True
check("validate_target_ip raises ValueError on garbage input", raised)

r = pv.check_ip_in_pfsense_table("not-an-ip-at-all", ssh_runner=lambda: "8.8.8.8\n")
check("check_ip_in_pfsense_table returns AMBIGUOUS for a malformed target",
     r["result"] == pv.RESULT_AMBIGUOUS, r)
check("malformed target never reaches the ssh_runner (no query attempted)",
     r["error"] is not None and "invalid target IP" in r["error"])

r2 = pv.check_ip_in_pfsense_table("", ssh_runner=lambda: "8.8.8.8\n")
check("empty string target is also AMBIGUOUS, not a crash", r2["result"] == pv.RESULT_AMBIGUOUS)

r3 = pv.check_ip_in_pfsense_table(None, ssh_runner=lambda: "8.8.8.8\n")
check("None target is also AMBIGUOUS, not a crash", r3["result"] == pv.RESULT_AMBIGUOUS)


# ==============================================================================
# 11-13. Private / Tailscale-CGNAT / protected-asset rejection
# ==============================================================================
# NOTE: these three specific policy decisions ("is this address blockable at
# all") are e2e_soc_orchestrator.policy_guard()'s job, already proven correct
# in that module and reused UNCHANGED by the whole agent — pfsense_verify.py
# does not duplicate that logic (per "do not create a second containment
# implementation"). What THIS module can and does independently confirm is
# that validate_target_ip() correctly PARSES private/CGNAT addresses as valid
# IPs (they are not malformed — policy_guard(), not IP parsing, is what refuses
# them) and that ipaddress' own classification agrees with the guard's checks.

print("\n=== 11-13. Private/CGNAT/protected addresses parse fine; POLICY refusal is policy_guard()'s job (reused, not duplicated) ===")
priv = pv.validate_target_ip("192.168.10.20")
check("a private RFC1918 address parses as a valid IP (rejection is policy_guard's job)",
     priv.is_private is True)
cgnat = pv.validate_target_ip("100.99.54.59")
check("a Tailscale/CGNAT address parses as a valid IP",
     cgnat in __import__("ipaddress").ip_network("100.64.0.0/10"))

import e2e_soc_orchestrator as orch
ok1, reason1 = orch.policy_guard("192.168.10.20")
check("policy_guard still correctly refuses the private address (reused, unchanged)",
     ok1 is False and "RFC1918" in reason1, reason1)
ok2, reason2 = orch.policy_guard("100.99.54.59")
check("policy_guard still correctly refuses the explicitly-protected ELK server",
     ok2 is False and "protected" in reason2.lower(), reason2)
ok3, reason3 = orch.policy_guard("100.101.27.63")
check("policy_guard still correctly refuses an ordinary Tailscale/CGNAT address",
     ok3 is False and "CGNAT" in reason3, reason3)
ok4, reason4 = orch.policy_guard("202.61.130.163")
check("policy_guard still correctly ALLOWS a genuine external routable address",
     ok4 is True, reason4)


# ==============================================================================
# Query-failure / ambiguous outcomes (feeds Phase 2's precheck/postcheck logic)
# ==============================================================================

print("\n=== Query failure and ambiguous-table outcomes ===")
def raising_runner():
    raise pv.PfSenseQueryError("SSH timed out")
r = pv.check_ip_in_pfsense_table("8.8.8.8", ssh_runner=raising_runner)
check("an ssh_runner that raises PfSenseQueryError -> QUERY_FAILED, not ABSENT",
     r["result"] == pv.RESULT_QUERY_FAILED, r)
check("QUERY_FAILED never silently becomes 'confirmed absent'", r["result"] != pv.RESULT_ABSENT)

def unexpected_runner():
    raise RuntimeError("something else entirely")
r2 = pv.check_ip_in_pfsense_table("8.8.8.8", ssh_runner=unexpected_runner)
check("an UNEXPECTED exception from ssh_runner is also caught as QUERY_FAILED, not a crash",
     r2["result"] == pv.RESULT_QUERY_FAILED, r2)

r3 = pv.check_ip_in_pfsense_table("8.8.8.8", ssh_runner=lambda: "")
check("an empty (but successfully queried) table correctly means ABSENT",
     r3["result"] == pv.RESULT_ABSENT)
check("table_size is 0 for an empty table, not None", r3["table_size"] == 0)

r4 = pv.check_ip_in_pfsense_table("8.8.8.8",
                                  ssh_runner=lambda: "not-a-valid-line\n8.8.8.8\ngarbage###\n")
check("unparseable lines are skipped, valid entries still matched",
     r4["result"] == pv.RESULT_PRESENT, r4)
check("table_size only counts the parseable entries", r4["table_size"] == 1, r4)


# ==============================================================================
# Summary
# ==============================================================================

print("\n" + "=" * 70)
print(f"  PFSENSE VERIFY TESTS: {len(PASS)} passed, {len(FAIL)} failed")
print("=" * 70)
if FAIL:
    print("FAILED:")
    for f in FAIL:
        print("  -", f)
    sys.exit(1)
sys.exit(0)
