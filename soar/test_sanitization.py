#!/usr/bin/env python3
"""
Tests for the side-effect-free `sanitization.py` module (Phase 7A).

Covers: zero-import-side-effect proof, behavior parity with the pre-refactor
agent_orchestrator.py implementation (regression), and the new
Phase-7-specific additions (sanitize_text, sha256_hex, contains_unredacted_secret).

Run: ./.venv/bin/python test_sanitization.py
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sanitization as san

PASS, FAIL = [], []


def check(name, cond, detail=""):
    if cond:
        PASS.append(name); print(f"  PASS  {name}")
    else:
        FAIL.append(name); print(f"  FAIL  {name}  {detail}")


# ==============================================================================
# 1. Zero side effects on import — no network-capable module pulled in
# ==============================================================================

print("\n=== 1. importing sanitization.py has ZERO side effects ===")
proc = subprocess.run(
    [sys.executable, "-c",
     "import sys; import sanitization; "
     "leaked = [m for m in ('requests', 'thehive4py', 'socket') if m in sys.modules]; "
     "print('LEAKED:' + ','.join(leaked) if leaked else 'CLEAN')"],
    cwd=os.path.dirname(os.path.abspath(__file__)),
    capture_output=True, text=True, timeout=15)
check("import triggers no requests/thehive4py/socket import as a side effect",
     "CLEAN" in proc.stdout, proc.stdout + proc.stderr)


# ==============================================================================
# 2. Regression: exact behavior parity with the pre-refactor implementation
# ==============================================================================

print("\n=== 2. redact_secrets(): known cases still redact correctly ===")
jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
cases = [
    ("Authorization: Bearer abc123def456", "abc123def456"),
    ("bearer abc123def456xyz", "abc123def456xyz"),
    (jwt, jwt),
    ("api_key=sk-live-abcdef1234567890", "sk-live-abcdef1234567890"),
    ("password: SuperSecret123!", "SuperSecret123!"),
    ("secret=topsecretvalue", "topsecretvalue"),
]
for raw, needle in cases:
    redacted = san.redact_secrets(raw)
    check(f"redacted: {raw[:30]!r}", needle not in redacted and "[REDACTED]" in redacted, redacted)

print("\n=== 3. sanitize_for_email(): redact then HTML-escape, in that order ===")
malicious = "<script>alert('xss')</script> password: hunter2"
out = san.sanitize_for_email(malicious)
check("HTML is escaped", "<script>" not in out and "&lt;script&gt;" in out, out)
check("secret is redacted", "hunter2" not in out, out)
check("None input returns empty string", san.sanitize_for_email(None) == "")

print("\n=== 4. validate_email_address() / mask_email(): unchanged behavior ===")
check("valid address accepted", san.validate_email_address("a@b.com") is True)
check("invalid address rejected", san.validate_email_address("not-an-email") is False)
check("empty/None rejected", san.validate_email_address("") is False and san.validate_email_address(None) is False)
masked = san.mask_email("someone.specific@example.com")
check("local part hidden", "someone.specific" not in masked, masked)
check("domain label hidden", "example" not in masked, masked)
check("TLD kept", masked.endswith(".com"), masked)
check("no-@ input masked safely", san.mask_email("not-an-email") == "***")

print("\n=== 5. correlation_id(): deterministic, stable ===")
c1 = san.correlation_id("some-key")
c2 = san.correlation_id("some-key")
c3 = san.correlation_id("different-key")
check("same input -> same id", c1 == c2)
check("different input -> different id", c1 != c3)
check("12-char hex preview", len(c1) == 12)


# ==============================================================================
# 6. New Phase 7 additions
# ==============================================================================

print("\n=== 6. sanitize_text(): html_escape defaults False (preserves attack payload features) ===")
xss_payload = "<script>alert(1)</script>"
out_default = san.sanitize_text(xss_payload)
check("default (html_escape=False) preserves the raw markup shape for evaluative content",
     out_default == xss_payload, out_default)
out_escaped = san.sanitize_text(xss_payload, html_escape=True)
check("html_escape=True still escapes when explicitly requested",
     "<script>" not in out_escaped, out_escaped)
out_secret = san.sanitize_text("password: hunter2")
check("secrets still redacted regardless of html_escape", "hunter2" not in out_secret, out_secret)

print("\n=== 7. sha256_hex(): full, non-truncated, deterministic ===")
h1 = san.sha256_hex("some content")
h2 = san.sha256_hex("some content")
h3 = san.sha256_hex("different content")
check("64 hex chars (full digest, not truncated like correlation_id)", len(h1) == 64, h1)
check("deterministic", h1 == h2)
check("different content -> different hash", h1 != h3)

print("\n=== 8. contains_unredacted_secret(): fail-closed secret-scan gate ===")
check("clean text has no unredacted secret", san.contains_unredacted_secret("just a normal sentence") is False)
check("raw secret text (never redacted) IS flagged",
     san.contains_unredacted_secret("password: hunter2") is True)
check("already-redacted text (post redact_secrets) has nothing left to flag",
     san.contains_unredacted_secret(san.redact_secrets("password: hunter2")) is False)
check("empty/None input is never flagged",
     san.contains_unredacted_secret("") is False and san.contains_unredacted_secret(None) is False)


# ==============================================================================
# Summary
# ==============================================================================

print("\n=== 9. stable_pseudonym(): deterministic, salted, non-reversible-looking ===")
p1 = san.stable_pseudonym("alice@example.com", salt="run-1")
p2 = san.stable_pseudonym("alice@example.com", salt="run-1")
p3 = san.stable_pseudonym("alice@example.com", salt="run-2")
p4 = san.stable_pseudonym("bob@example.com", salt="run-1")
check("same (value, salt) -> same pseudonym", p1 == p2)
check("different salt -> different pseudonym for the SAME value", p1 != p3)
check("different value -> different pseudonym", p1 != p4)
check("pseudonym never contains the raw value", "alice" not in p1, p1)

print("\n=== 10. pseudonymize_identities_in_text(): replaces embedded emails, keeps other text ===")
text = "Reported by alice@example.com regarding a login from bob@corp.example"
out = san.pseudonymize_identities_in_text(text, salt="run-1")
check("neither raw email survives", "alice@example.com" not in out and "bob@corp.example" not in out, out)
check("non-identity text is preserved", "Reported by" in out and "regarding a login from" in out, out)
out2 = san.pseudonymize_identities_in_text(text, salt="run-1")
check("same salt on a second call -> identical replacement (stable across the run)", out == out2)
check("empty/None input returns empty string",
     san.pseudonymize_identities_in_text("", salt="run-1") == "" and
     san.pseudonymize_identities_in_text(None, salt="run-1") == "")


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print(f"  SANITIZATION TESTS: {len(PASS)} passed, {len(FAIL)} failed")
    print("=" * 70)
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    sys.exit(0)
