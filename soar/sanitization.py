#!/usr/bin/env python3
"""
Side-effect-free shared redaction/sanitization primitives.

Extracted from `agent_orchestrator.py` (Phase 5/5.5) verbatim — same regex
patterns, same behavior — so Phase 7's dataset-building code can reuse the
SAME proven redaction logic without importing the full orchestrator (which
pulls in thehive4py, live-API-touching code, and module-level state that has
no business being imported just to redact a string).

Zero side effects: importing this module makes no network call, touches no
file, and has no dependency beyond the Python standard library (`re`,
`html`, `hashlib`). Safe to import from anywhere, including fully offline
dataset-build tooling and unit tests.

`agent_orchestrator.py` re-exports these under its original underscore-
prefixed names (`_redact_secrets`, `_sanitize_for_email`, `_mask_email`,
`_validate_email_address`) so every existing call site is unchanged — this
extraction is a pure refactor, proven by re-running the full existing test
suite (see L1-L2-SAFETY-AUDIT.md Phase 7A section).
"""
import hashlib
import html
import re

SECRET_PATTERNS = [
    re.compile(r'(?i)authorization\s*:\s*.+'),   # consume the WHOLE header value, not just one token
    re.compile(r'(?i)\bbearer\s+[a-z0-9\-_.]+'),
    re.compile(r'\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b'),   # JWT
    re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+'),
    re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*\S+'),
    re.compile(r'(?i)(secret|token)\s*[:=]\s*\S+'),
]

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# Unanchored variant — finds an email-SHAPED substring anywhere inside free
# text (a title/description), as opposed to EMAIL_RE which validates that an
# entire standalone string IS an address. Used by pseudonymize_identities().
EMAIL_IN_TEXT_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def redact_secrets(text) -> str:
    """Strip anything that looks like a credential/token/secret. Applied to
    every field sourced from an alert title/description, analyzer output, or
    agent-generated text — none of those are validated to be free of an
    accidentally-echoed secret (e.g. a raw HTTP request body reflected into
    an alert by a WAF rule, or an accidentally-logged auth header)."""
    if not text:
        return ""
    out = str(text)
    for pat in SECRET_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


def sanitize_for_email(value) -> str:
    """The SINGLE choke point every field passes through before insertion
    into an email subject/body: redact secrets, THEN HTML-escape. Treat every
    such field as untrusted, whatever its apparent source."""
    if value is None:
        return ""
    return html.escape(redact_secrets(str(value)))


def sanitize_text(value, html_escape: bool = False) -> str:
    """General-purpose sanitizer for non-email contexts (e.g. dataset build
    output, where HTML-escaping would corrupt attack-payload evaluative
    content like `<script>` in an XSS test case rather than protect anything
    — html_escape defaults to False here, unlike sanitize_for_email())."""
    if value is None:
        return ""
    out = redact_secrets(str(value))
    return html.escape(out) if html_escape else out


def validate_email_address(addr) -> bool:
    return bool(addr) and bool(EMAIL_RE.match(str(addr).strip()))


def mask_email(addr) -> str:
    """Never log/comment/reason-code a full recipient address. Keeps just
    enough shape (first local-part char, first domain-label char, TLD) to be
    useful for a human scanning logs, nothing an attacker or a careless
    paste could reuse."""
    addr = str(addr or "").strip()
    if "@" not in addr:
        return "***"
    local, _, domain = addr.partition("@")
    dom_parts = domain.split(".")
    masked_local = f"{local[0]}***" if local else "***"
    masked_domain = f"{dom_parts[0][0]}***.{'.'.join(dom_parts[1:])}" if dom_parts and dom_parts[0] else "***"
    return f"{masked_local}@{masked_domain}"


def correlation_id(key: str) -> str:
    """Short, stable id derived from an action/content key (not randomly
    generated) — the SAME input always produces the SAME id, so it can be
    grepped across an audit log, a sent email, or a dataset manifest."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


def sha256_hex(text: str) -> str:
    """Full (non-truncated) SHA-256 hex digest — used for dataset content
    hashes and manifest checksums (Phase 7), where truncation would raise
    the collision probability at a scale correlation_id() was never meant
    to operate at."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def contains_unredacted_secret(text) -> bool:
    """Secret-scan predicate: True if `text`, AS GIVEN, matches any secret
    pattern. Deliberately does NOT call redact_secrets() internally — this
    is a scan of whatever text is about to be written to disk, independent
    of whether (or how) it was already redacted upstream. Its value is
    defense-in-depth: it catches a field that redaction was accidentally
    SKIPPED for (a real, possible mistake in a dataset-build pipeline with
    many fields), not a claim that redact_secrets() itself can ever leave a
    residue (checking the redacted output against its own pattern list would
    be a tautological always-False check — this function checks the INPUT,
    which is the actually useful independent gate).

    Phase 7's dataset build calls this as the LAST step before writing any
    file — a non-empty match here fails the build outright, it does not
    silently re-redact and continue."""
    if not text:
        return False
    text = str(text)
    return any(pat.search(text) for pat in SECRET_PATTERNS)


def stable_pseudonym(value: str, salt: str, prefix: str = "anon") -> str:
    """A deterministic, non-reversible pseudonym for one identity value
    (an email, username, internal hostname, ...) — the SAME (value, salt)
    pair always produces the SAME pseudonym, so cross-record linkage is
    preserved (e.g. the same reporter appearing on 5 cases gets the same
    pseudonym on all 5, without ever storing the real value). `salt` should
    be a PER-EXPORT-RUN secret/constant, never a fixed literal shared across
    runs/datasets — without the salt, the mapping cannot be reversed even by
    someone who guesses the likely original value and hashes it themselves."""
    return f"{prefix}-{sha256_hex(f'{salt}:{value.strip().lower()}')[:10]}"


def pseudonymize_identities_in_text(text, salt: str) -> str:
    """Replace every email-shaped substring found in free text with a
    stable pseudonym (see stable_pseudonym()) — for content where an
    identity might be embedded INSIDE a title/description rather than
    living in its own dedicated field. Runs independently of
    redact_secrets(); apply both when sanitizing untrusted free text meant
    for a dataset export."""
    if not text:
        return ""
    text = str(text)
    def _replace(m):
        return stable_pseudonym(m.group(0), salt, prefix="anon-email")
    return EMAIL_IN_TEXT_RE.sub(_replace, text)
