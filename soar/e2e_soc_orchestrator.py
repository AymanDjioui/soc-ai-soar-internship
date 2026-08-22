#!/usr/bin/env python3
"""
End-to-end SOAR + AI triage orchestrator.

    TheHive alert  ->  AI triage  ->  case  ->  Cortex enrichment
                   ->  AI verdict ->  POLICY GUARD  ->  containment

Devoteam internship — "SOAR and AI for Detection Improvement in the SOC"
Original pipeline: Badr.  Hardening / guardrails / prompt integration: Ayman.

------------------------------------------------------------------------------
DESIGN PRINCIPLE — the model informs, code decides.
------------------------------------------------------------------------------
The LLM is never asked whether an IP may be blocked. It produces an assessment
(verdict, severity, confidence, technique); `policy_guard()` — deterministic,
code-side, veto-only — decides whether that assessment is *allowed* to result in
a containment action.

This is not defensive over-engineering. It is a direct response to a measured
result during model benchmarking (see ai/results/prompt-iteration-log.md, v2):
when the schema included a `safe_to_auto_block` field, the model recommended
auto-blocking one of our OWN internal Windows hosts for emitting normal UPnP
discovery traffic. Additionally, 5 of the 7 cases in our golden test set must
never be auto-blocked, because our own attack traffic arrives over Tailscale.

A guard can therefore only ever REFUSE. It can never authorise.
------------------------------------------------------------------------------

Environment variables (no secrets in source):
    THEHIVE_URL          default http://100.124.232.121:9000
    THEHIVE_API_KEY      REQUIRED
    OLLAMA_BASE_URL      default http://100.90.228.58:11434  (ollama-l4-server, GPU)
    OLLAMA_MODEL         default mistral:7b
    SOAR_AUDIT_LOG       default <script dir>/soar_audit.jsonl   (absolute)
    SOAR_KILL_SWITCH     default <script dir>/KILL_SWITCH        (absolute)
    SOAR_MAX_BLOCKS_HOUR default 5
    SOAR_MIN_CONFIDENCE  default 0.75
    SOAR_DRY_RUN         set to 1 to log containment decisions without executing
    SOAR_MAX_ALERTS      stop after N alerts (default: unlimited)
    SOAR_ONCE            set to 1 for a single pass over the queue, then exit

Kill switch:  `touch KILL_SWITCH`  — halts all containment immediately.
             Triage and enrichment continue; only blocking is disabled.
"""

import ipaddress
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import requests

try:
    from thehive4py.client import TheHiveApi
except ImportError:
    sys.exit("thehive4py not installed:  pip install thehive4py")


# ==============================================================================
# CONFIGURATION
# ==============================================================================

THEHIVE_URL = os.environ.get("THEHIVE_URL", "http://100.124.232.121:9000")
THEHIVE_API_KEY = os.environ.get("THEHIVE_API_KEY")

# ollama-l4-server (GCP, NVIDIA L4) on the tailnet. This is the live LLM host.
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://100.90.228.58:11434")
OLLAMA_CHAT_URL = OLLAMA_BASE_URL.rstrip("/") + "/api/chat"
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "mistral:7b")
# 420s, not 180s. On the EC2 m7i-flex.large host (2 vCPU / ~1 physical core) a
# single schema-constrained triage measured 177.6s warm, and
# ai/results/deployment-latency.md records a 202.8s worst case. A 180s timeout
# sits *below* our own measured worst case, so it would fail the call, return
# None, and silently leave alerts for a human — looking like a model failure
# when it is really a client timeout.
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "420"))

# Both are resolved to ABSOLUTE paths, anchored next to this file rather than to
# the current working directory.
#
# This is a safety fix, not tidiness. When these were relative:
#   - `touch KILL_SWITCH` in the wrong directory left containment ARMED while the
#     operator believed it was disabled. A kill switch that depends on which
#     directory you happened to be standing in is not a kill switch.
#   - recent_block_count() reads the audit log, so running from a different
#     directory silently reset the rate limiter to zero.
#
# Setting SOAR_AUDIT_LOG / SOAR_KILL_SWITCH explicitly still works; a relative
# value given there is resolved against the current directory as the caller asked.
_HERE = os.path.dirname(os.path.abspath(__file__))

AUDIT_LOG = os.path.abspath(
    os.environ.get("SOAR_AUDIT_LOG") or os.path.join(_HERE, "soar_audit.jsonl"))
KILL_SWITCH_FILE = os.path.abspath(
    os.environ.get("SOAR_KILL_SWITCH") or os.path.join(_HERE, "KILL_SWITCH"))
MAX_BLOCKS_PER_HOUR = int(os.environ.get("SOAR_MAX_BLOCKS_HOUR", "5"))
MIN_CONFIDENCE_TO_ACT = float(os.environ.get("SOAR_MIN_CONFIDENCE", "0.75"))
DRY_RUN = os.environ.get("SOAR_DRY_RUN", "") == "1"

# Bounded runs. TheHive currently holds ~260 unprocessed alerts; without a bound,
# starting the orchestrator commits to processing all of them (roughly 70 s each).
#   SOAR_MAX_ALERTS=3   stop after 3 alerts
#   SOAR_ONCE=1         one pass over the queue, then exit instead of polling
MAX_ALERTS = int(os.environ.get("SOAR_MAX_ALERTS", "0")) or None
RUN_ONCE = os.environ.get("SOAR_ONCE", "") == "1"

# Process ONE specific alert by id and exit, instead of polling the queue.
#   SOAR_ALERT_ID='~123121912'
# Needed because the poll loop takes the oldest alert first, so with a large
# backlog there is otherwise no way to target the alert you just created.
TARGET_ALERT_ID = os.environ.get("SOAR_ALERT_ID", "").strip() or None

POLL_INTERVAL_SECONDS = 10
ANALYZER_JOB_TIMEOUT_SECONDS = 120
ANALYZER_POLL_INTERVAL_SECONDS = 3

# Observables land on a freshly promoted case asynchronously; retry before
# concluding there are none. See the fetch loop in process_single_alert().
OBSERVABLE_FETCH_ATTEMPTS = 5
OBSERVABLE_FETCH_DELAY_SECONDS = 2

CORTEX_ID = os.environ.get("CORTEX_ID", "Cortex-DevoteamSOC")
# The responder's NAME. Its Cortex id is a hash that changes on reinstall, so it is
# resolved at runtime by resolve_responder_id(). Passing the name as the id makes
# Cortex reject the job with "worker <name> not found", asynchronously, after the
# submit call has already returned successfully.
RESPONDER_NAME = os.environ.get("RESPONDER_NAME", "PfSense_Blocker_1_0")
MAILER_RESPONDER_NAME = os.environ.get("MAILER_RESPONDER_NAME", "Mailer_1_0")
MAILER_RECIPIENTS = ["emailjdid38@gmail.com", "aymandjioui17@gmail.com"]

ANALYZER_NAME_PREFIXES = [
    "VirusTotal_GetReport",
    "AbuseIPDB",
    "AlienVault_OTX",
    "URLhaus",
    "GreyNoise",   # added by Badr 2026-08-2x — mass-scanner vs targeted-attacker signal
    "Shodan_Host",  # added by Badr 2026-08-2x — investigation/exposure context
]

# Infrastructure that must never be blocked even if it somehow appears external.
# Belt-and-braces on top of the RFC1918 / CGNAT checks in policy_guard().
PROTECTED_ASSETS = {
    "192.168.10.2",     # pfSense LAN gateway
    "172.16.0.2",       # pfSense DMZ gateway
    "192.168.84.134",   # pfSense WAN
    "100.70.145.65",    # pfSense Tailscale
    "100.99.54.59",     # ELK / SIEM
    "100.124.232.121",  # TheHive / Cortex
    "100.96.231.95",    # soc-llm-aws  (EC2 CPU host, stopped but kept as baseline)
    "100.90.228.58",    # ollama-l4-server (GCP L4 GPU, current LLM host)
}


# ==============================================================================
# AUDIT TRAIL
# ==============================================================================

def audit(event: str, **fields):
    """Append one JSON-lines record. Every decision the pipeline makes is logged
    here — this is the evidence trail for any autonomous action."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except Exception as exc:                                  # never fail the pipeline on logging
        print(f"   [audit] WARNING could not write audit log: {exc}")
    return record


# ==============================================================================
# GUARDRAILS
# ==============================================================================

def kill_switch_active() -> bool:
    return os.path.exists(KILL_SWITCH_FILE)


def recent_block_count(window_hours: int = 1) -> int:
    """Count containment actions executed in the recent window, from the audit log."""
    if not os.path.exists(AUDIT_LOG):
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    count = 0
    try:
        with open(AUDIT_LOG, encoding="utf-8") as fh:
            for line in fh:
                # Parse each record independently. Previously a single malformed
                # entry (or one missing "ts") raised out of the whole loop and
                # returned a PARTIAL count, which under-reports blocks and so
                # allows more of them. A rate limiter must never fail open.
                try:
                    rec = json.loads(line)
                    if rec.get("event") != "containment_executed":
                        continue
                    if datetime.fromisoformat(rec["ts"]) >= cutoff:
                        count += 1
                except Exception:
                    continue
    except Exception as exc:
        # If the audit log cannot be read at all we cannot know how many blocks
        # have happened, so report the limit as already reached. Refusing to act
        # on unknown state is the only safe direction here.
        print(f"   [guard] WARNING could not read audit log ({exc}); "
              f"treating rate limit as reached")
        return MAX_BLOCKS_PER_HOUR
    return count


def policy_guard(ip_str: str):
    """
    Deterministic containment policy. VETO-ONLY — this function can refuse an
    action, it can never authorise one on the model's behalf.

    Returns (allowed: bool, reason: str).
    """
    if not ip_str:
        return False, "no IP supplied"

    try:
        ip = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return False, f"not a valid IP address ({ip_str!r}) — refusing to act on non-IP data"

    if str(ip) in PROTECTED_ASSETS:
        return False, "explicitly protected lab asset"

    # Order matters. `is_private` is True for loopback, link-local and (on some
    # Python versions) CGNAT, so the specific checks must come first — otherwise
    # 127.0.0.1 gets refused with the reason "RFC1918 private address", which is
    # wrong. The verdict would still be correct, but the reason is written into
    # the case comment and the audit log, so an inaccurate one is a real defect.
    if ip.is_loopback:
        return False, "loopback address"
    if ip.is_link_local:
        return False, "link-local address"
    if ip.is_multicast:
        return False, "multicast address"
    if ip.is_reserved or ip.is_unspecified:
        return False, "reserved or unspecified address"
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return False, "Tailscale CGNAT range — our own administrative access path"
    if ip.is_private:
        return False, "RFC1918 private address — internal host, blocking causes self-inflicted outage"

    return True, "external routable address, not protected"


def containment_allowed(ip_str: str, confidence: float):
    """
    Full pre-flight check before any containment. Every refusal path is audited.
    Returns (allowed: bool, reason: str).
    """
    if kill_switch_active():
        return False, f"KILL SWITCH ACTIVE ({KILL_SWITCH_FILE} exists)"

    # The schema declares confidence as 0..1, but constrained decoding enforces the
    # TYPE reliably and the range only best-effort. A model returning 95 instead of
    # 0.95 would clear the 0.75 threshold trivially, so check the range in code.
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        return False, f"confidence is not a number ({confidence!r})"
    if not 0.0 <= confidence <= 1.0:
        return False, (f"confidence {confidence} is outside 0..1 — refusing to act on "
                       f"an out-of-range value")

    if confidence < MIN_CONFIDENCE_TO_ACT:
        return False, (f"model confidence {confidence:.2f} below required "
                       f"{MIN_CONFIDENCE_TO_ACT:.2f} — escalating to human instead")

    allowed, reason = policy_guard(ip_str)
    if not allowed:
        return False, f"policy guard: {reason}"

    blocks = recent_block_count()
    if blocks >= MAX_BLOCKS_PER_HOUR:
        return False, (f"rate limit reached ({blocks}/{MAX_BLOCKS_PER_HOUR} blocks "
                       f"in the last hour) — possible runaway automation")

    return True, "all guardrails passed"


# ==============================================================================
# LLM — schema-constrained, defensive
# ==============================================================================

# MITRE techniques actually validated in this lab (= the ROADMAP C1 catalog).
# A closed enum makes it *physically impossible* for the model to invent a
# plausible-but-wrong technique ID under constrained decoding — measured to
# improve technique accuracy from 2/7 to 6/7 (ai/results/model-benchmark.md).
LAB_TECHNIQUES = [
    "N/A", "T1190", "T1046", "T1003.002", "T1110", "T1059.001",
    "T1547.001", "T1053.005", "T1053.003", "T1136.001", "T1098",
    "T1548", "T1071.001", "T1078", "OTHER",
]

TRIAGE_SYSTEM = """You are a Tier-1 SOC analyst for a lab network. Be precise and conservative.

NETWORK BASELINE (critical for judging false positives):
- 192.168.10.0/24 = internal LAN. 192.168.10.2 = pfSense gateway (our own firewall).
  192.168.10.20 = Linux host. 192.168.10.30 = Windows host.
- 172.16.0.0/24 = DMZ. 172.16.0.10 = OWASP Juice Shop (deliberately vulnerable, internet-exposed).
- 100.64.0.0/10 = Tailscale VPN (our own administrative access).
- Internal-to-internal traffic (RFC1918 source AND RFC1918 destination) using
  discovery/broadcast protocols - SSDP, UPnP, mDNS, NetBIOS, LLMNR, DHCP - is
  NORMAL BACKGROUND NOISE here. Windows hosts emit these constantly. Signatures
  labelling such traffic "amplification", "scan" or "DoS" are FALSE POSITIVES
  unless there is clear rate/volume evidence of abuse.
- Signatures in the "Not Suspicious Traffic" or "Misc activity" category, or whose
  name begins "ET INFO", are informational. Treat as false positives unless the
  surrounding context shows real attacker behaviour.
- A true positive normally involves an EXTERNAL source IP, or a clear
  exploitation / credential-access / persistence payload.

RULES:
- mitre_technique MUST be one of the allowed values. It is NOT a CVE number.
  Use "N/A" if the event is benign, "OTHER" if a real technique applies that is
  not in the list.
- severity reflects real impact in THIS environment, not the raw signature severity.
- confidence is 0.0 to 1.0. Use LOW confidence when genuinely unsure — low
  confidence causes escalation to a human rather than automated action.

Return ONLY a JSON object. No prose, no markdown fences."""

TRIAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "summary":             {"type": "string"},
        "severity":            {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "is_false_positive":   {"type": "boolean"},
        "confidence":          {"type": "number", "minimum": 0, "maximum": 1},
        "mitre_technique":     {"type": "string", "enum": LAB_TECHNIQUES},
        "technique_reasoning": {"type": "string"},
        "recommended_action":  {"type": "string"},
    },
    "required": ["summary", "severity", "is_false_positive", "confidence",
                 "mitre_technique", "technique_reasoning", "recommended_action"],
}

# Few-shot examples. Deliberately NOT drawn from the golden test set, so the
# benchmark remains a genuinely held-out evaluation. Measured effect:
# +4 points overall with no regression in false-positive accuracy.
TRIAGE_FEWSHOT = [
    ({"event_type": "alert", "src_ip": "192.168.10.30", "dest_ip": "224.0.0.251",
      "alert": {"signature": "ET INFO mDNS Query Observed", "category": "Misc activity",
                "severity": 3}},
     {"summary": "Windows host sent a routine mDNS service-discovery query to the local "
                 "multicast address. Normal LAN background traffic.",
      "severity": "low", "is_false_positive": True, "confidence": 0.95,
      "mitre_technique": "N/A",
      "technique_reasoning": "Benign service discovery; no adversary technique applies.",
      "recommended_action": "No action. Consider tuning this signature to reduce noise."}),
    ({"event_type": "alert", "src_ip": "45.155.205.211", "dest_ip": "172.16.0.10",
      "alert": {"signature": "ET WEB_SERVER SQL Injection UNION SELECT",
                "category": "Web Application Attack", "severity": 1},
      "http": {"url": "/rest/products/search?q=' UNION SELECT * FROM users--"}},
     {"summary": "External host attempted SQL injection against the DMZ web application "
                 "using a UNION SELECT payload to extract user data.",
      "severity": "critical", "is_false_positive": False, "confidence": 0.93,
      "mitre_technique": "T1190",
      "technique_reasoning": "Exploitation of a public-facing application via SQLi.",
      "recommended_action": "Block the source IP and review application logs for successful extraction."}),
]

VERDICT_SYSTEM = """You are a Tier-2 SOC analyst making a final assessment after threat-intelligence
enrichment. You are given real Cortex analyzer reports (VirusTotal, AbuseIPDB,
AlienVault OTX, URLhaus) for an observable.

Assess whether the observable is malicious based on the EVIDENCE in those reports.

IMPORTANT:
- You do NOT decide whether to block anything. You assess. Containment policy is
  enforced separately by the system.
- If the reports show no detections, no abuse reports, and no threat-intel hits,
  the correct verdict is "benign" — do not escalate on absence of evidence.
- confidence is 0.0 to 1.0. Low confidence causes escalation to a human analyst.
- Cite the specific evidence you relied on in key_evidence.

Return ONLY a JSON object. No prose, no markdown fences."""

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict":      {"type": "string", "enum": ["malicious", "benign", "inconclusive"]},
        "confidence":   {"type": "number", "minimum": 0, "maximum": 1},
        "reason":       {"type": "string"},
        "key_evidence": {"type": "string"},
    },
    "required": ["verdict", "confidence", "reason", "key_evidence"],
}


def call_llm(system_prompt: str, messages: list, schema: dict, label: str = "LLM"):
    """
    Schema-constrained call to Ollama. Returns (parsed_dict | None, error | None).

    Passing a JSON Schema (not the string "json") to Ollama's `format` parameter
    engages constrained decoding, which measured 56/56 valid, correctly-shaped
    responses across 5 models during benchmarking. Generic JSON mode guarantees
    only that output *parses*, not that it has the required keys.

    Returns None on failure rather than a fabricated fallback verdict — callers
    decide what a failure means. A silent default here is how automation acts on
    a decision nobody made.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [{"role": "system", "content": system_prompt}] + messages,
        "format": schema,
        "stream": False,
        "options": {"temperature": 0},
    }

    t0 = time.time()
    try:
        resp = requests.post(OLLAMA_CHAT_URL, json=payload, timeout=OLLAMA_TIMEOUT)
        resp.raise_for_status()
        content = resp.json().get("message", {}).get("content", "")
    except Exception as exc:
        print(f"   [{label}] request failed: {exc}")
        return None, str(exc)

    elapsed = time.time() - t0
    print(f"   [{label}] responded in {elapsed:.1f}s")

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        print(f"   [{label}] returned unparseable JSON: {exc}")
        return None, f"unparseable JSON: {exc}"

    missing = [k for k in schema.get("required", []) if k not in parsed]
    if missing:
        print(f"   [{label}] response missing required keys: {missing}")
        return None, f"missing keys: {missing}"

    parsed["_latency_s"] = round(elapsed, 1)
    return parsed, None


def triage_alert(alert: dict, observables: list = None):
    """
    Phase 1 — assess the raw alert. Returns (assessment | None, error | None).

    `observables` should be the result of api.alert.find_observables(). It is passed
    in rather than read off the alert because TheHive does NOT return observables on
    the alert object: `alert.get("observables")` is always absent, so the previous
    `observables_count` was permanently 0 and the model was told there was no
    observable data even when the alert carried two IPs.

    Including the observables with their src/dst tags matters because the alert
    description is a flat block of text. Without them the model has to infer which
    address is the attacker from prose, which is exactly the judgement the whole
    pipeline depends on.
    """
    print("\n[AI phase 1] triaging raw alert ...")

    obs_list = []
    for o in (observables or []):
        obs_list.append({
            "type": o.get("dataType"),
            "value": o.get("data"),
            "role": "source" if "src" in {str(t).lower() for t in (o.get("tags") or [])}
                    else "destination" if "dst" in {str(t).lower() for t in (o.get("tags") or [])}
                    else "unspecified",
        })

    alert_summary = {
        "title": alert.get("title"),
        "description": alert.get("description"),
        "severity": alert.get("severity"),
        "source": alert.get("source"),
        "tags": alert.get("tags"),
        "observables": obs_list,
        "observables_count": len(obs_list),
    }

    messages = []
    for example_alert, example_answer in TRIAGE_FEWSHOT:
        messages.append({"role": "user", "content": json.dumps(example_alert, indent=2)})
        messages.append({"role": "assistant", "content": json.dumps(example_answer)})
    messages.append({"role": "user", "content": json.dumps(alert_summary, indent=2)})

    return call_llm(TRIAGE_SYSTEM, messages, TRIAGE_SCHEMA, label="triage")


def assess_enrichment(reports: list, observable: str):
    """Phase 2 — assess enrichment results. Returns (assessment | None, error | None)."""
    print("\n[AI phase 2] assessing Cortex analyzer reports ...")
    user = {"observable": observable, "analyzer_reports": reports}
    messages = [{"role": "user", "content": json.dumps(user, indent=2, default=str)}]
    return call_llm(VERDICT_SYSTEM, messages, VERDICT_SCHEMA, label="verdict")


# ==============================================================================
# THEHIVE HELPERS
# ==============================================================================

def post_case_comment(case_id: str, body: str):
    """
    Post an AI-generated comment onto a case, clearly labelled so no analyst
    mistakes it for a human note. Tries thehive4py, falls back to the REST API.
    """
    try:
        import thehive4py  # noqa: F401
        api = TheHiveApi(THEHIVE_URL, apikey=THEHIVE_API_KEY)
        api.comment.create_in_case(case_id=case_id, comment={"message": body})
        return True
    except Exception:
        pass

    try:
        resp = requests.post(
            f"{THEHIVE_URL}/api/v1/case/{case_id}/comment",
            headers={"Authorization": f"Bearer {THEHIVE_API_KEY}",
                     "Content-Type": "application/json"},
            json={"message": body},
            timeout=30,
        )
        resp.raise_for_status()
        return True
    except Exception as exc:
        print(f"   [comment] could not post AI comment: {exc}")
        return False


def build_ai_comment(triage: dict, verdict: dict, containment: dict) -> str:
    """Render the AI assessment as a labelled markdown comment."""
    lines = [
        "## 🤖 AI Triage Draft",
        "_Generated automatically by the SOAR pipeline. **Not** a human analyst note._",
        "",
        "### Initial triage",
        f"- **Summary:** {triage.get('summary', 'n/a')}",
        f"- **Severity:** `{triage.get('severity', 'n/a')}`",
        f"- **False positive:** `{triage.get('is_false_positive')}`",
        f"- **Confidence:** `{triage.get('confidence', 0):.2f}`",
        f"- **MITRE technique:** `{triage.get('mitre_technique', 'n/a')}` — "
        f"{triage.get('technique_reasoning', '')}",
        f"- **Recommended action:** {triage.get('recommended_action', 'n/a')}",
    ]

    if verdict:
        lines += [
            "",
            "### Post-enrichment assessment",
            f"- **Verdict:** `{verdict.get('verdict', 'n/a').upper()}`",
            f"- **Confidence:** `{verdict.get('confidence', 0):.2f}`",
            f"- **Reason:** {verdict.get('reason', 'n/a')}",
            f"- **Key evidence:** {verdict.get('key_evidence', 'n/a')}",
        ]

        # The two phases can disagree: triage reads the alert alone, the verdict
        # reads threat-intelligence enrichment. Printing both without comment left
        # analysts with "high severity attack" followed by "BENIGN" and no guidance
        # on which to believe. Enrichment is the better-informed of the two, so say
        # so explicitly rather than leaving the reader to work it out.
        triage_says_bad = triage.get("is_false_positive") is False
        verdict_says_ok = verdict.get("verdict") in ("benign", "inconclusive")
        if triage_says_bad and verdict_says_ok:
            lines += [
                "",
                f"> ⚠️ **The two phases disagree.** Initial triage rated this "
                f"`{triage.get('severity', 'n/a')}` and not a false positive; "
                f"threat-intelligence enrichment then returned "
                f"`{verdict.get('verdict', 'n/a').upper()}`. "
                f"The enrichment assessment is based on more evidence and takes "
                f"precedence, which is why no action was taken.",
            ]
        elif triage.get("is_false_positive") is True and verdict.get("verdict") == "malicious":
            lines += [
                "",
                "> ⚠️ **The two phases disagree.** Initial triage called this a false "
                "positive, but enrichment rated it `MALICIOUS`. Treat the initial "
                "triage as unreliable for this alert and review manually.",
            ]

    lines += ["", "### Automated containment"]
    if containment.get("executed"):
        lines.append(f"- ✅ **EXECUTED** against `{containment.get('target')}`")
        lines.append(f"- Guardrails: {containment.get('reason')}")
    elif containment.get("attempted"):
        lines.append(f"- ❌ **REFUSED** — no action taken against `{containment.get('target')}`")
        lines.append(f"- **Reason:** {containment.get('reason')}")
        lines.append("- Escalated for human review.")
    else:
        lines.append(f"- ➖ Not applicable — {containment.get('reason', 'no containment considered')}")

    lines += [
        "",
        "---",
        f"_Model `{OLLAMA_MODEL}` @ `{OLLAMA_BASE_URL}` · prompt v4 (few-shot + enum schema) · "
        f"{datetime.now(timezone.utc).isoformat()}_",
    ]
    return "\n".join(lines)


def wait_for_analyzer_job(api, job_id):
    """Poll a Cortex job to a terminal state, or raise TimeoutError."""
    elapsed = 0
    last_status = None
    while elapsed <= ANALYZER_JOB_TIMEOUT_SECONDS:
        try:
            job = api.cortex.get_analyzer_job(job_id)
        except Exception as exc:
            print(f"   polling error: {exc}")
            time.sleep(ANALYZER_POLL_INTERVAL_SECONDS)
            elapsed += ANALYZER_POLL_INTERVAL_SECONDS
            continue

        status = job.get("status")
        if status != last_status:
            print(f"   job status: {status} ({elapsed}s)")
            last_status = status
        if status in ("Success", "Failure"):
            return job

        time.sleep(ANALYZER_POLL_INTERVAL_SECONDS)
        elapsed += ANALYZER_POLL_INTERVAL_SECONDS

    raise TimeoutError(f"analyzer job {job_id} did not finish in "
                       f"{ANALYZER_JOB_TIMEOUT_SECONDS}s (last status: {last_status})")


OPERATIONAL_ALERT_TYPES = {"pipeline-health"}
OPERATIONAL_ALERT_TAGS = {"watchdog", "pipeline-health"}


def is_operational_alert(alert: dict) -> bool:
    """
    True for pipeline/ops-health alerts (the ElastAlert dead-man watchdogs from
    ROADMAP A-1), which must never enter the security triage path.

    They describe *our own* telemetry going silent, not attacker activity. They
    carry no attacker observable, so there is nothing to enrich and nothing to
    contain — running triage on them would burn ~6 min of LLM time per alert and
    create meaningless cases. They belong to a human on-call, not to this
    pipeline.
    """
    if str(alert.get("type", "")).lower() in OPERATIONAL_ALERT_TYPES:
        return True
    tags = {str(t).lower() for t in (alert.get("tags") or [])}
    return bool(tags & OPERATIONAL_ALERT_TAGS)


def resolve_responder_id(api, observable_id: str, wanted_name: str):
    """
    Look up a Cortex responder's real ID from its NAME.

    Cortex identifies workers by a hash id such as 'aebe07e932adfb592a20678599943378',
    not by the human-readable name. Passing the name produces
    `worker PfSense_Blocker_1_0 not found` and the action fails ASYNCHRONOUSLY, after
    create_responder_action() has already returned successfully.

    Resolving at runtime also survives a Cortex reinstall, which changes the hash.

    Returns (responder_id | None, error | None).
    """
    try:
        responders = api.cortex.list_responders(entity_type="case_artifact",
                                                entity_id=observable_id)
    except Exception as exc:
        return None, f"could not list responders: {exc}"

    for r in responders or []:
        if r.get("name") == wanted_name:
            return r.get("id"), None

    available = [r.get("name") for r in (responders or [])]
    return None, f"responder {wanted_name!r} not available on this observable (found: {available})"


def resolve_case_responder_id(api, case_id: str, wanted_name: str):
    """Look up a Cortex responder by name for a case entity (e.g., Mailer)."""
    try:
        responders = api.cortex.list_responders(entity_type="case", entity_id=case_id)
    except Exception as exc:
        return None, f"could not list case responders: {exc}"
    for r in responders or []:
        if r.get("name") == wanted_name:
            return r.get("id"), None
    return None, f"case responder {wanted_name!r} not available"


def trigger_mailer_responder(api, case_id: str):
    """Tag the case with recipient emails and trigger the Mailer responder."""
    # 1. Add mail= tags so the Mailer knows who to email
    try:
        existing = api.case.get(case_id).get("tags", [])
        mail_tags = [f"mail={addr}" for addr in MAILER_RECIPIENTS]
        merged = list(set(existing + mail_tags))
        api.case.update(case_id, {"tags": merged})
    except Exception as exc:
        print(f"   [mailer] could not tag case: {exc}")

    # 2. Resolve and fire the Mailer responder
    responder_id, rerr = resolve_case_responder_id(api, case_id, MAILER_RESPONDER_NAME)
    if responder_id is None:
        print(f"   [mailer] could not resolve: {rerr}")
        return False
    try:
        api.cortex.create_responder_action({
            "responderId": responder_id,
            "cortexId": CORTEX_ID,
            "objectType": "case",
            "objectId": case_id,
        })
        print("   [mailer] email notification triggered")
        audit("mailer_triggered", case_id=case_id, recipients=MAILER_RECIPIENTS)
        return True
    except Exception as exc:
        print(f"   [mailer] call failed: {exc}")
        return False


def wait_for_responder_action(observable_id: str, timeout_s: int = 60, poll_s: int = 3):
    """
    Confirm a responder action actually SUCCEEDED.

    create_responder_action() only submits the job. Cortex runs it asynchronously and
    can fail afterwards. Auditing 'containment_executed' on submission produced an
    audit trail that claimed a firewall block which never happened, discovered only by
    inspecting pfSense directly. For an autonomous containment action, "we asked" and
    "it worked" must not be recorded as the same thing.

    Returns (status_string, report_dict | None).
    """
    # thehive4py exposes no "list actions" call, so query TheHive directly.
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            resp = requests.post(
                f"{THEHIVE_URL}/api/v1/query",
                json={"query": [{"_name": "listAction"},
                                {"_name": "sort", "_fields": [{"startDate": "desc"}]},
                                {"_name": "page", "from": 0, "to": 20}]},
                headers={"Authorization": f"Bearer {THEHIVE_API_KEY}"},
                timeout=15,
            )
            resp.raise_for_status()
            actions = resp.json()
        except Exception:
            actions = []

        for a in actions or []:
            if a.get("objectId") != observable_id:
                continue
            # A rejected job records no responderName, so match on the object and
            # take the most recent action rather than requiring the name.
            st = a.get("status")
            if st in ("Success", "Failure"):
                return st, a.get("report")
            break
        time.sleep(poll_s)
    return "Timeout", None


def select_containment_target(observables: list):
    """
    Explicitly choose which observable containment would apply to.

    The original implementation reused a loop variable, so it acted on whichever
    observable happened to be iterated last — which, now that rules extract
    multiple typed observables (IP + request URI + body), could mean attempting
    to 'block' a request body. Selection is now explicit: IP-typed observables
    only, preferring one that actually passes the policy guard.
    """
    ip_observables = [o for o in observables if o.get("dataType") == "ip"]
    if not ip_observables:
        return None, "no IP-type observable on this case"

    # Pick the ATTACKER, not merely "whichever address is external".
    #
    # The previous version returned the first IP that passed the policy guard.
    # For an inbound attack (external -> internal) that is the attacker and the
    # result is right. For an OUTBOUND alert (internal -> external) the external
    # address is the *destination*, and blocking it means blocking the victim or
    # a legitimate service. Our own test case 04-powershell-ua is exactly this
    # shape: 192.168.10.30 -> 217.160.0.187.
    #
    # The ElastAlert rules already tag observables `src` and `dst`
    # (see suricata_high_severity.yaml), so the role is available; the old code
    # simply ignored it. Rules that do not tag (pfsense_portscan.yaml) list the
    # source first, so document order is the fallback signal.
    def _tags(o):
        return {str(t).lower() for t in (o.get("tags") or [])}

    tagged_src = [o for o in ip_observables if "src" in _tags(o)]
    tagged_dst = [o for o in ip_observables if "dst" in _tags(o)]

    if tagged_src:
        candidates, basis = tagged_src, "observable tagged 'src'"
    elif tagged_dst and len(tagged_dst) < len(ip_observables):
        # Some are explicitly destinations; prefer everything that is not.
        candidates = [o for o in ip_observables if o not in tagged_dst]
        basis = "untagged observable (destinations excluded)"
    else:
        # No usable tags. Rules emit the source first, so respect document order
        # rather than reordering by which address happens to be routable.
        candidates, basis = ip_observables, "document order (source listed first)"

    for obs in candidates:
        allowed, _ = policy_guard(obs.get("data"))
        if allowed:
            return obs, f"attacker selected by {basis}"

    # Nothing among the likely-attacker observables is blockable. Return the best
    # candidate anyway so containment_allowed() records a specific refusal with a
    # named target, instead of a vague "no target found".
    return candidates[0], f"only internal/protected addresses among {basis}"


# ==============================================================================
# MAIN PIPELINE
# ==============================================================================

def process_single_alert(api, alert):
    alert_id = alert.get("_id") or alert.get("id")
    title = alert.get("title", "<untitled>")
    print(f"\n{'='*70}\nALERT {alert_id} — {title}\n{'='*70}")
    audit("alert_received", alert_id=alert_id, title=title)

    # -- Phase 1: triage -------------------------------------------------------
    # Fetch the alert's observables so triage can see the actual IPs and which one
    # is the source. TheHive does not include them on the alert object itself.
    try:
        alert_observables = api.alert.find_observables(alert_id)
    except Exception as exc:
        print(f"   could not fetch alert observables: {exc}")
        alert_observables = []

    triage, err = triage_alert(alert, alert_observables)

    if triage is None:
        # FAIL SAFE: an unavailable or malformed model must never cause an
        # automated decision. Leave the alert untouched for a human.
        print(f"   triage unavailable ({err}) — leaving alert for human review")
        audit("triage_failed", alert_id=alert_id, error=err, outcome="left_for_human")
        return

    print(f"   verdict          : false_positive={triage['is_false_positive']}")
    print(f"   severity         : {triage['severity']}")
    print(f"   confidence       : {triage['confidence']:.2f}")
    print(f"   MITRE            : {triage['mitre_technique']}")
    audit("triage_complete", alert_id=alert_id, **{
        k: triage[k] for k in ("severity", "is_false_positive", "confidence", "mitre_technique")
    })

    # Decision derived in CODE from the model's assessment — the model is not
    # asked "should I promote this?", it is asked "what is this?".
    if triage["is_false_positive"] and triage["confidence"] >= MIN_CONFIDENCE_TO_ACT:
        print("   -> confident false positive; marking alert Ignored")
        # thehive4py 2.x takes the changes as a `fields` dict; the 1.x-style
        # keyword form (status="Ignored") raises TypeError and leaves the alert
        # New, so it would be re-triaged on every restart at ~3 min a time.
        try:
            api.alert.update(alert_id, fields={"status": "Ignored"})
            audit("alert_dismissed", alert_id=alert_id,
                  confidence=triage["confidence"])
        except Exception as exc:
            # Do NOT record alert_dismissed here — the alert is still New in
            # TheHive, and an audit trail that claims otherwise is worse than
            # no audit trail.
            print(f"   could not mark Ignored: {exc}")
            audit("alert_dismiss_failed", alert_id=alert_id,
                  confidence=triage["confidence"], error=str(exc))
        return

    if triage["is_false_positive"]:
        print(f"   -> assessed false positive but confidence {triage['confidence']:.2f} "
              f"below {MIN_CONFIDENCE_TO_ACT:.2f}; promoting for human review")

    # -- Promote to case -------------------------------------------------------
    try:
        case = api.alert.promote_to_case(alert_id)
        case_id = case.get("_id") or case.get("id")
        print(f"\n   promoted to case {case_id}")
        audit("case_created", alert_id=alert_id, case_id=case_id)
    except Exception as exc:
        print(f"   could not promote alert to case: {exc}")
        audit("promote_failed", alert_id=alert_id, error=str(exc))
        return

    # -- Phase 2: Cortex enrichment -------------------------------------------
    reports = []
    observables = []

    # Observables are copied to the case asynchronously and indexed in
    # near-real-time, so querying immediately after promote_to_case can return
    # an empty list even though they exist a moment later. Without this retry
    # the whole enrichment + verdict + containment path is silently skipped and
    # the run looks "successful" while having tested nothing.
    for attempt in range(OBSERVABLE_FETCH_ATTEMPTS):
        try:
            observables = api.case.find_observables(case_id)
        except Exception:
            try:
                observables = api.alert.find_observables(alert_id)
            except Exception as exc:
                print(f"   could not fetch observables: {exc}")
                break
        if observables:
            break
        if attempt < OBSERVABLE_FETCH_ATTEMPTS - 1:
            time.sleep(OBSERVABLE_FETCH_DELAY_SECONDS)

    if not observables:
        print(f"   no observables found on case {case_id} after "
              f"{OBSERVABLE_FETCH_ATTEMPTS} attempts")
        audit("observables_missing", case_id=case_id, alert_id=alert_id)

    if observables:
        try:
            catalog = api.cortex.list_analyzers()
        except Exception as exc:
            print(f"   could not list analyzers: {exc}")
            catalog = []

        for obs in observables:
            obs_id = obs.get("_id") or obs.get("id")
            obs_data = obs.get("data")
            obs_type = obs.get("dataType")
            print(f"\n   observable: {obs_data}  (type: {obs_type})")

            matching = []
            for a in catalog:
                name = a.get("name", "")
                if not any(name.startswith(p) for p in ANALYZER_NAME_PREFIXES):
                    continue
                supported = a.get("dataTypeList")
                if supported and obs_type not in supported:
                    continue
                matching.append(a)

            if not matching:
                print(f"      no enabled analyzer supports dataType '{obs_type}'")
                continue

            ran_ok = False
            for analyzer in matching:
                name = analyzer.get("name")
                try:
                    job = api.cortex.create_analyzer_job({
                        "analyzerId": analyzer.get("id"),
                        "cortexId": CORTEX_ID,
                        "artifactId": obs_id,
                    })
                    job_id = job.get("_id") or job.get("id")
                    print(f"      running {name} (job {job_id})")
                    status = wait_for_analyzer_job(api, job_id)
                except TimeoutError as exc:
                    print(f"      {exc}")
                    continue
                except Exception as exc:
                    print(f"      analyzer {name} failed: {exc}")
                    continue

                if status.get("status") == "Success":
                    ran_ok = True
                else:
                    print(f"      {name} finished with status {status.get('status')}")

            if not ran_ok:
                continue

            # Cortex's distilled taxonomy tags (e.g. "VT:GetReport=0/91") are NOT
            # present on the raw job status object returned by get_analyzer_job() —
            # that only has success/full/artifacts, no "summary" key, so reading
            # report["summary"]["taxonomies"] from it silently returns an empty list
            # every time (confirmed against a live job: real taxonomies exist, this
            # path never sees them). TheHive computes taxonomies separately and
            # attaches them to the observable itself, so it has to be fetched fresh
            # after the jobs finish. Send the LLM these distilled tags instead of the
            # full raw analyzer report — a raw VirusTotal report alone runs to tens of
            # KB of per-vendor scan results the model has no use for, and that noise
            # is the likely cause of the same-alert verdict flip-flopping seen during
            # C-1 testing.
            try:
                fresh_obs = api.observable.get(obs_id)
            except Exception as exc:
                print(f"      could not fetch observable reports: {exc}")
                continue

            for analyzer_name, analyzer_report in (fresh_obs.get("reports") or {}).items():
                taxonomies = analyzer_report.get("taxonomies", [])
                for tax in taxonomies:
                    print(f"         [{tax.get('level')}] {tax.get('namespace')}:"
                          f"{tax.get('predicate')} = {tax.get('value')}")
                reports.append({
                    "observable": obs_data,
                    "analyzer": analyzer_name,
                    "taxonomies": [
                        {"level": t.get("level"), "namespace": t.get("namespace"),
                         "predicate": t.get("predicate"), "value": t.get("value")}
                        for t in taxonomies
                    ],
                })

    print(f"\n   collected {len(reports)} analyzer report(s)")
    audit("enrichment_complete", case_id=case_id, report_count=len(reports))

    # -- Phase 3: post-enrichment assessment ----------------------------------
    target_obs, target_reason = select_containment_target(observables)
    target_ip = target_obs.get("data") if target_obs else None

    verdict = None
    if reports:
        verdict, err = assess_enrichment(reports, target_ip or "unknown")
        if verdict is None:
            print(f"   verdict unavailable ({err}) — no automated action will be taken")
            audit("verdict_failed", case_id=case_id, error=err)
        else:
            print(f"   verdict    : {verdict['verdict'].upper()}")
            print(f"   confidence : {verdict['confidence']:.2f}")
            print(f"   evidence   : {verdict.get('key_evidence','')[:160]}")
            audit("verdict_complete", case_id=case_id,
                  verdict=verdict["verdict"], confidence=verdict["confidence"])
    else:
        print("   no analyzer reports — skipping enrichment assessment")

    # -- Phase 4: containment, gated ------------------------------------------
    containment = {"attempted": False, "executed": False,
                   "target": target_ip, "reason": "no malicious verdict"}

    if verdict and verdict["verdict"] == "malicious":
        containment["attempted"] = True

        if target_obs is None:
            containment["reason"] = target_reason
            print(f"\n   CONTAINMENT REFUSED — {target_reason}")
            audit("containment_refused", case_id=case_id, reason=target_reason)
        else:
            allowed, reason = containment_allowed(target_ip, verdict["confidence"])
            containment["reason"] = reason

            if not allowed:
                print(f"\n   CONTAINMENT REFUSED — {reason}")
                print(f"   target was: {target_ip}")
                audit("containment_refused", case_id=case_id,
                      target=target_ip, reason=reason,
                      verdict=verdict["verdict"], confidence=verdict["confidence"])
                trigger_mailer_responder(api, case_id)
            elif DRY_RUN:
                containment["reason"] = f"{reason} (DRY RUN — not executed)"
                print(f"\n   DRY RUN — would block {target_ip} ({reason})")
                audit("containment_dry_run", case_id=case_id, target=target_ip, reason=reason)
                trigger_mailer_responder(api, case_id)
            else:
                obs_id = target_obs.get("_id") or target_obs.get("id")

                # Cortex identifies workers by hash id, not by name. Resolve first,
                # otherwise the job is rejected asynchronously with
                # "worker <name> not found" long after we have reported success.
                responder_id, rerr = resolve_responder_id(api, obs_id, RESPONDER_NAME)
                if responder_id is None:
                    containment["reason"] = f"responder unavailable: {rerr}"
                    print(f"\n   CONTAINMENT FAILED — {rerr}")
                    audit("containment_error", case_id=case_id, target=target_ip, error=rerr)
                else:
                    try:
                        api.cortex.create_responder_action({
                            "responderId": responder_id,
                            "cortexId": CORTEX_ID,
                            "objectType": "case_artifact",
                            "objectId": obs_id,
                        })
                    except Exception as exc:
                        containment["reason"] = f"responder call failed: {exc}"
                        print(f"\n   containment failed: {exc}")
                        audit("containment_error", case_id=case_id,
                              target=target_ip, error=str(exc))
                    else:
                        # Submitting is not the same as succeeding. Wait for Cortex to
                        # report the outcome before claiming the host was blocked.
                        print(f"\n   responder submitted, waiting for Cortex result ...")
                        status, report = wait_for_responder_action(obs_id)

                        if status == "Success":
                            containment["executed"] = True
                            containment["reason"] = f"{reason} (responder confirmed Success)"
                            print(f"   CONTAINMENT EXECUTED against {target_ip}")
                            audit("containment_executed", case_id=case_id, target=target_ip,
                                  responder=RESPONDER_NAME, responder_id=responder_id,
                                  confidence=verdict["confidence"], cortex_status=status)
                            trigger_mailer_responder(api, case_id)
                        else:
                            containment["reason"] = (f"responder did not confirm success "
                                                     f"(status={status})")
                            print(f"   CONTAINMENT NOT CONFIRMED — Cortex status: {status}")
                            if report:
                                print(f"   report: {str(report)[:220]}")
                            audit("containment_unconfirmed", case_id=case_id,
                                  target=target_ip, responder=RESPONDER_NAME,
                                  cortex_status=status, report=str(report)[:400])

    # -- Always leave the reasoning visible in TheHive -------------------------
    comment = build_ai_comment(triage, verdict, containment)
    if post_case_comment(case_id, comment):
        print("   AI triage comment posted to case")
        audit("comment_posted", case_id=case_id)

    print(f"\n{'='*70}\nALERT {alert_id} COMPLETE\n{'='*70}")


def main():
    if not THEHIVE_API_KEY:
        sys.exit("THEHIVE_API_KEY is not set. Export it before running:\n"
                 "    export THEHIVE_API_KEY='<key>'")

    print("=" * 70)
    print("  SOAR + AI TRIAGE ORCHESTRATOR")
    print("=" * 70)
    print(f"  TheHive        : {THEHIVE_URL}")
    print(f"  LLM            : {OLLAMA_MODEL} @ {OLLAMA_BASE_URL}")
    print(f"  Audit log      : {AUDIT_LOG}")
    print(f"  Kill switch    : {KILL_SWITCH_FILE} "
          f"({'ACTIVE — containment disabled' if kill_switch_active() else 'inactive'})")
    print(f"  Min confidence : {MIN_CONFIDENCE_TO_ACT}")
    print(f"  Rate limit     : {MAX_BLOCKS_PER_HOUR} blocks/hour")
    print(f"  Dry run        : {DRY_RUN}")
    print("=" * 70)
    if not DRY_RUN and not kill_switch_active():
        print("  *** CONTAINMENT IS ARMED — this run can modify the firewall ***")
        print(f"  To stop it at any time:  touch {KILL_SWITCH_FILE}")
        print("=" * 70)

    audit("pipeline_started", model=OLLAMA_MODEL, dry_run=DRY_RUN,
          min_confidence=MIN_CONFIDENCE_TO_ACT, max_blocks_hour=MAX_BLOCKS_PER_HOUR)

    api = TheHiveApi(THEHIVE_URL, apikey=THEHIVE_API_KEY)

    # -- Targeted single-alert mode -------------------------------------------
    if TARGET_ALERT_ID:
        print(f"\ntargeted mode: processing alert {TARGET_ALERT_ID} only\n")
        try:
            alert = api.alert.get(TARGET_ALERT_ID)
        except Exception as exc:
            sys.exit(f"could not fetch alert {TARGET_ALERT_ID}: {exc}")

        print(f"  title : {alert.get('title')}")
        print(f"  status: {alert.get('status')}\n")
        try:
            process_single_alert(api, alert)
        except Exception as exc:
            print(f"   unhandled error processing {TARGET_ALERT_ID}: {exc}")
            audit("processing_error", alert_id=TARGET_ALERT_ID, error=str(exc))
        audit("pipeline_stopped", reason="targeted_single_alert",
              alert_id=TARGET_ALERT_ID)
        return

    seen = set()          # in-process guard against reprocessing on transient failure
    processed = 0

    if MAX_ALERTS:
        print(f"\nbounded run: stopping after {MAX_ALERTS} alert(s)")
    if RUN_ONCE:
        print("single-pass mode: will exit after one sweep of the queue")
    print(f"\npolling every {POLL_INTERVAL_SECONDS}s ...\n")
    while True:
        try:
            alerts = api.alert.find()

            # Operational/watchdog alerts never enter triage (see is_operational_alert),
            # but were previously left sitting as "New" forever with no queue signal
            # distinguishing them from a real, unprocessed backlog. Dismiss them
            # directly instead — no LLM triage needed, there is nothing to assess.
            for a in alerts:
                a_id = a.get("_id") or a.get("id")
                if (a.get("status") == "New" and a_id not in seen
                        and is_operational_alert(a)):
                    seen.add(a_id)
                    try:
                        api.alert.update(a_id, fields={"status": "Ignored"})
                        audit("operational_alert_dismissed", alert_id=a_id,
                              title=a.get("title"))
                    except Exception as exc:
                        print(f"   could not dismiss operational alert {a_id}: {exc}")
                        audit("operational_alert_dismiss_failed", alert_id=a_id,
                              error=str(exc))

            new = [a for a in alerts
                   if a.get("status") == "New"
                   and (a.get("_id") or a.get("id")) not in seen
                   and not is_operational_alert(a)]

            # Oldest first, so a bounded run drains the backlog in arrival order
            # rather than repeatedly chewing whichever alerts the API returns first.
            new.sort(key=lambda a: a.get("_createdAt") or a.get("createdAt") or 0)

            for alert in new:
                if MAX_ALERTS and processed >= MAX_ALERTS:
                    break
                alert_id = alert.get("_id") or alert.get("id")
                seen.add(alert_id)
                try:
                    process_single_alert(api, alert)
                except Exception as exc:
                    print(f"   unhandled error processing {alert_id}: {exc}")
                    audit("processing_error", alert_id=alert_id, error=str(exc))
                processed += 1

            if MAX_ALERTS and processed >= MAX_ALERTS:
                print(f"\nreached SOAR_MAX_ALERTS={MAX_ALERTS} — stopping "
                      f"({processed} processed)")
                audit("pipeline_stopped", reason="max_alerts_reached", processed=processed)
                break

            if RUN_ONCE:
                print(f"\nsingle pass complete — {processed} alert(s) processed")
                audit("pipeline_stopped", reason="single_pass", processed=processed)
                break

            time.sleep(POLL_INTERVAL_SECONDS)

        except KeyboardInterrupt:
            print(f"\nshutting down ({processed} alert(s) processed)")
            audit("pipeline_stopped", reason="interrupted", processed=processed)
            break
        except Exception as exc:
            print(f"polling error: {exc}")
            if RUN_ONCE:
                audit("pipeline_stopped", reason="poll_error", processed=processed)
                break
            time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
