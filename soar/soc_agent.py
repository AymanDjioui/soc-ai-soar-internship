#!/usr/bin/env python3
"""
SOC investigation agent — the ReAct loop (AGENT-ROADMAP.md Phase D).

The agent chooses which tools to call and in what order to investigate an alert,
then produces a structured verdict. It has autonomy over INVESTIGATION only. The
containment decision is made by the SAME deterministic guard the pipeline uses —
imported unchanged from e2e_soc_orchestrator.py, never reimplemented here.

    alert ─► [Observe ─► Reason ─► Act(tool) ─► Observe]×N ─► conclude(verdict)
                                                                    │
                                                     containment_allowed()  ◄─ unchanged
                                                                    │
                                                         allow(auto) / refuse(escalate)

Design guarantees carried over from the pipeline:
  * "the model informs, code decides" — the loop's output is a verdict, never an action.
  * constrained decoding on every model turn (proven 56/56 in benchmarking, and again
    in the Phase A spike) — an action-schema for the loop, a verdict-schema to conclude.
  * every step audited; a full reasoning trace is attached to the case.
  * fail-safe: any loop/model error leaves the alert for a human, exactly like the
    pipeline's triage==None path.

This module is STANDALONE (parallel mode). It does not run containment. Wiring it into
the live orchestrator behind SOAR_AGENT_MODE is a later step.

Env: THEHIVE_URL, THEHIVE_API_KEY, ES_URL, ES_USER, ES_PASSWORD,
     OLLAMA_BASE_URL (default GPU L4), OLLAMA_MODEL (default mistral:7b)
"""
import json
import os
import time

import requests

import agent_tools as T
# The REAL guard, imported unchanged. This is the whole point — same code path.
# LAB_TECHNIQUES is reused so the agent's verdict is enum-constrained to techniques
# actually validated in this lab — the same fix that moved the pipeline's technique
# accuracy from 2/7 to 6/7 (ai/results/model-benchmark.md). A free-string field let
# the agent invent plausible-but-wrong ids (T1132.007, T1147.003 in the first bench).
from e2e_soc_orchestrator import (containment_allowed, select_containment_target,
                                  LAB_TECHNIQUES)

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://100.90.228.58:11434")
OLLAMA_CHAT_URL = OLLAMA_BASE_URL.rstrip("/") + "/api/chat"
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "mistral:7b")
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "120"))
MAX_ITERS = int(os.environ.get("SOAR_AGENT_MAX_ITERS", "6"))

# ---- schemas -----------------------------------------------------------------
ACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "thought":        {"type": "string"},
        "action":         {"type": "string", "enum": [
            "search_elasticsearch", "search_past_cases", "get_mitre_context",
            "get_playbook", "run_analyzer", "conclude"]},
        "query":          {"type": "string"},   # search_elasticsearch
        "value":          {"type": "string"},   # search_past_cases (IP or Txxxx)
        "technique":      {"type": "string"},   # get_mitre_context
        "alert_type":     {"type": "string"},   # get_playbook
        "observable":     {"type": "string"},   # run_analyzer — the IP to enrich
        "analyzer_name":  {"type": "string"},   # run_analyzer — e.g. GreyNoise
    },
    "required": ["thought", "action"],
}

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict":         {"type": "string", "enum": ["malicious", "benign", "inconclusive"]},
        "confidence":      {"type": "number", "minimum": 0, "maximum": 1},
        "severity":        {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "mitre_technique": {"type": "string", "enum": LAB_TECHNIQUES},
        "reason":          {"type": "string"},
        "key_evidence":    {"type": "string"},
    },
    "required": ["verdict", "confidence", "severity", "mitre_technique",
                 "reason", "key_evidence"],
}

SYSTEM = """You are an autonomous SOC investigation agent for a lab network. You investigate one alert by calling tools, then conclude with a structured assessment.

TOOLS (one action per turn):
- search_elasticsearch: query SIEM events. Provide "query" (an IP, a signature substring, or a Lucene string). Use to see how often a source has appeared and on what signatures.
- search_past_cases: check how similar alerts were resolved before. Provide "value" (an IP address, or a MITRE technique id like T1190, or a tag). A repeated FalsePositive history is strong evidence toward benign.
- get_mitre_context: get the ATT&CK description for a technique. Provide "technique" (e.g. T1190).
- get_playbook: get the standard operating procedure. Provide "alert_type" (e.g. juiceshop_sqli).
- run_analyzer: trigger FRESH threat-intelligence enrichment on an IP if you need more than history alone provides. Provide "observable" (the IP) and "analyzer_name" — one of: AbuseIPDB, GreyNoise (distinguishes mass internet scanners from targeted attackers — use this for recon/scan alerts when you are unsure), VirusTotal_GetReport, Shodan_Host (exposure/service context), AlienVault_OTX, URLhaus. Only usable once the case exists; if it returns "not_wired", the case isn't promoted yet — rely on the other tools instead.
- conclude: stop investigating and give your assessment.

NETWORK BASELINE:
- 192.168.10.0/24 = internal LAN, 172.16.0.0/24 = DMZ (172.16.0.10 = Juice Shop, deliberately vulnerable), 100.64.0.0/10 = Tailscale (our own admin access; our red-team Kali is 100.125.163.9).
- Internal-to-internal discovery traffic (SSDP/UPnP/mDNS/NetBIOS) is normal background noise.
- Signatures in the "Not Suspicious Traffic" or "Misc activity" category, or whose name begins "ET INFO", are INFORMATIONAL — treat as benign/false-positive unless the surrounding evidence shows real attacker behaviour. An internal host making an outbound request with a PowerShell user-agent is normal admin tooling here, not an attack.
- A true positive normally involves an EXTERNAL source IP or a clear exploitation/credential/persistence payload.

RULES:
- Investigate BEFORE concluding. For any alert with an external IP, check reputation history (search_past_cases) and/or SIEM history (search_elasticsearch) first. Do not conclude on a guess.
- For persistence (scheduled task, registry Run key, account creation/manipulation) and PowerShell execution alerts specifically: call get_playbook BEFORE concluding. These technique classes have lab-specific false-positive patterns (e.g. legitimate OS update tasks, benign built-in PowerShell variables) that materially change the verdict and are easy to get wrong from the alert title alone.
- For any alert whose likely technique is a C2 beacon to an external IP (Cobalt Strike/AdaptixC2/AsyncRAT-style): call BOTH search_past_cases AND run_analyzer on that IP before concluding, even if one alone already looks decisive. Case history alone does not tell you whether the indicator is still active; a fresh analyzer alone does not tell you how it was resolved before. The downstream automated-response policy requires evidence from both tools, not just a verdict, before it will ever consider an automatic response — investigate accordingly rather than stopping at the first useful result.
- Two or three well-chosen tool calls are usually enough for other alert types. Once you have checked history and any relevant context (and, for C2-style alerts, both tools above), CONCLUDE. Do not keep searching.
- You do NOT decide whether to block anything. You only assess. Containment policy is enforced separately by code.
- CRITICAL: traffic from our own red-team Kali (100.125.163.9) or the Tailscale range is our own infrastructure, but a real exploitation payload (SQLi, XSS, LFI/path-traversal, brute-force, C2 beacon, credential dumping) is STILL a real attack and MUST be assessed "malicious" with the correct technique. Do NOT downgrade a genuine attack to "benign" just because the source is ours. Whether it is authorized penetration testing is a HUMAN's determination — your job is to identify the attack. The containment guard will correctly refuse to block our own infrastructure and the case will escalate to a human either way. Reserve "benign" ONLY for genuine non-attacks: discovery/broadcast noise (SSDP/UPnP/mDNS) and ET INFO / "Not Suspicious Traffic" signatures.
- confidence is a number STRICTLY between 0.0 and 1.0 (never above 1.0). It expresses how sure you are of your verdict. If you are genuinely unsure, use a LOW value (e.g. 0.3) and verdict "inconclusive" — that escalates to a human. High confidence (>0.75) means you are certain.
- mitre_technique must be one of the allowed enum values, or "N/A" if benign. Do not invent one.
- Do not repeat the same tool call with the same arguments.
- If run_analyzer returns "not_wired" or an error, do NOT retry it — fall back to search_past_cases/search_elasticsearch instead.

CALIBRATION — a clear exploitation payload is decisive evidence on its own; do not hedge to "inconclusive" when the alert already shows an attack:
- SQL-injection auth bypass (e.g. body `' OR 1=1--` returning HTTP 200 + an admin token) → verdict "malicious", severity "critical", technique T1190, confidence ~0.95.
- C2 beacon to/from an IP designated a known-malicious C2 (ThreatFox/ET MALWARE, e.g. Cobalt Strike/AdaptixC2/AsyncRAT) → "malicious", "high", T1071.001, ~0.9. A threat-intel "known C2" designation is decisive on its own; an EMPTY local SIEM search does NOT lower it (a private lab cannot see a public C2's reputation locally).
- Credential dumping (e.g. `reg save HKLM\\SAM`) → "malicious", "high", T1003.002, ~0.9.
- Brute force (repeated failed SSH or Windows logons from one external source) → "malicious", "medium", T1110, ~0.85.
- Network service scan / nmap recon → "malicious", "medium", T1046, ~0.85.
- Internal host → own gateway on a discovery protocol (SSDP/UPnP/mDNS) → "benign", "low", N/A, ~0.95.
- Our own PowerShell Invoke-WebRequest tooling tripping an ET INFO signature → "benign", "low", N/A, ~0.9.
Note: a "malicious" verdict does NOT mean the source will be blocked — the guard still refuses to act on internal/Tailscale addresses. Assess the threat honestly; containment is decided separately.

Return ONLY a JSON object matching the schema. No prose."""


def _call(messages, schema):
    payload = {"model": OLLAMA_MODEL, "messages": messages, "format": schema,
               "stream": False, "options": {"temperature": 0}}
    r = requests.post(OLLAMA_CHAT_URL, json=payload, timeout=OLLAMA_TIMEOUT)
    r.raise_for_status()
    return r.json()["message"]["content"]


def _dispatch(action: str, step: dict, api=None, observables=None) -> dict:
    """Route a chosen action to the matching tool with the right argument."""
    if action == "search_elasticsearch":
        return T.search_elasticsearch(step.get("query", ""))
    if action == "search_past_cases":
        return T.search_past_cases(step.get("value", ""))
    if action == "get_mitre_context":
        return T.get_mitre_context(step.get("technique", ""))
    if action == "get_playbook":
        return T.get_playbook(step.get("alert_type", ""))
    if action == "run_analyzer":
        return T.run_analyzer(step.get("observable", ""), step.get("analyzer_name", ""),
                              api=api, observables=observables)
    return {"error": f"unknown action {action}"}


def investigate(alert: dict, observables: list, verbose: bool = True, api=None) -> dict:
    """
    Run the agent loop over one alert. Returns a dict with the verdict, the full
    reasoning trace, and the guard's containment decision (evaluated, NOT executed).

    `api` (a thehive4py TheHiveApi instance) is optional — only needed for
    run_analyzer to trigger live Cortex enrichment. Pass it, plus real CASE
    observables (with _id), once the alert has been promoted to a case; without it
    run_analyzer degrades honestly to "not_wired" rather than fabricating data.
    """
    obs_summary = [{"type": o.get("dataType"), "value": o.get("data"),
                    "tags": o.get("tags")} for o in (observables or [])]
    user0 = {"title": alert.get("title"), "description": (alert.get("description") or "")[:1200],
             "severity": alert.get("severity"), "tags": alert.get("tags"),
             "observables": obs_summary}
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": "ALERT:\n" + json.dumps(user0, indent=2, default=str)}]

    trace = []
    tools_used = []
    concluded = False
    seen_calls = set()      # (action, arg) already run — kill repeated/wasteful calls
    repeats = 0
    empty_failures = 0      # consecutive empty-arg calls — kill flailing separately

    REQUIRED_FIELD = {
        "search_elasticsearch": "query", "search_past_cases": "value",
        "get_mitre_context": "technique", "get_playbook": "alert_type",
        "run_analyzer": "observable AND analyzer_name",
    }

    def _arg_of(action, step):
        if action == "run_analyzer":
            obs, an = step.get("observable", "").strip(), step.get("analyzer_name", "").strip()
            return f"{obs}:{an}" if obs and an else ""
        return {"search_elasticsearch": step.get("query"),
                "search_past_cases": step.get("value"),
                "get_mitre_context": step.get("technique"),
                "get_playbook": step.get("alert_type")}.get(action, "")

    for i in range(MAX_ITERS):
        try:
            raw = _call(messages, ACTION_SCHEMA)
            step = json.loads(raw)
        except Exception as exc:
            # Fail-safe: leave for a human, exactly like the pipeline's triage==None.
            return {"error": f"agent step failed: {exc}", "trace": trace,
                    "verdict": None, "outcome": "left_for_human"}

        action = step.get("action")
        thought = step.get("thought", "")
        messages.append({"role": "assistant", "content": raw})

        if action == "conclude":
            concluded = True
            trace.append({"step": i + 1, "action": "conclude", "thought": thought})
            if verbose:
                print(f"   [{i+1}] conclude — {thought[:80]}")
            break

        arg = (_arg_of(action, step) or "").strip()

        # Reject empty-argument tool calls — they waste a turn and return nothing useful.
        # Name the exact missing field: a generic "provide an argument" message let the
        # model repeat the same empty call up to the iteration cap without correcting it.
        if not arg:
            empty_failures += 1
            messages.append({"role": "user", "content":
                f"{action} requires the '{REQUIRED_FIELD.get(action, '?')}' field, which "
                f"you left empty. Provide it now, or choose 'conclude' if you already "
                f"have enough evidence."})
            trace.append({"step": i + 1, "action": action, "arg": "", "thought": thought,
                          "result": {"skipped": "empty argument"}})
            if verbose:
                print(f"   [{i+1}] {action}() -> skipped (empty arg)")
            if empty_failures >= 3:      # persistent flailing — stop and force a verdict
                if verbose:
                    print(f"   [{i+1}] repeated empty-arg calls — forcing conclusion")
                break
            continue

        # Kill repeated identical calls — the model otherwise loops on the same lookup.
        if (action, arg) in seen_calls:
            repeats += 1
            messages.append({"role": "user", "content":
                f"You already called {action}({arg}); the result is above. Do NOT repeat a "
                f"call. Investigate something new or conclude."})
            trace.append({"step": i + 1, "action": action, "arg": arg, "thought": thought,
                          "result": {"skipped": "duplicate call"}})
            if verbose:
                print(f"   [{i+1}] {action}({arg}) -> skipped (duplicate)")
            if repeats >= 2:      # persistent looping — stop and force a verdict
                if verbose:
                    print(f"   [{i+1}] repeated calls — forcing conclusion")
                break
            continue

        seen_calls.add((action, arg))
        result = _dispatch(action, step, api=api, observables=observables)
        tools_used.append(action)
        trace.append({"step": i + 1, "action": action, "arg": arg,
                      "thought": thought, "result": result})
        if verbose:
            if action == "run_analyzer" and result.get("status") == "Success":
                rsummary = f"{len(result.get('taxonomies', []))} taxonomy tag(s)"
            else:
                rsummary = result.get("hint") or result.get("total_matches") or \
                           result.get("name") or result.get("playbook") or \
                           result.get("status") or result.get("error") or "ok"
            print(f"   [{i+1}] {action}({arg}) -> {rsummary}")
        messages.append({"role": "user",
                         "content": "TOOL RESULT:\n" + json.dumps(result, default=str)[:2000]})

    # Force a verdict (dedicated schema) whether it concluded or hit the cap.
    # Re-state the ORIGINAL alert here, not just "give your verdict" — found live:
    # with no IP observable to anchor on (a real case for host-only alerts like
    # scheduled tasks), one stray tool result late in the trace (e.g. an irrelevant
    # playbook fetched by mistake) could dominate recency and pull the verdict onto
    # a completely different alert (a Windows persistence alert got assessed as the
    # Juice Shop SQLi playbook's contents). Re-anchoring fixes it cheaply.
    try:
        vraw = _call(messages + [{"role": "user", "content":
                     "Provide your final verdict now as JSON, for THIS alert only:\n"
                     + json.dumps(user0, indent=2, default=str)}], VERDICT_SCHEMA)
        verdict = json.loads(vraw)
    except Exception as exc:
        return {"error": f"verdict failed: {exc}", "trace": trace,
                "verdict": None, "outcome": "left_for_human"}

    # Constrained decoding enforces TYPE reliably but RANGE only best-effort (same
    # caveat as the orchestrator). An out-of-range confidence is untrustworthy — treat
    # it as low confidence so it escalates rather than ever clearing the auto floor.
    try:
        c = float(verdict.get("confidence"))
    except (TypeError, ValueError):
        c = 0.0
    if not 0.0 <= c <= 1.0:
        verdict["confidence_raw"] = verdict.get("confidence")
        verdict["confidence"] = 0.0
        verdict["reason"] = ("[confidence out of range — forced to 0.0, escalating] "
                             + str(verdict.get("reason", "")))
    else:
        verdict["confidence"] = c

    # ---- hand the verdict to the REAL guard (evaluate only, never execute) ----
    target_obs, target_reason = select_containment_target(observables or [])
    target_ip = target_obs.get("data") if target_obs else None
    if verdict["verdict"] == "malicious" and target_ip:
        allowed, guard_reason = containment_allowed(target_ip, verdict["confidence"])
    else:
        allowed, guard_reason = False, ("no malicious verdict" if verdict["verdict"] != "malicious"
                                        else target_reason)

    # Tiered autonomy: allow -> auto-respond; refuse -> escalate to human.
    disposition = "AUTO-RESPOND" if allowed else "ESCALATE-TO-HUMAN"

    return {
        "verdict": verdict, "trace": trace, "iters": len(trace),
        "tools_used": tools_used, "concluded_naturally": concluded,
        "containment": {"target": target_ip, "allowed": allowed,
                        "reason": guard_reason, "disposition": disposition},
    }


# ==============================================================================
# SELF-TEST — run the agent read-only over real closed cases (no execution)
# ==============================================================================

def _fetch_case_observables(case_id: str) -> list:
    r = requests.post(f"{T.THEHIVE_URL}/api/v1/query",
                      headers={"Authorization": f"Bearer {T.THEHIVE_API_KEY}"},
                      json={"query": [{"_name": "getCase", "idOrName": case_id},
                                      {"_name": "observables"},
                                      {"_name": "page", "from": 0, "to": 20}]}, timeout=15)
    r.raise_for_status()
    return r.json()


def _recent_cases(n: int = 2) -> list:
    r = requests.post(f"{T.THEHIVE_URL}/api/v1/query",
                      headers={"Authorization": f"Bearer {T.THEHIVE_API_KEY}"},
                      json={"query": [{"_name": "listCase"},
                                      {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
                                      {"_name": "page", "from": 0, "to": n}]}, timeout=15)
    r.raise_for_status()
    return r.json()


if __name__ == "__main__":
    import sys
    if not T.THEHIVE_API_KEY:
        sys.exit("set THEHIVE_API_KEY (and ES_PASSWORD) before the self-test")

    print("=" * 70)
    print(f"  SOC AGENT SELF-TEST — read-only over real cases · {OLLAMA_MODEL}")
    print("=" * 70)

    cases = _recent_cases(2)
    for c in cases:
        cid = c.get("_id")
        print(f"\n{'─'*70}\nCASE {cid} — {c.get('title')}  (actual disposition: {c.get('status')})")
        obs = _fetch_case_observables(cid)
        alert = {"title": c.get("title"), "description": c.get("description"),
                 "severity": c.get("severity"), "tags": c.get("tags")}
        t0 = time.time()
        res = investigate(alert, obs)
        dt = time.time() - t0
        if res.get("verdict"):
            v = res["verdict"]
            print(f"   VERDICT: {v['verdict'].upper()} conf={v['confidence']:.2f} "
                  f"sev={v['severity']} tech={v['mitre_technique']}")
            print(f"   evidence: {v['key_evidence'][:120]}")
            print(f"   containment: {res['containment']['disposition']} "
                  f"({res['containment']['reason']})")
            print(f"   tools used: {res['tools_used']}  |  {res['iters']} steps  |  {dt:.1f}s")
        else:
            print(f"   {res.get('outcome')} — {res.get('error')}")
    print("\n" + "=" * 70)
