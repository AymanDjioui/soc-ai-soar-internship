#!/usr/bin/env python3
"""
LLM triage benchmark — runs a fixed prompt across N models over the golden test set.

Usage:
    python3 benchmark.py --models phi4-mini mistral:7b --prompt v3-zeroshot
    python3 benchmark.py --models phi4-mini --prompt v3-fewshot

Writes:
    results/raw/<prompt>__<model>__<case>.json    every raw response
    results/results.csv                            appended scored rows
"""
import argparse, csv, json, os, time, urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
TESTSET = os.path.join(HERE, "testset")
RESULTS = os.path.join(HERE, "results")
RAW = os.path.join(RESULTS, "raw")
OLLAMA = "http://127.0.0.1:11434/api/chat"

SYSTEM = """You are a Tier-1 SOC analyst for a lab network. Be precise and conservative.

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
- mitre_technique MUST be a MITRE ATT&CK technique ID of form T#### or T####.###
  (e.g. T1190, T1003.002). It is NOT a CVE number. If the event is benign or no
  technique applies, return exactly "N/A".
- severity reflects real impact in THIS environment, not the raw signature severity.
- confidence is 0.0 to 1.0. Use low confidence when genuinely unsure.

Return ONLY a JSON object. No prose, no markdown fences."""

# safe_to_auto_block deliberately REMOVED from every schema.
# Containment eligibility is deterministic policy computed in code (see policy_guard),
# never a model opinion. See ai/results/prompt-iteration-log.md v2 regression.

# Techniques actually validated in this lab (= the ROADMAP C1 MITRE catalog).
# "OTHER" is the escape hatch: an alert whose technique is not in our catalog must be
# admitted as unknown and escalated to a human, never forced into a wrong-but-plausible ID.
LAB_TECHNIQUES = [
    "N/A",          # benign / no technique applies
    "T1190",        # Exploit Public-Facing Application (SQLi, XSS on Juice Shop)
    "T1046",        # Network Service Discovery (nmap)
    "T1003.002",    # OS Credential Dumping: SAM (reg save HKLM\\SAM)
    "T1110",        # Brute Force (SSH + web login)
    "T1059.001",    # Command & Scripting: PowerShell (encoded command)
    "T1547.001",    # Persistence: Registry Run Key
    "T1053.005",    # Persistence: Scheduled Task
    "T1053.003",    # Persistence: Cron
    "T1136.001",    # Create Account: Local Account (backdoor user)
    "T1098",        # Account Manipulation (admin group add)
    "T1548",        # Abuse Elevation Control Mechanism (su privesc)
    "T1071.001",    # C2: Web Protocols
    "T1078",        # Valid Accounts (stolen token / auth bypass)
    "OTHER",        # not in catalog -> escalate to human
]

_BASE_PROPS = {
    "summary":            {"type": "string"},
    "severity":           {"type": "string", "enum": ["low", "medium", "high", "critical"]},
    "is_false_positive":  {"type": "boolean"},
    "confidence":         {"type": "number"},
    "recommended_action": {"type": "string"},
}
_REQUIRED = ["summary", "severity", "is_false_positive", "confidence",
             "mitre_technique", "recommended_action"]

# v3: free-form pattern. Validates SHAPE only - the model can invent any T-number.
SCHEMA_V3 = {
    "type": "object",
    "properties": {**_BASE_PROPS,
                   "mitre_technique": {"type": "string",
                                       "pattern": r"^(T[0-9]{4}(\.[0-9]{3})?|N/A)$"}},
    "required": _REQUIRED,
}

# v4: closed enum + OTHER escape hatch + reasoning field.
# Constrained decoding makes inventing an off-list ID physically impossible.
SCHEMA_V4 = {
    "type": "object",
    "properties": {**_BASE_PROPS,
                   "mitre_technique": {"type": "string", "enum": LAB_TECHNIQUES},
                   "technique_reasoning": {"type": "string"}},
    "required": _REQUIRED + ["technique_reasoning"],
}

SCHEMAS = {"v3-pattern": SCHEMA_V3, "v4-enum": SCHEMA_V4}

# Few-shot examples. Deliberately NOT drawn from the test set, so every scored
# case remains genuinely held out.
FEWSHOT = [
    ({"event_type": "alert", "src_ip": "192.168.10.30", "dest_ip": "224.0.0.251", "in_iface": "em1",
      "alert": {"signature": "ET INFO mDNS Query Observed", "signature_id": 2000001,
                "category": "Misc activity", "severity": 3}},
     {"summary": "Windows host sent a routine mDNS service-discovery query to the local "
                 "multicast address. Normal LAN background traffic.",
      "severity": "low", "is_false_positive": True, "confidence": 0.95,
      "mitre_technique": "N/A",
      "recommended_action": "No action. Consider tuning this signature to reduce noise."}),
    ({"event_type": "alert", "src_ip": "45.155.205.211", "dest_ip": "172.16.0.10", "in_iface": "em2",
      "alert": {"signature": "ET WEB_SERVER SQL Injection UNION SELECT", "signature_id": 2006446,
                "category": "Web Application Attack", "severity": 1},
      "http": {"url": "/rest/products/search?q=' UNION SELECT * FROM users--"}},
     {"summary": "External host attempted SQL injection against the DMZ web application "
                 "using a UNION SELECT payload to extract user data.",
      "severity": "critical", "is_false_positive": False, "confidence": 0.93,
      "mitre_technique": "T1190",
      "recommended_action": "Block the source IP and review application logs for successful extraction."}),
]


def policy_guard(alert: dict) -> bool:
    """Deterministic containment policy. Returns True only if the source IP may be
    auto-blocked. This is CODE, not a model opinion - it can only ever veto."""
    import ipaddress
    src = alert.get("src_ip") or alert.get("access_log", {}).get("client_ip")
    if not src:
        return False                       # host-based event, nothing to block
    try:
        ip = ipaddress.ip_address(src)
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False                       # our own infrastructure
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return False                       # Tailscale - blocking severs admin access
    return True


def build_messages(alert: dict, fewshot: bool):
    msgs = [{"role": "system", "content": SYSTEM}]
    if fewshot:
        for a, ans in FEWSHOT:
            msgs.append({"role": "user", "content": json.dumps(a, indent=2)})
            msgs.append({"role": "assistant", "content": json.dumps(ans)})
    msgs.append({"role": "user", "content": json.dumps(alert, indent=2)})
    return msgs


def call_ollama(model: str, messages: list, schema: dict, timeout: int = 900):
    payload = {"model": model, "messages": messages, "format": schema,
               "stream": False, "options": {"temperature": 0}}
    req = urllib.request.Request(OLLAMA, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = json.loads(r.read().decode())
    return body, time.time() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", required=True)
    ap.add_argument("--prompt", default="v3-zeroshot",
                    choices=["v3-zeroshot", "v3-fewshot"])
    ap.add_argument("--schema", default="v3-pattern",
                    choices=list(SCHEMAS.keys()))
    args = ap.parse_args()
    schema = SCHEMAS[args.schema]
    fewshot = args.prompt.endswith("fewshot")

    os.makedirs(RAW, exist_ok=True)
    cases = [json.load(open(os.path.join(TESTSET, f)))
             for f in sorted(os.listdir(TESTSET)) if f.endswith(".json")]

    csv_path = os.path.join(RESULTS, "results.csv")
    new = not os.path.exists(csv_path)
    fh = open(csv_path, "a", newline="")
    cols = ["schema", "prompt", "model", "case", "json_valid", "fp_correct", "severity_correct",
            "technique_correct", "score", "latency_s", "got_fp", "want_fp",
            "got_sev", "want_sev", "got_tech", "want_tech", "policy_blockable"]
    w = csv.DictWriter(fh, fieldnames=cols)
    if new:
        w.writeheader()

    for model in args.models:
        print(f"\n{'='*70}\n  {model}   [{args.prompt} | {args.schema}]\n{'='*70}")
        agg = {"json": 0, "fp": 0, "sev": 0, "tech": 0, "lat": 0.0, "n": 0}

        for c in cases:
            gt = c["ground_truth"]
            try:
                body, lat = call_ollama(model, build_messages(c["alert"], fewshot), schema)
                content = body.get("message", {}).get("content", "")
            except Exception as e:
                print(f"  {c['id']:<28} ERROR: {e}")
                w.writerow({"schema": args.schema, "prompt": args.prompt, "model": model, "case": c["id"],
                            "json_valid": 0, "fp_correct": 0, "severity_correct": 0,
                            "technique_correct": 0, "score": 0, "latency_s": "",
                            "got_fp": "", "want_fp": gt["is_false_positive"],
                            "got_sev": "", "want_sev": gt["severity"],
                            "got_tech": "", "want_tech": gt["mitre_technique"],
                            "policy_blockable": policy_guard(c["alert"])})
                continue

            json.dump({"case": c["id"], "model": model, "prompt": args.prompt,
                       "latency_s": round(lat, 2), "raw": content},
                      open(os.path.join(RAW, f"{args.schema}__{args.prompt}__{model.replace(':','-')}__{c['id']}.json"), "w"),
                      indent=2)

            try:
                out = json.loads(content)
                valid = 1
            except Exception:
                out, valid = {}, 0

            fp_ok  = int(valid and out.get("is_false_positive") == gt["is_false_positive"])
            sev_ok = int(valid and out.get("severity") == gt["severity"])
            tec_ok = int(valid and out.get("mitre_technique") == gt["mitre_technique"])
            score  = fp_ok + sev_ok + tec_ok

            agg["json"] += valid; agg["fp"] += fp_ok; agg["sev"] += sev_ok
            agg["tech"] += tec_ok; agg["lat"] += lat; agg["n"] += 1

            flag = "OK " if score == 3 else ("!! " if not fp_ok else "~  ")
            print(f"  {flag}{c['id']:<28} fp={fp_ok} sev={sev_ok} tech={tec_ok}  "
                  f"{lat:5.1f}s   got:{str(out.get('is_false_positive')):<5} "
                  f"{str(out.get('severity')):<8} {out.get('mitre_technique')}")

            w.writerow({"schema": args.schema, "prompt": args.prompt, "model": model, "case": c["id"],
                        "json_valid": valid, "fp_correct": fp_ok,
                        "severity_correct": sev_ok, "technique_correct": tec_ok,
                        "score": score, "latency_s": round(lat, 2),
                        "got_fp": out.get("is_false_positive"), "want_fp": gt["is_false_positive"],
                        "got_sev": out.get("severity"), "want_sev": gt["severity"],
                        "got_tech": out.get("mitre_technique"), "want_tech": gt["mitre_technique"],
                        "policy_blockable": policy_guard(c["alert"])})
            fh.flush()

        n = agg["n"] or 1
        print(f"  {'-'*66}")
        print(f"  JSON {agg['json']}/{n} · FP {agg['fp']}/{n} · SEV {agg['sev']}/{n} · "
              f"TECH {agg['tech']}/{n} · total {agg['fp']+agg['sev']+agg['tech']}/{n*3} · "
              f"avg {agg['lat']/n:.1f}s")

    fh.close()
    print(f"\nresults -> {csv_path}")


if __name__ == "__main__":
    main()
