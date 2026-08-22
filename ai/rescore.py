#!/usr/bin/env python3
"""
Rebuild results.csv from the preserved raw model outputs.

Scoring is deliberately separated from running: raw/ is the immutable record of what
each model actually said, and this script derives the scored table from it. That means
scoring rules can change without re-running 50+ inferences, and results.csv can always
be regenerated from evidence.

Usage:  python3 rescore.py
"""
import csv, json, os, ipaddress

HERE = os.path.dirname(os.path.abspath(__file__))
TESTSET = os.path.join(HERE, "testset")
RAW = os.path.join(HERE, "results", "raw")
OUT = os.path.join(HERE, "results", "results.csv")


def policy_guard(alert: dict) -> bool:
    """Deterministic containment policy — code, not model opinion. Veto-only."""
    src = alert.get("src_ip") or alert.get("access_log", {}).get("client_ip")
    if not src:
        return False
    try:
        ip = ipaddress.ip_address(src)
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return True


def parse_name(fn: str):
    """Handles both naming generations:
       new: <schema>__<prompt>__<model>__<case>.json
       old: <prompt>__<model>__<case>.json   (before --schema existed => v3-pattern)"""
    parts = fn[:-5].split("__")
    if len(parts) == 4:
        return parts[0], parts[1], parts[2], parts[3]
    if len(parts) == 3:
        return "v3-pattern", parts[0], parts[1], parts[2]
    raise ValueError(fn)


def main():
    cases = {}
    for f in os.listdir(TESTSET):
        if f.endswith(".json"):
            c = json.load(open(os.path.join(TESTSET, f)))
            cases[c["id"]] = c

    rows = []
    for fn in sorted(os.listdir(RAW)):
        if not fn.endswith(".json"):
            continue
        schema, prompt, model_fn, case_id = parse_name(fn)
        blob = json.load(open(os.path.join(RAW, fn)))
        case = cases[case_id]
        gt = case["ground_truth"]

        try:
            out = json.loads(blob.get("raw", ""))
            valid = 1
        except Exception:
            out, valid = {}, 0

        fp_ok = int(valid and out.get("is_false_positive") == gt["is_false_positive"])
        sev_ok = int(valid and out.get("severity") == gt["severity"])
        tec_ok = int(valid and out.get("mitre_technique") == gt["mitre_technique"])

        rows.append({
            "schema": schema, "prompt": prompt,
            "model": blob.get("model", model_fn.replace("-", ":", 1)),
            "case": case_id,
            "json_valid": valid, "fp_correct": fp_ok,
            "severity_correct": sev_ok, "technique_correct": tec_ok,
            "score": fp_ok + sev_ok + tec_ok,
            "latency_s": blob.get("latency_s", ""),
            "got_fp": out.get("is_false_positive"), "want_fp": gt["is_false_positive"],
            "got_sev": out.get("severity"), "want_sev": gt["severity"],
            "got_tech": out.get("mitre_technique"), "want_tech": gt["mitre_technique"],
            "policy_blockable": policy_guard(case["alert"]),
        })

    cols = ["schema", "prompt", "model", "case", "json_valid", "fp_correct",
            "severity_correct", "technique_correct", "score", "latency_s",
            "got_fp", "want_fp", "got_sev", "want_sev", "got_tech", "want_tech",
            "policy_blockable"]
    with open(OUT, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    print(f"rebuilt {OUT}: {len(rows)} rows\n")

    # summary per configuration
    from collections import defaultdict
    agg = defaultdict(lambda: dict(n=0, j=0, fp=0, sev=0, tec=0, lat=0.0))
    for r in rows:
        k = (r["model"], r["prompt"], r["schema"])
        a = agg[k]
        a["n"] += 1; a["j"] += r["json_valid"]; a["fp"] += r["fp_correct"]
        a["sev"] += r["severity_correct"]; a["tec"] += r["technique_correct"]
        a["lat"] += float(r["latency_s"] or 0)

    hdr = f"{'model':<14}{'prompt':<13}{'schema':<12}{'JSON':>5}{'FP':>5}{'SEV':>5}{'TECH':>6}{'TOTAL':>8}{'avg s':>8}"
    print(hdr); print("-" * len(hdr))
    for k in sorted(agg, key=lambda k: -(agg[k]["fp"] + agg[k]["sev"] + agg[k]["tec"])):
        a = agg[k]; n = a["n"]
        tot = a["fp"] + a["sev"] + a["tec"]
        print(f"{k[0]:<14}{k[1]:<13}{k[2]:<12}"
              f"{a['j']}/{n:<3}{a['fp']}/{n:<3}{a['sev']}/{n:<3}{a['tec']}/{n:<4}"
              f"{tot:>4}/{n*3:<3}{a['lat']/n:>8.1f}")


if __name__ == "__main__":
    main()
