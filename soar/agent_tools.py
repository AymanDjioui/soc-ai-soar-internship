#!/usr/bin/env python3
"""
Agent tools — the callable capabilities the SOC agent (Phase D) can choose from.

Standalone and importable. This module deliberately does NOT import or modify
e2e_soc_orchestrator.py: the agent build stays in parallel mode (AGENT-ROADMAP.md
decision 2) so the proven pipeline is never disturbed.

Each tool returns a COMPACT dict suitable to feed straight back into the LLM as a
tool-result turn — never a raw multi-KB API response (the same lesson as the
orchestrator's taxonomy distillation: noise degrades the verdict).

Tools:
    search_elasticsearch(query, ...)  — related events / history for an IP or signature
    search_past_cases(value)          — RAG over closed TheHive cases (IP or technique)
    get_mitre_context(technique)      — ATT&CK reference for a lab technique
    get_playbook(alert_type)          — retrieve the matching SOP
    run_analyzer(...)                 — Cortex enrichment (interface only; wired in Phase D)

Config via env (same names as the orchestrator, no secrets in source):
    THEHIVE_URL, THEHIVE_API_KEY, ES_URL, ES_USER, ES_PASSWORD
"""
import ipaddress
import json
import os

import requests

THEHIVE_URL = os.environ.get("THEHIVE_URL", "http://100.124.232.121:9000")
THEHIVE_API_KEY = os.environ.get("THEHIVE_API_KEY")
ES_URL = os.environ.get("ES_URL", "http://100.99.54.59:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD")

_HERE = os.path.dirname(os.path.abspath(__file__))
_KB = os.path.join(_HERE, "agent_kb")
_MITRE_PATH = os.path.join(_KB, "mitre.json")
_PLAYBOOK_DIR = os.path.join(_KB, "playbooks")

HTTP_TIMEOUT = 15


def _es_auth():
    return (ES_USER, ES_PASSWORD) if ES_PASSWORD else None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


# ==============================================================================
# TOOL 1 — search_elasticsearch
# ==============================================================================

def search_elasticsearch(query: str, index: str = "suricata-alerts-*",
                         size: int = 5, hours: int = 720) -> dict:
    """
    Query ES for events matching `query` (an IP, signature substring, or Lucene
    string) in the last `hours`. Returns a compact histogram + a few samples, not
    the raw hits — the agent needs 'how often / what signatures', not 10 KB of docs.
    """
    body = {
        "size": size,
        "query": {"bool": {"must": [{"query_string": {"query": query}}],
                           "filter": [{"range": {"@timestamp":
                                      {"gte": f"now-{hours}h"}}}]}},
        "aggs": {"top_sigs": {"terms":
                 {"field": "alert.signature.keyword", "size": 5}}},
        "sort": [{"@timestamp": {"order": "desc"}}],
    }
    try:
        r = requests.get(f"{ES_URL}/{index}/_search", auth=_es_auth(),
                         json=body, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        return {"tool": "search_elasticsearch", "error": str(exc)}

    hits = data.get("hits", {})
    total = hits.get("total", {})
    total = total.get("value", total) if isinstance(total, dict) else total
    sigs = [{"signature": b["key"], "count": b["doc_count"]}
            for b in data.get("aggregations", {}).get("top_sigs", {}).get("buckets", [])]
    samples = []
    for h in hits.get("hits", [])[:size]:
        s = h.get("_source", {})
        samples.append({
            "ts": s.get("@timestamp"),
            "src": (s.get("src_ip") or s.get("source", {}).get("ip")),
            "dest": (s.get("dest_ip") or s.get("destination", {}).get("ip")),
            "signature": s.get("alert", {}).get("signature"),
        })
    return {"tool": "search_elasticsearch", "query": query, "window_hours": hours,
            "total_matches": total, "top_signatures": sigs, "samples": samples}


# ==============================================================================
# TOOL 2 — search_past_cases  (RAG over closed TheHive cases)
# ==============================================================================

def _thehive_query(query_blocks: list) -> list:
    r = requests.post(f"{THEHIVE_URL}/api/v1/query",
                      headers={"Authorization": f"Bearer {THEHIVE_API_KEY}",
                               "Content-Type": "application/json"},
                      json={"query": query_blocks}, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    return r.json()


def search_past_cases(value: str, limit: int = 10) -> dict:
    """
    'Have we seen this before, and how did we resolve it?'

    If `value` is an IP: find observables with that data, then the cases they belong
    to, and summarise the dispositions (TruePositive / FalsePositive / ...).
    If `value` is a MITRE technique id (T....): find cases tagged with it.

    Returns disposition counts + a few titles — the analyst-memory signal that most
    reduces false positives (a repeatedly-benign IP should not be re-escalated).
    """
    try:
        if _is_ip(value):
            # observables with this IP -> their parent cases
            obs = _thehive_query([
                {"_name": "listObservable"},
                {"_name": "filter", "_field": "data", "_value": value},
                {"_name": "page", "from": 0, "to": 50},
            ])
            case_ids = []
            for o in obs:
                oid = o.get("_id")
                if not oid:
                    continue
                try:
                    parents = _thehive_query([
                        {"_name": "getObservable", "idOrName": oid},
                        {"_name": "case"},
                        {"_name": "page", "from": 0, "to": 5},
                    ])
                    case_ids.extend(parents)
                except Exception:
                    continue
            cases = case_ids
        else:
            cases = _thehive_query([
                {"_name": "listCase"},
                {"_name": "filter", "_field": "tags", "_value": value},
                {"_name": "page", "from": 0, "to": limit},
            ])
    except Exception as exc:
        return {"tool": "search_past_cases", "value": value, "error": str(exc)}

    dispositions = {}
    titles = []
    seen = set()
    for c in cases:
        cid = c.get("_id")
        if cid in seen:
            continue
        seen.add(cid)
        st = c.get("status", "unknown")
        dispositions[st] = dispositions.get(st, 0) + 1
        if len(titles) < 5:
            titles.append({"title": c.get("title"), "status": st,
                           "stage": c.get("stage")})

    return {"tool": "search_past_cases", "value": value,
            "cases_found": len(seen), "dispositions": dispositions,
            "sample_titles": titles,
            "hint": ("no prior cases for this value" if not seen else
                     "prior FalsePositive history — weigh toward benign"
                     if dispositions.get("FalsePositive", 0) > dispositions.get("TruePositive", 0)
                     else "prior TruePositive history — weigh toward malicious"
                     if dispositions.get("TruePositive", 0) else "mixed/other history")}


# ==============================================================================
# TOOL 3 — get_mitre_context
# ==============================================================================

_MITRE_CACHE = None


def get_mitre_context(technique: str) -> dict:
    """ATT&CK reference for a lab technique id (e.g. 'T1190')."""
    global _MITRE_CACHE
    if _MITRE_CACHE is None:
        try:
            with open(_MITRE_PATH, encoding="utf-8") as fh:
                _MITRE_CACHE = json.load(fh)
        except Exception as exc:
            return {"tool": "get_mitre_context", "error": f"KB unavailable: {exc}"}
    key = str(technique).strip()
    entry = _MITRE_CACHE.get(key.upper())
    if entry:
        return {"tool": "get_mitre_context", "technique": key.upper(), **entry}

    # Parent-technique match: the model often passes the bare parent id ("T1053")
    # when the KB only has sub-techniques ("T1053.005", "T1053.003") — found live
    # 2026-08-20 (a real campaign alert tagged T1053.005 got "not a lab technique"
    # because the model asked for "T1053"). Return every matching sub-technique
    # rather than picking one arbitrarily.
    kup = key.upper()
    if not kup.startswith("T") and kup.isdigit():
        kup = "T" + kup
    if "." not in kup:
        matches = {tid: e for tid, e in _MITRE_CACHE.items() if tid.startswith(kup + ".")}
        if matches:
            return {"tool": "get_mitre_context", "technique": key,
                    "matched_by": "parent_technique", "sub_techniques": matches}

    # Loose match on the technique NAME (the model often passes "Path Traversal"
    # instead of an id). Match if the query is a substring of a technique's name.
    q = key.lower()
    for tid, e in _MITRE_CACHE.items():
        if tid.startswith("T") and (q in e.get("name", "").lower()
                                    or e.get("name", "").lower() in q):
            return {"tool": "get_mitre_context", "technique": tid, "matched_by": "name", **e}
    return {"tool": "get_mitre_context", "technique": technique,
            "error": "not a lab technique",
            "known": {k: v["name"] for k, v in _MITRE_CACHE.items() if k.startswith("T")}}


# ==============================================================================
# TOOL 4 — get_playbook
# ==============================================================================

_PLAYBOOK_INDEX = {
    # web app attacks
    "sqli": "sqli-juiceshop", "juiceshop_sqli": "sqli-juiceshop",
    "juiceshop": "sqli-juiceshop", "sql": "sqli-juiceshop",
    "t1190": "sqli-juiceshop", "web": "sqli-juiceshop",
    "lfi": "sqli-juiceshop", "traversal": "sqli-juiceshop", "xss": "sqli-juiceshop",
    # command-and-control
    "c2": "c2-beacon", "beacon": "c2-beacon", "cnc": "c2-beacon", "c2 beacon": "c2-beacon",
    "cobalt": "c2-beacon", "cobalt strike": "c2-beacon", "asyncrat": "c2-beacon",
    "adaptixc2": "c2-beacon", "malware": "c2-beacon", "t1071": "c2-beacon", "t1071.001": "c2-beacon",
    # brute force — linux/ssh
    "ssh": "ssh-bruteforce", "ssh brute-force": "ssh-bruteforce",
    "linux_ssh_bruteforce": "ssh-bruteforce", "ssh_bruteforce": "ssh-bruteforce",
    # brute force — windows
    "windows logon brute-force": "windows-logon-bruteforce",
    "windows logon": "windows-logon-bruteforce", "logon": "windows-logon-bruteforce",
    "smb": "windows-logon-bruteforce", "rdp": "windows-logon-bruteforce",
    "winrm": "windows-logon-bruteforce", "t1110": "ssh-bruteforce",
    "brute": "ssh-bruteforce", "bruteforce": "ssh-bruteforce", "brute-force": "ssh-bruteforce",
    # recon / scanning
    "recon": "recon-scanning", "scan": "recon-scanning", "nmap": "recon-scanning",
    "t1046": "recon-scanning", "port scan": "recon-scanning", "portscan": "recon-scanning",
    # credential dumping
    "credential dump": "credential-dumping", "cred-dump": "credential-dumping",
    "creddump": "credential-dumping", "sam": "credential-dumping", "lsass": "credential-dumping",
    "secretsdump": "credential-dumping", "t1003": "credential-dumping",
    "t1003.002": "credential-dumping",
    # persistence — scheduled task / registry run key / account creation/manipulation
    "persistence": "windows-persistence", "scheduled task": "windows-persistence",
    "t1053": "windows-persistence", "t1053.005": "windows-persistence",
    "t1053.003": "windows-persistence", "t1547": "windows-persistence",
    "t1547.001": "windows-persistence", "run key": "windows-persistence",
    "t1136": "windows-persistence", "t1136.001": "windows-persistence",
    "t1098": "windows-persistence", "new account": "windows-persistence",
    "account manipulation": "windows-persistence",
    # PowerShell execution
    "powershell": "powershell-execution", "t1059": "powershell-execution",
    "t1059.001": "powershell-execution", "script block": "powershell-execution",
    # privilege escalation
    "privilege escalation": "privilege-escalation", "privesc": "privilege-escalation",
    "t1548": "privilege-escalation", "uac": "privilege-escalation",
    # valid accounts / token abuse
    "valid account": "valid-accounts", "t1078": "valid-accounts",
    "token theft": "valid-accounts", "admin token": "valid-accounts",
}


def get_playbook(alert_type: str) -> dict:
    """
    Retrieve the SOP whose slug matches an alert type / tag / technique.

    Normalizes underscores/hyphens to spaces (the model sometimes passes
    "scheduled_task" for an index key stored as "scheduled task"). Loose matching
    tries LONGEST index keys first — a short generic key like "windows" would
    otherwise win a match it shouldn't just by appearing first in dict order
    (found live: "windows_persistence" was matching the brute-force playbook via
    the bare "windows" key before this fix).
    """
    key = str(alert_type).strip().lower().replace("_", " ")
    slug = _PLAYBOOK_INDEX.get(key)
    if not slug:
        for k in sorted(_PLAYBOOK_INDEX, key=len, reverse=True):
            if k in key:
                slug = _PLAYBOOK_INDEX[k]
                break
    if not slug:
        return {"tool": "get_playbook", "alert_type": alert_type,
                "error": "no matching playbook", "available": sorted(set(_PLAYBOOK_INDEX.values()))}
    path = os.path.join(_PLAYBOOK_DIR, slug + ".md")
    try:
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
    except Exception as exc:
        return {"tool": "get_playbook", "alert_type": alert_type, "error": str(exc)}
    return {"tool": "get_playbook", "alert_type": alert_type, "playbook": slug,
            "content": content}


# ==============================================================================
# TOOL 5 — run_analyzer  (real: triggers a live Cortex job against a case observable)
# ==============================================================================

def run_analyzer(value: str, analyzer_name: str, api=None, observables=None,
                 cortex_id: str = "Cortex-DevoteamSOC") -> dict:
    """
    Trigger a specific Cortex analyzer against an observable already present on the
    CURRENT case, and return its distilled taxonomies. Requires a live `api`
    (thehive4py TheHiveApi) and `observables` (the real case-observable list, with
    _id) — both are only available once the case has been promoted, which is why
    agent_orchestrator.py promotes BEFORE calling soc_agent.investigate().

    Without live context (standalone use, the golden-set bench, a fresh alert not
    yet promoted) this degrades to an honest "not_wired" result rather than
    fabricating enrichment data — same fail-safe principle as the rest of the agent.

    Reuses the orchestrator's own proven job-polling function
    (wait_for_analyzer_job) rather than reimplementing it, per the project's own
    "don't duplicate a subtle flow" discipline.
    """
    if api is None or not observables:
        return {"tool": "run_analyzer", "observable": value, "analyzer": analyzer_name,
                "status": "not_wired",
                "note": "no live case context available (standalone/benchmark run, or "
                        "the case has not been promoted yet) — analyzer NOT invoked, "
                        "no data fabricated"}

    obs = next((o for o in observables
               if o.get("dataType") == "ip" and o.get("data") == value), None)
    if obs is None:
        return {"tool": "run_analyzer", "observable": value, "analyzer": analyzer_name,
                "error": "no matching ip observable on this case for that value"}
    obs_id = obs.get("_id") or obs.get("id")

    try:
        catalog = api.cortex.list_analyzers()
    except Exception as exc:
        return {"tool": "run_analyzer", "error": f"could not list analyzers: {exc}"}

    match = next((a for a in catalog if str(a.get("name", "")).startswith(analyzer_name)),
                 None)
    if match is None:
        return {"tool": "run_analyzer", "observable": value, "analyzer": analyzer_name,
                "error": "analyzer not found/enabled",
                "available": sorted({a.get("name") for a in catalog})}

    try:
        job = api.cortex.create_analyzer_job({
            "analyzerId": match.get("id"), "cortexId": cortex_id, "artifactId": obs_id})
        job_id = job.get("_id") or job.get("id")
    except Exception as exc:
        return {"tool": "run_analyzer", "observable": value, "analyzer": match.get("name"),
                "error": f"job submission failed: {exc}"}

    import e2e_soc_orchestrator as orch  # lazy import: avoid module-load coupling
    try:
        status = orch.wait_for_analyzer_job(api, job_id)
    except TimeoutError as exc:
        return {"tool": "run_analyzer", "observable": value, "analyzer": match.get("name"),
                "error": str(exc)}
    if status.get("status") != "Success":
        return {"tool": "run_analyzer", "observable": value, "analyzer": match.get("name"),
                "status": status.get("status")}

    try:
        fresh = api.observable.get(obs_id)
    except Exception as exc:
        return {"tool": "run_analyzer", "error": f"could not fetch fresh observable: {exc}"}

    report = (fresh.get("reports") or {}).get(match.get("name"), {})
    taxonomies = [{"level": t.get("level"), "namespace": t.get("namespace"),
                  "predicate": t.get("predicate"), "value": t.get("value")}
                 for t in report.get("taxonomies", [])]
    return {"tool": "run_analyzer", "observable": value, "analyzer": match.get("name"),
            "status": "Success", "taxonomies": taxonomies}


# Registry the agent loop will expose to the model.
TOOLS = {
    "search_elasticsearch": search_elasticsearch,
    "search_past_cases": search_past_cases,
    "get_mitre_context": get_mitre_context,
    "get_playbook": get_playbook,
    "run_analyzer": run_analyzer,
}


if __name__ == "__main__":
    # Self-test against live data. Read-only; touches nothing armed.
    import sys
    if not THEHIVE_API_KEY:
        sys.exit("set THEHIVE_API_KEY (and ES_PASSWORD) before the self-test")

    print("=" * 66, "\nAGENT TOOLS SELF-TEST (read-only, live data)\n", "=" * 66)

    print("\n[1] get_mitre_context('T1190')")
    print("   ", json.dumps(get_mitre_context("T1190"))[:200])

    print("\n[2] get_playbook('juiceshop_sqli')")
    pb = get_playbook("juiceshop_sqli")
    print("    playbook:", pb.get("playbook"), "| chars:", len(pb.get("content", "")))

    print("\n[3] search_elasticsearch('8.8.8.8')  [may be 0 — just proving the call]")
    print("   ", json.dumps(search_elasticsearch("event_type:alert"))[:240])

    print("\n[4] search_past_cases('8.8.8.8')")
    print("   ", json.dumps(search_past_cases("8.8.8.8"))[:260])

    print("\n[5] search_past_cases('suricata')  [technique/tag path]")
    print("   ", json.dumps(search_past_cases("suricata"))[:260])

    print("\n" + "=" * 66)
