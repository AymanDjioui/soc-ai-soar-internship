# SOAR + AI Triage Orchestrator

End-to-end pipeline: **TheHive alert → AI triage → case → Cortex enrichment → AI verdict
→ policy guard → containment**, with the AI's reasoning written back onto the case.

Original pipeline architecture: **Badr**. Hardening, guardrails, and prompt integration:
**Ayman**. See `notes/13.md`, `notes/15.md` and `ai/results/` for the evidence behind the
design decisions.

---

## Running it

```bash
pip install thehive4py requests

export THEHIVE_API_KEY='<key>'          # never hardcode — rotate per ROADMAP A3

# Recommended first run: assess and log everything, execute nothing.
export SOAR_DRY_RUN=1
python3 e2e_soc_orchestrator.py
```

Once dry-run output looks correct, unset `SOAR_DRY_RUN` to arm containment.

| Variable | Default | Purpose |
|---|---|---|
| `THEHIVE_API_KEY` | — | **required** |
| `THEHIVE_URL` | `http://100.124.232.121:9000` | |
| `OLLAMA_BASE_URL` | `http://100.96.231.95:11434` | `soc-llm-aws` over Tailscale |
| `OLLAMA_MODEL` | `mistral:7b` | benchmark winner — `ai/results/model-benchmark.md` |
| `SOAR_MIN_CONFIDENCE` | `0.75` | below this → escalate to human, never act |
| `SOAR_MAX_BLOCKS_HOUR` | `5` | runaway-automation circuit breaker |
| `SOAR_DRY_RUN` | off | log containment decisions without executing |
| `SOAR_AUDIT_LOG` | `./soar_audit.jsonl` | every decision, append-only |
| `SOAR_KILL_SWITCH` | `./KILL_SWITCH` | file exists → containment disabled |

### Kill switch

The switch file and the audit log are resolved to **absolute** paths next to
`e2e_soc_orchestrator.py`, and both are printed in the startup banner. Use the path the
banner shows:

```bash
touch /path/from/banner/KILL_SWITCH    # containment halts immediately
rm    /path/from/banner/KILL_SWITCH    # re-arm
```

Triage and enrichment continue while the switch is active — only the *action* stops.

> These were relative paths until 2026-08-10. `touch KILL_SWITCH` from the wrong
> directory left containment **armed** while the operator believed it was disabled, and
> the rate limiter silently reset to zero because it reads the audit log. Verified fixed:
> the switch is now honoured no matter which directory the process runs from.

---

## Design principle: the model informs, code decides

The LLM is **never** asked whether an IP may be blocked. It produces an assessment
(verdict, severity, confidence, MITRE technique). `policy_guard()` — deterministic,
code-side, **veto-only** — decides whether that assessment may result in an action.

This is a direct response to a measured failure, not defensive over-engineering. During
prompt development (`ai/results/prompt-iteration-log.md`, v2), when the schema included a
`safe_to_auto_block` field, the model recommended **auto-blocking one of our own internal
Windows hosts** for emitting normal UPnP discovery traffic. Separately, **5 of the 7 cases
in the golden test set must never be auto-blocked**, because our own attack traffic
originates from the Tailscale range.

A guard can only ever **refuse**. It can never authorise.

### What the guard refuses

| Condition | Rationale |
|---|---|
| RFC1918 private | our own hosts — blocking is a self-inflicted outage |
| `100.64.0.0/10` Tailscale CGNAT | our own administrative access path |
| Explicit protected-asset list | pfSense, ELK, TheHive, the LLM host itself |
| loopback / link-local / multicast / reserved | never valid containment targets |
| non-IP data | request URIs and bodies are observables too — refuse, don't guess |
| confidence < `SOAR_MIN_CONFIDENCE` | uncertainty escalates to a human |
| rate limit exceeded | circuit breaker against runaway automation |
| kill switch present | manual override |

Verified against the real golden-set IPs — all 9 cases pass, including both Tailscale
addresses and the SSDP false-positive host.

---

## Changes from the original implementation

| # | Issue | Fix |
|---|---|---|
| 1 | **No guardrails** — LLM verdict went straight to the firewall | `policy_guard()` + confidence threshold + rate limit + kill switch, all audited |
| 2 | **Failed open** — the LLM error path returned `action: "promote"`, and the "safe default dismiss" branch was unreachable dead code | `call_llm()` returns `None` on failure; callers leave the alert for a human. No fabricated verdicts |
| 3 | **Wrong containment target** — a loop variable left `target_observable_id` pointing at whichever observable was iterated last (could be a request body) | `select_containment_target()` explicitly picks IP-typed observables |
| 4 | **`KeyError` crashes** — `format: "json"` guarantees parseable output, not correctly-shaped output | JSON **Schema** passed to `format` (constrained decoding) + required-key validation before use |
| 5 | **AI reasoning invisible** — verdicts only went to stdout | Labelled `🤖 AI Triage Draft` comment posted to the case, including refusals |
| 6 | **Weakest benchmarked config** — zero-shot, free-form technique field ≈ **62%** | Few-shot + enum-constrained schema ≈ **90%** on the same test set |
| 7 | **Hardcoded API key in source** | `THEHIVE_API_KEY` from environment |
| 8 | **No audit trail** | Append-only JSON-lines log of every decision |
| 9 | `mock_llm_*` names, dead `TARGET_ALERT_ID` | Renamed / removed |

---

## Audit log

Every decision is one JSON line in `soar_audit.jsonl`:

```
alert_received · triage_complete · triage_failed · alert_dismissed
case_created · enrichment_complete · verdict_complete · verdict_failed
containment_refused · containment_dry_run · containment_executed · containment_error
comment_posted · processing_error
```

Useful for the report — MTTD/MTTR and refusal rates come straight out of this file:

```bash
# every refusal, with its reason
jq -r 'select(.event=="containment_refused") | "\(.ts)  \(.target)  \(.reason)"' soar_audit.jsonl

# containment actions in the last hour (what the rate limiter counts)
jq -r 'select(.event=="containment_executed")' soar_audit.jsonl
```

---

## Demo value: the refusal is worth as much as the block

Two results should be captured for the report, not one:

1. **A successful autonomous block** — external attacker → detection → case → enrichment
   → verdict → guard passes → traffic verifiably dropped, zero human clicks.
2. **A correct refusal** — a Tailscale-sourced or internal-host alert reaching a
   `malicious` verdict, and the guard declining to act, with the reason recorded on the
   case and in the audit log.

The second demonstrates the system knows its own limits. In a viva that is the harder
thing to show, and the more convincing one.
