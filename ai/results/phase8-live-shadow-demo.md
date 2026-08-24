# Phase 8E — live shadow-mode demonstration (real data, zero mutations)

**Date**: 2026-08-24. **Source commit**: `81fffb31d40eff9eb84cf5f431bb1f21fba71136`
("Enforce strict read-only shadow mode", the Phase 8D.1 audit fix). **Deployed
release**: `~/soc-ai-soar/releases/81fffb3/` on `ollama-l4-server-spot`.

## What this proves

One real TheHive alert was run through the actual, final per-alert entry
point (`agent_orchestrator.main() -> process_alert_agent()`), using **real**
evidence at every stage — not mocks, not a benchmark harness — while the
service stayed in shadow mode throughout. The systemd service itself was
never started; this was a manual one-shot invocation
(`SOAR_ALERT_ID=~204828832`), since `main()` has no queue-polling path at
all — it processes exactly the one alert named or does nothing.

## Credentials used (least-privileged, demo-scoped)

- TheHive: `soar-shadow-demo@thehive.local`, `devoteam-soc` org, **Read-Only**
  profile.
- Elasticsearch: `soar_shadow_demo`, role `soar_shadow_demo_reader` —
  `read` + `view_index_metadata` on `suricata-alerts-*` only.
- Stored at `/etc/soc-ai-soar/shadow.env`, `root:root`, mode `600`. No
  Cortex, mailer, L2-assignment, or pfSense credential was ever placed in
  this file.

## Selected alert

`~204828832` — **"Port Scan Detected by PfSense"**, severity 2, source
`elastalert2` (a genuine automated-pipeline detection, not synthetic/demo
fixture data), tags `MITRE:T1046` / `pfsense` / `port-scan` /
`reconnaissance`, 1 IP observable. Already linked to a pre-existing case
(`~327725240`) from earlier testing — untouched by this run.

## Real evidence sources actually exercised

| Source | Used? | Evidence |
|---|---|---|
| TheHive alert + observables | ✅ | Alert fetched, observable IP extracted |
| Elasticsearch / Suricata | ✅ | `search_elasticsearch` on the alert's own source IP returned 1 real matching event |
| Local RAG / past-case history | ✅ | `search_past_cases` on the same IP returned "mixed/other history" |
| Mistral 7B, localhost Ollama | ✅ | Real inference, 100% GPU utilization observed |
| MITRE playbooks | Available, not invoked this run | The model didn't request one for this alert type |

## Tool trace

1. `search_elasticsearch(<source IP>)` → 1 matching event
2. `search_elasticsearch(<source IP>)` → skipped, duplicate call
3. `search_past_cases(<source IP>)` → mixed/other history
4. `search_elasticsearch(<source IP>)` → skipped, duplicate call
5. **Repeated-call safety cutoff fired** → forced conclusion (a second live,
   real-data confirmation of this specific anti-flailing mechanism, first
   proven in `test_shadow_mode.py`)

## Verdict

**MALICIOUS**, confidence **0.8**, severity **medium**, technique **T1046**
(reconnaissance). Disposition: **L2 — escalate**, reason: *"malicious but
the guard refused containment: KILL SWITCH ACTIVE"* — the kill switch was
live and load-bearing in this exact run, not a theoretical control.

## Performance

- Total latency: **15.46 s** (5 LLM round-trips).
- GPU: NVIDIA L4, peak **100% utilization**, **4959 MiB** VRAM — genuine
  GPU-resident inference.

## Zero-mutation proof

Before/after comparison across 14 fields (status, assignee, case linkage,
tags, observable fingerprints, description fingerprint, case comment count,
case action/Cortex-job count on the linked case): **`fields_changed: {}`
— every field identical.** No case created, no comment posted, no
assignment, no email/responder, no Cortex analyzer job, no containment, no
pfSense change. The systemd service was never started, remained
`disabled`/`inactive` throughout (`MainPID=0`), and the kill switch file's
mtime was unchanged before and after.

## Sanitized audit trail

```
agent_alert_received     alert_id=~204828832
agent_shadow_verdict      alert_id=~204828832
agent_shadow_disposition  alert_id=~204828832
```

No case-created, comment, assignment, or mailer event appears anywhere in
the audit log for this run.

## Limitations

- pfSense state was not independently re-verified (no key-based SSH access
  to that host this session) — not required here since containment was
  never attempted and the guard's refusal is directly visible in the run's
  own output.
- Single alert, single run — demonstrates the pipeline works end-to-end on
  real data and stays read-only. It is not an accuracy benchmark; see
  `ai/results/model-benchmark.md` and `agent-benchmark.md` for those.
