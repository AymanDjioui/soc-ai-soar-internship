# SOAR dry-run evidence — 2026-08-06

Audit trail from the first end-to-end `SOAR_DRY_RUN=1` execution of the hardened
orchestrator, captured on the **AWS CPU host** before migrating to GPU.

Host: `soc-llm-aws` — EC2 `m7i-flex.large`, 2 vCPU (~1 physical core), CPU-only
inference, `mistral:7b` Q4_K_M via Ollama.

## Files

| File | Contents |
|---|---|
| `soar_audit-2026-08-06-aws-cpu.jsonl` | 15 audit events across 3 real TheHive alerts |

## The result worth citing

Alert `~122888288` → case `~123113560` (Tailscale-sourced XSS against Juice Shop):

```
triage   182.4s  -> not false positive, high, confidence 0.85, T1190
promote  -> case ~123113560
enrich   -> 6/6 Cortex analyzer jobs Success
verdict  265.0s  -> MALICIOUS, confidence 0.95
guard    -> CONTAINMENT REFUSED (Tailscale CGNAT — our own admin path)
total    514.4s, zero unhandled exceptions
```

The model reached `malicious` at **0.95 confidence — above the 0.75 action
threshold** — and the deterministic `policy_guard()` refused anyway. This is the
"model informs, code decides" principle demonstrated on live data rather than on
a unit test.

## Latency baseline (CPU) — for the hardware comparison

| Call | Measured |
|---|---|
| triage (warm) | 177.6 s / 182.4 s / 185.0 s |
| verdict (larger prompt) | 265.0 s |
| full alert, end to end | **514.4 s** |

Ollama server-side breakdown for one triage:

```
prompt eval :  88.1s / 1125 tokens (12.77 tok/s)
generation  :  73.8s /  120 tokens ( 1.63 tok/s)
```

Compare against `../deployment-latency.md` (laptop vs EC2) and the GPU figures to
come — that gives a three-way comparison across identical model, prompt and
schema, with only the hardware varying.

## Known quality defect in this run

In case `~123113560` the model wrote:

> **Reason:** detected as malicious by multiple engines including MalwareURL,
> Phishtank, and Sucuri SiteCheck

while the evidence quoted directly beneath it in the same comment reads **clean**
for all three engines — and confidence was *raised* 0.85 → 0.95 on that basis.

The verdict is defensible for an XSS attempt; the stated reasoning is fabricated.
Kept deliberately as evidence for why containment authorisation is deterministic
and code-side. See `notes/15.md`.
