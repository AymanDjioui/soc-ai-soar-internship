# Chapter 9 — Toward Autonomous Tier-1: What We Automated, and What Must Not Be

> Draft, 2026-08-13. This is the project's central chapter. It argues the thesis of the
> whole work: not that we automated a SOC, but that we determined *which* Tier-1
> decision may responsibly be automated, built it under code-enforced guardrails, and
> proved the boundary in both directions — the system acting on a real threat, and the
> system correctly refusing to act on our own infrastructure.

## 9.1 The claim, stated narrowly on purpose

It would be easy, and wrong, to claim "we built a SOC that detects and blocks attacks
automatically." That claim is unbounded and the first question in a defense dismantles
it. What we actually built is narrower and more defensible:

> A locally-hosted LLM performs the Tier-1 triage *judgment* — deciding what an alert
> is — and a separate, deterministic policy layer decides whether any containment may
> follow. The model is never asked whether to block. That single architectural split is
> the safety argument of the entire project.

The rest of this chapter substantiates that claim: the incident that motivated the
design, the architecture that enforces it, the two captured proofs (an autonomous block
and a correct refusal), the guardrail model, and an honest statement of the readiness
criteria we did *not* have the observation window to meet.

## 9.2 The motivating incident: why naive autonomy is dangerous

Early in the project, before any guardrails existed, the detection layer produced a
high volume of "SSDP Amplification Scan" alerts. On inspection these were benign: a
Windows host on our own LAN performing routine UPnP device discovery (`M-SEARCH
ssdp:discover` broadcasts to `239.255.255.250:1900`), which an over-aggressive
Emerging Threats signature flags as a possible denial-of-service precursor.

The lesson was concrete and dated: **a naive "detect, then block" automation would have
blocked one of our own internal hosts**, causing a self-inflicted outage, on the
strength of a threat-intel rule firing on normal traffic. This is not a hypothetical.
It is the reason the containment decision was removed from the model entirely and given
to deterministic code that refuses to act on internal address space no matter how
confident the verdict. Everything in the guardrail model (§9.5) traces back to this
incident.

## 9.3 The architecture: separating "what is this" from "should I act"

The orchestrator (`soar/e2e_soc_orchestrator.py`) is a Python service that polls
TheHive for new alerts and runs each through four phases:

1. **Triage (LLM).** The raw alert is sent to a locally-hosted `mistral:7b` model
   (NVIDIA L4 GPU) with a few-shot, enum-constrained prompt. The model returns a
   structured verdict: severity, whether it looks like a false positive, a confidence
   value, and a MITRE technique drawn from a closed enum. Median latency: **3.0 s**.
   Low-value alerts are dismissed here (≈22% of all alerts) before any expensive
   enrichment.

2. **Enrichment (Cortex).** Promoted alerts become cases; each IP observable is
   enriched through Cortex analyzers (VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus).
   Median latency: **17.2 s** — the dominant cost in the pipeline, and it is external
   threat-intel API time, not the AI.

3. **Verdict (LLM).** Cortex's distilled taxonomy tags (e.g. `VT:GetReport=8
   resolution(s)`, `AbuseIPDB:Score=0`) are sent back to the model for a final
   assessment: malicious, benign, or inconclusive, with cited evidence. Median latency:
   **3.4 s**.

4. **Containment (deterministic, gated).** Only if the verdict is `malicious` is
   containment *attempted*, and even then the action must pass a deterministic
   pre-flight check (§9.5) before a Cortex responder is allowed to block the IP on
   pfSense.

The critical property: **at no point is the LLM asked "should I block this?"** It is
asked "what is this?" The block decision lives entirely in phase 4's deterministic
guard. A wrong or manipulated model output cannot, by construction, cause an
unauthorized firewall change — it can at most cause an alert to be mis-triaged, which a
human can review.

## 9.4 Proof 1 — the autonomous block (C-1)

To prove the loop end-to-end we needed an alert whose observable the threat feeds would
genuinely flag as malicious. The lab produces no real malicious external traffic, so we
injected a synthetic alert — labelled as such throughout, per our evidence-integrity
rule — carrying a **real, currently-active Command-and-Control IP**: a Cobalt Strike C2
server (`68.64.183.127`) sourced from abuse.ch ThreatFox at 100% confidence, first seen
roughly twenty minutes before the test.

The pipeline then ran with **zero human interaction**:

| Phase | Result |
|---|---|
| Triage | not a false positive, confidence 1.00, MITRE T1071.001 |
| Enrichment | VirusTotal, AbuseIPDB, URLhaus queried; VT returned real detections (`2/91` engines, 8 malicious DNS resolutions) |
| Verdict | **`malicious`, confidence 0.90**, citing the VirusTotal evidence |
| Guard | all checks passed |
| Containment | Cortex `PfSense_Blocker` responder executed |

Crucially, we did **not** trust the application's own success message — an earlier
version of this project had a bug where the audit log claimed a block had succeeded
while Cortex had actually rejected the job. We verified the block *independently at the
firewall*: `pfctl -t EasyRuleBlockHostsWAN -T show` on pfSense confirmed
`68.64.183.127` genuinely present in the block table. Full elapsed time from alert to
confirmed block: **~50 seconds**, consistent with the measured median MTTR of 61 s
(§9.7).

We also confirmed the result was *stable*, not a lucky single run — the earlier C-1
attempt had failed precisely because a stale threat-intel IP produced verdicts that
flip-flopped between runs. This IP produced a `malicious` verdict on three independent
dry runs (confidence 0.80, 0.89, 0.90) before the armed run, because the evidence it
rested on (documented malicious DNS resolutions) is durable, not a single volatile
engine flag.

## 9.5 The guardrail model

The deterministic guard (`containment_allowed()`) is veto-only: it can stop a
containment action, never initiate one. Every refusal is written to an audit log. In
order, it checks:

1. **Kill switch.** If a sentinel file exists on the host, all containment is halted
   immediately, regardless of verdict. This is the human emergency stop — one file,
   no code change, no service restart. We verified it works: with the kill switch
   active, a confidently-`malicious` verdict was correctly refused
   (`CONTAINMENT REFUSED — KILL SWITCH ACTIVE`).
2. **Confidence bound and floor.** The confidence value is re-validated in code (the
   schema enforces the type but only best-effort the range), and must meet a 0.75
   threshold. Below it, the alert is escalated to a human rather than actioned.
3. **Policy guard — protected address space.** The action target must not be RFC1918
   private space, must not be in the Tailscale CGNAT range (`100.64.0.0/10`, our own
   administrative mesh), and must not be an explicitly listed protected asset (the ELK
   server, pfSense, TheHive/Cortex, the GPU host). This is the direct descendant of the
   SSDP incident.
4. **Rate limit.** No more than five blocks per hour, as a circuit-breaker against
   runaway automation. (Notably, Cortex itself imposes no rate limit — this code is the
   only rate limit in the entire system.)

## 9.6 Proof 2 — the correct refusal (C-2)

A system that blocks whatever it thinks is malicious is dangerous. Proving it knows
*not* to act is worth as much as proving it can. This required care, because public
threat-intel has no data on our own private addresses — a live run against an internal
IP can only ever return `benign`, which never reaches the guard. So we proved it in two
parts:

**Part 1 — live pipeline against our own infrastructure.** We injected an alert
describing beaconing-shaped traffic from our ELK server's own Tailscale IP
(`100.99.54.59`). The result is itself informative: triage read the described pattern
as `medium` severity and *not* a false positive — an appropriately cautious first read —
but enrichment then checked the real IP against VirusTotal (0/91) and AbuseIPDB (score
0) and correctly overrode to `benign`, explicitly stating *"the two phases disagree …
the enrichment assessment is based on more evidence and takes precedence."* No
containment was attempted. This demonstrates the system does not false-positive on its
own assets, and that the two-phase design resolves disagreement in favour of evidence.

**Part 2 — direct guard test.** To exercise the guard's *override* behaviour (which
Part 1 never reaches, because there is nothing to override), we fed the real
`containment_allowed()` function a manufactured high-confidence `malicious` verdict
against the same protected IP — the same technique used to validate the kill switch.
Results:

| Target | Confidence | Outcome |
|---|---|---|
| `100.99.54.59` (explicitly protected asset) | 0.95 | **Refused** — "explicitly protected lab asset" |
| `100.101.27.63` (ordinary lab host, *not* on the protected list) | 0.92 | **Refused** — "Tailscale CGNAT range" |
| `68.64.183.127` (the real external C2 from C-1) | 0.92 | **Allowed** — "all guardrails passed" |

The second row matters most: the protection is not a hand-maintained IP allowlist — the
general CGNAT/RFC1918 range check catches any internal address, including ones nobody
remembered to list. The third row proves the guard is not merely conservative: at the
same confidence, it correctly *allows* action against a genuine external threat. We
confirmed via `pfctl` that pfSense was untouched throughout.

## 9.7 What it costs, measured

All figures are from real recorded timestamps (audit log, Elasticsearch), not
estimates. Full methodology in `ai/results/metrics.md`.

| Metric | Value |
|---|---|
| Full autonomous response (alert → confirmed firewall block) | **~61 s median** (range 43–73 s) |
| AI triage latency (warm) | 3.0 s |
| Cortex enrichment | 17.2 s (the bottleneck; external APIs, not the model) |
| AI final verdict | 3.4 s |
| Model inference, GPU vs CPU | 2.5 s vs 177.6 s — **71× faster** |

The GPU figure is not a vanity metric: at 177 s per alert on CPU, autonomous triage is
impractical; at 2.5 s it is real-time. The hosting decision (a dedicated GPU) is what
makes the whole approach viable, and is documented as such.

## 9.8 Readiness criteria — what we did *not* do, and why that is the honest position

We have proven the mechanism works and the guardrails hold. We have **not** run it as a
standing autonomous service against live traffic, and the report should say so plainly.
The systemd deployment runs deliberately in dry-run mode: it triages, enriches, and
comments on every alert, but never touches the firewall. Arming it fully is a one-off,
targeted, human-initiated action.

Before autonomy could responsibly be widened, the following would have to be *measured*,
not assumed:

- **False-positive and true-positive rates over a real observation window.** We reduced
  detection noise by ~99% (§ metrics) but have not yet run long enough post-tuning to
  quantify the residual FP rate on genuine alerts.
- **Coverage maturity** (Chapter's coverage matrix): several tactics are blind or
  partial (no EDR, no email/identity telemetry). Autonomy is only as safe as the
  detection feeding it.
- **Rollback and blast-radius drills.** The kill switch and the `pfctl` delete are
  proven individually; a full "bad block, detect, roll back, learn" cycle has not been
  rehearsed.

We did not have the observation window to meet these criteria, and we state that as a
finding rather than hide it. The intellectual contribution of this project is not "we
automated everything" — it is "we determined precisely where autonomy must stop, built
the boundary in code, and proved it in both directions." That claim survives
questioning. The other one would not.
