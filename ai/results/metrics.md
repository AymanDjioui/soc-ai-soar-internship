# SOC Pipeline Metrics (E-5)

Measured 2026-08-13 from live data: Elasticsearch (`suricata-alerts-*`), TheHive
`/api/v1`, and the orchestrator audit log (`~/soar/soar_audit.jsonl`, 1327 entries
across all runs to date). Every number here is derived from real recorded timestamps
and counts, not estimated. Methodology and caveats are stated per metric so the
report can defend each figure under questioning.

---

## 1. Detection-layer noise reduction (the headline figure)

Effect of the 2026-08-12/13 Suricata suppression work (STUN SIDs 2016149/2016150,
SSDP 2019102, LOCAL portscan 9000001) on the true alert stream (`event_type:alert`,
excludes flow records):

| Day | Suricata alerts/day | Targeted-noise share | Signal (non-noise) |
|---|---|---|---|
| 2026-08-11 (before) | **21,361** | **99.1%** | 196 |
| 2026-08-12 (during rollout) | 9,306 | 97.3% | 253 |
| 2026-08-13 (after) | **105** | **0.0%** | 105 |

**~99.5% reduction in daily alert volume**, and the four targeted false-positive
sources went from 99.1% of all alerts to fully eliminated. Post-suppression, the top
remaining signatures are genuine web-attack patterns (ET WEB_SERVER `/etc/passwd` in
URI, XSS script-tag in URI, curl/Go-client crawls against Juice Shop) — i.e. the
stream is now signal, not noise.

Caveat / honesty note: the 21k/day figure is dominated by Tailscale STUN keepalive,
which is Suricata severity 3 and therefore never reached TheHive (only sev≤2 is
forwarded). So this metric measures **SIEM/dashboard load**, which STUN genuinely
flooded, not the analyst queue. The analyst-facing figure is metric 2.

## 2. Analyst-queue reduction (TheHive)

The historical TheHive backlog, cleaned 2026-08-13 (SSDP + both portscan rules,
marked `Ignored`/`FalsePositive`, reversibly):

| | Before | After |
|---|---|---|
| Unprocessed ("New") alerts | **246** | **74** |

**~70% reduction** in the queue an analyst (or the orchestrator) has to work through,
and the sources are now suppressed so it does not refill.

## 3. Full autonomous response time — MTTR (alert → firewall block)

End-to-end, fully unattended, measured from `alert_received` to `containment_executed`
in the audit log (n=4 real containment executions across all sessions, incl. the C-1
Cobalt Strike capture):

| | value |
|---|---|
| Median | **61.0 s** |
| Mean | 59.5 s |
| Range | 42.7 – 73.2 s |

So: from an alert existing to the attacker IP being blocked on pfSense, with zero human
interaction, is **about one minute**. (Executions only ever occur on a genuine
malicious verdict that passes the guard, so all four are valid; the enrichment bug
fixed 2026-08-13 caused false *benign* verdicts, never false executions.)

## 4. Per-phase pipeline latency (warm GPU)

From the audit log, per-stage medians (n as noted, outliers >2min from cold starts /
Cortex API stalls excluded):

| Phase | Median | Mean | n |
|---|---|---|---|
| AI triage (alert → triage verdict) | **3.0 s** | 3.5 s | 238 |
| Case promotion (triage → case) | 0.6 s | 0.7 s | 186 |
| Cortex enrichment (case → reports) | **17.2 s** | 23.8 s | 186 |
| AI final verdict (enrichment → verdict) | **3.4 s** | 3.6 s | 115 |

The two LLM calls (triage + verdict) together are ~6.4 s; the dominant cost is Cortex
enrichment (external VirusTotal/AbuseIPDB/OTX API round-trips), not the AI.

## 5. AI triage behaviour (workload shaping, n=238)

| Outcome | Count | Share |
|---|---|---|
| Promoted to case (worth enriching) | 186 | **78%** |
| Auto-dismissed as false positive at triage | 52 | **22%** |

Alert-to-case ratio ≈ **0.78**. The AI filters roughly a fifth of alerts out at the
cheap first stage (one 3 s LLM call, no Cortex spend) before committing to full
enrichment.

## 6. Containment posture (guard conservatism)

Across all runs, of every alert that reached a decision point:

| Decision | Count |
|---|---|
| Containment executed | 4 |
| Containment **refused** by guard | 54 |
| Dry-run (would-block, not armed) | 2 |

The deterministic guard **refuses far more often than it acts** — the correct posture
for an autonomous system: it blocks only genuine external threats and declines
everything internal/protected/low-confidence. This is the quantitative backing for the
C-2 "correct refusal" claim.

## 7. Model inference: GPU vs CPU (from the benchmark)

From `deployment-latency.md` (kept here for the consolidated metrics view):

| | AWS EC2 CPU | GCP NVIDIA L4 GPU |
|---|---|---|
| Warm triage | 177.6 s | **2.5 s** (**71× faster**) |
| Cold start (first call after boot) | — | 37.7 s |

This is why the pipeline is usable at all: 177 s/alert on CPU makes autonomous triage
impractical; 2.5 s makes it real-time.

---

## Not reported, and why (honesty)

- **MTTD (attack → detection latency)**: not cleanly measurable. Suricata detection is
  effectively real-time (the signature fires on the triggering packet), but the
  Suricata→Elasticsearch ingestion-latency calculation is contaminated by a known
  timezone/clock issue (Suricata logs local `+0100`, Elasticsearch stores UTC), which
  produces nonsense deltas. Rather than report a bad number, this is flagged as a
  measurement limitation (see also the clock-drift item in `FINAL-ROADMAP.md` R-8).
- **Post-enrichment verdict accuracy (malicious vs benign breakdown)**: the audit log
  shows 59 malicious / 56 benign, but this spans the period before the 2026-08-13
  taxonomy-extraction fix, when verdicts ran on silently-empty evidence and defaulted
  to benign. The raw ratio is therefore not a valid accuracy measure and is
  deliberately not presented as one. Verdict *correctness* is instead evidenced by the
  controlled C-1 (malicious, acted) and C-2 (benign + guarded-refusal) captures.
