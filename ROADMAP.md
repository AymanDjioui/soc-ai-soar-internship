# Roadmap — Final Phase

> ⚠️ **SUPERSEDED for task planning — see [`FINAL-ROADMAP.md`](FINAL-ROADMAP.md)**
> (created 2026-08-04) for the current step-by-step MVP plan with owners and dates.
> This document is retained for its background rationale, feasibility analysis and
> standing principles, which remain accurate and are referenced by the final plan.

**Project:** SOAR and AI for Detection Improvement in the SOC (Devoteam internship)
**Rewritten:** 2026-08-01 · **Deadline:** 2026-08-31 · **~30 calendar days left**
Previous version archived at `notes/archive-roadmap-2026-07-20.md`.

---

## 0. Read this before planning anything

### 0.1 The real time budget

30 calendar days is not 30 days of building. Subtract honestly:

| Item | Days |
|---|---|
| Report writing (12 chapters, evidence assembly) | 8 |
| Demo dry-runs ×2 + fixing what they break | 3 |
| Buffer before 08-31 (never demo on deadline day) | 3 |
| **Available for build work** | **~16** |

And of those 16, budget **30–40% for firefighting**. That is not pessimism — it is the
measured rate across 12 logged sessions. Every single session in `notes/` hit at least
one multi-hour unplanned incident: two pfSense lockouts requiring console reboots, Redis
silently dead twice after reboot (killing *all* Suricata alerting both times), a 4-day
silent Juice Shop log outage, three separate VM clock-drift incidents, a platform-wide
duplicate-event bug, a stale-swap-file edit collision.

**Realistic build capacity: ~10–11 effective days.** Plan for that number, not 30.

### 0.2 The single most important scoping decision

The goal as stated — *"detect all known attacks, respond to all of them, zero human
intervention, no SOC L1"* — cannot be built **and evidenced** in 10 effective days. Not
because the idea is wrong, but because:

1. **"All known attacks"** is unbounded. MITRE ATT&CK Enterprise has ~200 techniques and
   ~700 sub-techniques. We have ~16 validated. No team builds and validates 200 in a month.
2. **"Zero human intervention" is a claim that requires *measurement*, not a working
   demo.** To defend removing the analyst you need false-positive/true-positive rates over
   time. We have zero days of that data. A workflow that runs autonomously once in a demo
   is not evidence that it is safe to run unattended.
3. **We already have hard proof of why unguarded autonomy is dangerous** — see 0.3.

**The winning move is a reframe, not a retreat.** Do not claim "we automated everything."
Claim: *"we built and measured a working autonomous L1 loop for a defined alert class,
and produced a coverage + readiness assessment showing exactly what can and cannot yet
be safely delegated to it."* That is a stronger, more senior deliverable, and it is
defensible under questioning. Overclaiming is the one thing that can actually sink the
defense.

### 0.3 The empirical argument against naive full autonomy (use this in the report)

On 2026-07-28 (`notes/12.md`), immediately after the ElastAlert→TheHive bridge was
repaired, a benign Windows SSDP/UPnP discovery broadcast
(`192.168.10.30` → `192.168.10.2`) began matching `ET DOS Possible SSDP Amplification
Scan in Progress` and creating a **new TheHive case every ~5 minutes, indefinitely**.

Had a naive "AI decides → auto-block source IP" loop been wired up with no guardrails,
it would have auto-blocked `192.168.10.30` — **our own internal Windows host** — for
doing something completely normal. Self-inflicted outage, caused by automation working
exactly as designed.

This is not a hypothetical risk sourced from a blog post. It is a real event in our own
lab, found by us, with a timestamp. It is the single best justification in the whole
project for **gated** autonomy over blind autonomy, and it should be a named subsection
of the report.

---

## 1. Where the project actually stands (verified against notes/1–12)

### 1.1 Built and validated ✅

**Collection — 5 live sources**
| Source | Path | Index |
|---|---|---|
| pfSense filterlog | syslog UDP 5514 | `soc-logs-*` |
| Suricata WAN `em0` + DMZ `em2` + LAN `em1` | Redis 6379 → Logstash | `suricata-alerts-*` |
| Juice Shop nginx JSON access logs | rsyslog → syslog-ng relay `172.16.0.2:5517` | `juiceshop-docker-*` |
| Linux LAN host `192.168.10.20` | syslog UDP 5518 | `linux-lan-logs-*` |
| Windows LAN host `192.168.10.30` (Winlogbeat + Sysmon) | Beats 5044 | `windows-logs-*` |

**Detection** — 13 ElastAlert2 rules live (Suricata severity, pfSense portscan, DMZ→LAN
breakout, Juice Shop XSS/SQLi/LFI, Linux SSH brute-force + root login, Windows
brute-force/new-user/admin-group/new-service/PowerShell). GeoIP enrichment + internal-IP
labelling. 5 Kibana dashboards (Firewall Overview, IDS Detections, Juice Shop, Linux LAN,
Windows LAN).

**~16 attack classes validated end-to-end with live evidence:**
- *Network/IDS (4)*: port scan, XSS, SQLi (8 distinct signatures from one sqlmap run),
  known-bad-traffic baseline
- *App-layer (3)*: login brute force, **SQLi auth bypass → real admin JWT, full account
  takeover**, IDOR (cross-user data access with the stolen token)
- *Linux (3)*: SSH brute force, `su` privilege escalation, cron persistence
- *Windows (6)*: registry Run-key persistence, C2 network connection, credential access
  (`reg save HKLM\SAM` — not blocked by Defender), encoded PowerShell (defeated by
  script-block logging), backdoor account + admin group, scheduled-task persistence
- *Documented negative result (1)*: path traversal normalized by nginx — kept on purpose

**SOAR (Badr, working)** — TheHive 5.7.1 + Cortex 4.0.1 on AWS; 4 analyzers (VirusTotal,
AbuseIPDB, AlienVault OTX, URLhaus); custom `PfSense_Blocker` Bash responder → Flask
webhook → SSH → `easyrule block wan <ip>`. Proven closed loop.

### 1.2 Not started ❌

**The entire AI layer.** Ollama not installed. Shuffle not installed. No LLM has ever
been shown a single alert from this environment. ROADMAP Task 6 is at 0%.

### 1.3 Open debt carried into this phase (from notes/12.md + earlier)

| # | Item | Risk if ignored |
|---|---|---|
| 1 | ~~SSDP false-positive flood~~ | **✅ Fixed 2026-08-04 (A1)** — see `notes/14.md` |
| 2 | **No pipeline monitoring anywhere** | A 4-day Juice Shop outage went unnoticed; a 7-day WAN+DMZ+LAN outage (Redis) went unnoticed **as recently as this session**. Highest risk to the final demo — see A2 |
| 3 | **Redis on pfSense does not survive reboot** (**3 occurrences now** — `notes/9.md`, `notes/12.md`, `notes/14.md`) | Kills *all* Suricata alerting silently; the 3rd occurrence lasted a full week undetected |
| 4 | **TheHive API keys + Kibana encryption keys exposed in `notes/`** | Cannot ship the report or publish the repo as-is |
| 5 | **Windows VM test artifacts never cleaned** (backdoor account, scheduled task, Run key, `sam.save`/`system.save`) | Contaminates later detection work; embarrassing in a live demo |
| 6 | **`configs/` mirror is stale** — 1 ElastAlert rule vs 13 live; missing 2026-07-28 Logstash changes | Report would document a config that no longer exists |
| 7 | **`demo/screenshots-2026-07-20/` referenced in the runbook but does not exist** | Demo runbook cites missing evidence |
| 8 | Dead `socat_juiceshop.sh` still enabled in `rc.conf.local` (syslog-ng wins the port) | Confusing leftover state |
| 9 | DMZ VM clock drifts (no NTP path — DMZ has no egress by design) | Silent timestamp corruption, breaks correlation |
| 10 | Suricata WAN/DMZ rule categories never re-verified after `em1` silently lost its own | Same class of silent detection loss |
| 11 | "Top User Agents" panel polluted by non-HTTP noise; 1,089 legacy `app_log.*` docs | Cosmetic; low priority |

---

## 2. Feasibility split — blunt

### ✅ Tier 1 — Genuinely achievable and demonstrable by 08-31
- Ollama running locally, prompt validated by hand against **real** alert data
- One AI-triage workflow: TheHive case → LLM → structured JSON → labelled comment on the case
- **One fully autonomous, gated loop** for a narrow, well-chosen alert class (AI verdict
  gates an existing Cortex responder), with allowlist + confidence threshold + kill switch
- MITRE ATT&CK catalog of the ~16 already-validated techniques + honest coverage-gap matrix
- 2 multi-stage attack chains
- Master "SOC Overview" dashboard
- Pipeline watchdogs (the thing that protects the demo)
- Full report + 2 demo dry-runs

### ⚠️ Tier 2 — Partially reachable; scope down on contact
- Autonomous response across **2–3** alert classes (not "all")
- A *measured* FP/TP rate — realistically over days, not weeks. Report it as a
  short-window observation with explicit caveats, never as a stability claim
- Broadening detections toward more MITRE techniques — measured in single digits added,
  not dozens

### ❌ Tier 3 — Present as designed architecture / future work, do NOT claim as built
- "Detects and responds to **all** known attacks" — unbounded; replace with the coverage matrix
- **"Zero human intervention across the whole SOC"** — not evidenceable in 30 days.
  Present the *validated narrow loop* + the readiness criteria that would need to be met
  to widen it
- Elastic ML anomaly detection — **Platinum licence**, unavailable on our Basic licence
  (same class of constraint as the Kibana webhook connector already documented in notes/6.md)
- Fine-tuning a model on our own alert data
- Auto-isolate host / auto-disable account across all sources

### ⚠️ Hard resource constraint to check on day 1
The ELK VM is a 16 GB laptop already running Elasticsearch + Logstash + Kibana +
ElastAlert2. Adding **Ollama** (`llama3.1:8b` ≈ 5–6 GB resident for inference) **and**
Shuffle (multi-container Docker stack, ~2 GB) to the same host is a real risk of OOM —
which on this box would take down the SIEM itself.

**Mitigations, in order of preference:** (a) run a smaller model (`llama3.2:3b` /
`phi3:mini`) — quality is likely sufficient for structured triage summaries; (b) put
Ollama on the laptop host rather than inside the ELK VM; (c) drop Shuffle entirely and
drive the workflow from a small Python service — **Shuffle is a convenience, not a
requirement**, and cutting it removes an entire unknown-platform learning curve from a
10-day budget. Decide this in Task B1, not later.

**✅ Resolved in B1 (2026-08-04):** this constraint was real and got worse than
predicted — running the LLM VM alongside the ELK VM *and* the browser (needed
continuously for Kibana/pfSense dashboards) saturated host swap and contributed to a
genuine host hang. Resolution was not "smaller model," it was **moving inference off
the laptop entirely** — `soc-llm-aws` on AWS EC2, reachable over Tailscale. Shuffle vs.
Python-service is still an open decision for B2.

---

## 3. Tasks

Ordered by dependency. Each has an evidence-backed definition of done. **Track A must
land before Track B** — automation built on an unmonitored, noisy pipeline amplifies
noise and will fail live.

### Track A — Stabilize the foundation (do first)

#### A1 — Kill the false-positive flood — ✅ DONE (2026-08-04)
Suppressed SID 2019102 (SSDP amplification) for `192.168.10.30` via pfSense's native
Suricata Suppress List — scoped to the one confirmed-benign host, genuine SSDP scans
from any other source still fully detected. **Live-verified with 3 injected test
bursts** (exact rule content reproduced via PowerShell `UdpClient` over WinRM), not
just assumed from the config save. Found a real gap in the process: the GUI's "Save"
does not restart the affected Suricata instance, so the first test still fired —
caught via `ps` (same PID/start-time before and after "Save"), fixed with a manual
interface restart, re-verified clean. Before: 543 historical alerts, 39 TheHive cases
from this one signature. Full writeup: `notes/14.md`.

#### A2 — Pipeline watchdogs (protects the demo more than anything else) ⚠️ **now the top priority**
ElastAlert "dead-man" rules: no `suricata-alerts-*` in N min → alert; same for
`juiceshop-docker-*`, `windows-logs-*`, `linux-lan-logs-*`. Plus make Redis survive a
pfSense reboot (enable at boot, or a cron liveness check — GUI/API, **never** a raw
`config.xml` edit).
**Done when:** each watchdog fires on a deliberately stopped source, and Redis survives a
real pfSense reboot. Screenshot both.

**Elevated priority (2026-08-04):** while live-verifying A1, discovered Redis on
pfSense had been down for a **full 7 days**, silently killing WAN+DMZ+LAN detection
entirely (last real event before the fix: `2026-07-28`). This is the **third**
occurrence of this exact failure mode across the project (see `notes/9.md`,
`notes/12.md`, `notes/14.md`) — each time found by accident, never by monitoring. This
is no longer a theoretical risk item; it is the empirically most damaging gap in the
whole platform and must not slip further.

#### A3 — Secrets rotation + config mirror refresh
Rotate the TheHive API keys exposed in `notes/8.md` and this session's logs, plus the
Kibana encryption keys. Re-pull `configs/` from live (13 rules, current `logstash.conf`).
Decide the publication policy for `configs/` (it holds live secrets).
**Done when:** old keys rejected; `configs/` matches live; report/appendix uses
`<PLACEHOLDER>` only.

#### A4 — Windows VM cleanup
Remove the backdoor account, scheduled task, Run key, `sam.save`/`system.save`.
**Done when:** each removal verified on-box; note kept that these were *test* artifacts.

### Track B — The AI/SOAR layer (the missing half)

#### B1 — Ollama up + prompt validated **by hand** — ✅ DONE (2026-08-04)
Benchmarked 5 models × 4 prompt/schema configs (56 inferences) against a 7-case golden
set built from real lab alerts (`notes/3,7,10,11,12.md`). **Decision: `mistral:7b`,
few-shot prompt, enum-constrained MITRE schema — 19/21 (90%).** Full evidence in
`ai/results/model-benchmark.md` and `ai/results/prompt-iteration-log.md`.

Real finding along the way: an early prompt version (with a `safe_to_auto_block` field
in the model's own schema) recommended auto-blocking our own internal host — reproduced
the exact ROADMAP §0.3 risk as a measured result, not just a stated concern. Fixed
architecturally, not by re-prompting: containment eligibility (`policy_guard()`) moved
out of the model entirely into deterministic code that can only veto, never approve.
This is now the template for B5's guardrail design.

**Deployment:** production inference runs on `soc-llm-aws` (AWS EC2 `m7i-flex.large`,
eu-north-1), joined to the Tailscale mesh as `soc-llm-aws` (`100.96.231.95`) — reachable
the same way as pfSense/TheHive/ELK, not exposed publicly (Ollama bound to
`0.0.0.0:11434`, but only the tailnet interface is actually reachable in practice; the
security group permits only admin-IP SSH). Start-per-session, not always-on — full
rationale including the local-vs-AWS reversal in `ai/results/deployment-latency.md`.
See `notes/13.md` for the full session writeup.

#### B2 — Orchestration layer up
Shuffle via Docker Compose **or** the Python-service fallback (§2). Reachability to
TheHive (AWS/Tailscale), Elasticsearch (local), Ollama (now on `soc-llm-aws`, reachable
over Tailscale from anywhere — including from AWS itself, which simplifies this step
versus the original local-Ollama assumption). Secrets in the tool's own store, never in
workflow fields.
**Done when:** an end-to-end manual run fetches one real TheHive case and returns a
model response.

#### B3 — AI triage workflow, human-in-the-loop
Trigger → fetch case + observables → fetch raw source event from Elasticsearch → call
Ollama with the B1 prompt → validate JSON → **post back as a comment prefixed
`🤖 AI Triage Draft —`**. Output: summary, severity, MITRE technique ID, recommended action.
**Done when:** comment lands correctly on ≥3 different real case types, visibly labelled
AI-generated. Screenshot each.

#### B4 — Autonomous ingest
Replace the manual trigger with a TheHive webhook (or a polling trigger if the webhook
proves awkward — both are supported; pick whichever is reliable fastest).
**Done when:** a fresh attack produces an AI comment with **no human action**; end-to-end
latency measured and recorded (attack → case → comment).

#### B5 — The gated autonomous L1 loop ⭐ (the centrepiece)
For **one** deliberately narrow alert class (recommendation: external-sourced
high-severity Suricata alert with a *public* source IP — the Juice Shop SQLi path is the
strongest story), let the AI verdict gate the existing `PfSense_Blocker` Cortex responder.

**Non-negotiable guardrails — these are the report's core contribution, not overhead:**
- Never act on RFC1918 / Tailscale CGNAT / gateway IPs (**this is precisely the SSDP
  lesson from §0.3**)
- Confidence threshold — below it, escalate to human instead of acting
- Rate limit (max N auto-blocks per hour)
- Every autonomous action written to an audit trail in the case
- A documented, tested kill switch

**Done when:** attack → detection → case → AI verdict → auto-block → attacker traffic
verifiably dropped, **zero human clicks**, full timeline captured; *and* a deliberate
benign/internal trigger is correctly **refused** by the guardrails. Both directions must
be evidenced — the refusal is as important as the success.

#### B6 — *(Stretch, only if B5 is fully solid)* second automated response action

### Track C — Coverage and evidence

#### C1 — MITRE ATT&CK catalog (start now, it is desk work and report backbone)
Table: technique ID → tactic → target → detected by (which layer/rule) → evidence
(screenshot/query) → status. Populate with the ~16 already-validated techniques.
**Done when:** every validated attack maps to a technique ID with a working evidence link.

#### C2 — Coverage-gap matrix (this replaces the "all attacks" claim)
Against MITRE Enterprise tactics: what we cover, what we partially cover, what we cannot
see at all and **why** (no EDR, no email/identity/cloud telemetry, DMZ has no egress, etc.).
**Done when:** an honest per-tactic matrix exists. This is a maturity assessment — a
genuinely senior artifact, and far more defensible than a coverage claim.

#### C3 — Multi-stage attack chains (2, not 5)
1. Recon → Juice Shop SQLi initial access → admin token theft → lateral movement attempt
   toward LAN → persistence on Linux host
2. Windows foothold → privilege escalation → credential dumping → lateral movement attempt
Document what was caught **at each stage**, and what was missed. Missed stages are
valuable report content.
**Done when:** both chains executed, per-stage detection table completed, evidence captured.

#### C4 — Master "SOC Overview" dashboard
Single pane across all 5 sources + case/response status.
**Done when:** saved, screenshotted, usable as the demo opening slide.

### Track D — Report and demo

#### D1 — Evidence capture freeze ⚠️ **schedule early, not last**
Work through `REPORT-PLAN.md` §3 capture list while the environment is healthy.
**Rationale from our own history:** the environment has broken in nearly every session,
and `demo/screenshots-2026-07-20/` — cited by the demo runbook — is *already missing*.
Evidence not captured while things work may be uncapturable later.
**Done when:** every item in the capture list exists on disk.

#### D2 — Write the report — see `REPORT-PLAN.md`
Write each chapter as its track completes. Do not leave writing to the final week.

#### D3 — Demo dry-run ×2, full end-to-end, **not later than 2026-08-24**
First run will break something — that is the point of doing it twice with room to fix.
**Done when:** two clean consecutive runs from the printed runbook, no improvisation.

---

## 4. Suggested sequencing

| Phase | Tasks | Notes |
|---|---|---|
| 1 | A1, A2, A3, A4 · C1 in parallel | Stabilize + start catalog (desk work) |
| 2 | **B1** · D1 begins | Prompt validation is the go/no-go gate for the whole AI thesis |
| 3 | B2, B3, B4 | Human-in-the-loop AI triage working |
| 4 | **B5** · C3 | The centrepiece + attack chains |
| 5 | C2, C4 · D2 | Coverage matrix, master dashboard, writing |
| 6 | **D3 by 08-24** · D2 finish | Dry-runs with real buffer |

**If time runs short, cut in this order:** B6 → C3 chain #2 → C4 → B5 widening.
**Never cut:** A2 (watchdogs), B1 (prompt validation), B5 core loop, D1 (evidence), D3 (dry-run).

---

## 5. Standing principles (carried forward — these came from real incidents)

- Verify with live evidence, never "should be working." Capture before/after.
- Document negative results — the failed path traversal, the refused auto-block, the
  missed attack-chain stages are all legitimate, credibility-building content.
- pfSense: GUI or its own config API. **Never raw `config.xml` edits** — two outages.
- Prefer application-layer fixes over new firewall rules where possible.
- Announce before editing shared VM configs — a live `nano` collision was caught by luck
  on 2026-07-28.
- Never write real keys into any file — `<PLACEHOLDER>` only.
- **AI output stays labelled and separate from anything that auto-executes.** Autonomous
  actions are gated by explicit guardrails, never by the model's free-text opinion alone.
