# FINAL ROADMAP — MVP to Finish

**Project:** SOAR and AI for Detection Improvement in the SOC — Devoteam internship
**Team:** Ayman (SIEM / detection / AI layer) · Badr (SOAR / TheHive / Cortex / network)
**Created:** 2026-08-04 · **Deadline:** 2026-08-31 · **27 days remaining**

> This is the definitive endgame plan. It supersedes the task list in `ROADMAP.md`
> (which remains useful for background rationale). Share this file directly with Badr.

---

## 0. Read this first — the strategic situation

**The project is already strong.** Verified as built and working:

- 5 telemetry sources feeding a SIEM (pfSense filterlog, Suricata ×3 interfaces, Juice Shop
  app logs, Linux host, Windows host with Sysmon)
- 13 ElastAlert2 detection rules, MITRE/OWASP-tagged, with structured observables
- ~16 attack techniques validated end-to-end, including a real account takeover and a
  Defender-bypassing credential dump
- Atomic Red Team validation of the Windows detection set
- TheHive + Cortex with 277 analyzers and a working `PfSense_Blocker` auto-block responder
- A self-hosted LLM (`mistral:7b` on `soc-llm-aws`) benchmarked across 5 models and
  4 prompt/schema configurations — 90% on a 7-case labelled golden set
- A full autonomous orchestration pipeline: alert → AI triage → case → enrichment →
  AI verdict → guarded containment

**The risk is not capability. The risk is not finishing the evidence.**

Most of what remains is consolidation, verification, and writing — not building. The
single biggest threat to the grade is running out of days with a working system that
nobody documented properly.

**Therefore: no new features from here. Everything below either proves what exists,
protects it from breaking, or writes it down.**

---

## 1. Definition of "done" — the MVP

The project is finished when these **six** things exist. Not more.

| # | Deliverable | Why it matters |
|---|---|---|
| 1 | **One successful autonomous loop** — external attack → detection → case → AI triage → enrichment → AI verdict → guard passes → attacker traffic verifiably blocked, **zero human clicks** | This is the project's thesis |
| 2 | **One correct refusal** — same pipeline reaching a `malicious` verdict on an internal/Tailscale source, and the guard **declining to act**, with the reason on the case and in the audit log | Proves judgment, not just automation. Worth as much as #1 |
| 3 | **Coverage matrix** — per MITRE tactic: covered / partial / blind, and **why** | Replaces the unprovable "detects all attacks" claim with an honest maturity assessment |
| 4 | **Measured metrics** — MTTD, MTTR, false-positive rate before/after tuning, alert-to-case ratio | Turns assertion into evidence |
| 5 | **Written report** — 12 chapters, evidence attached | The graded artifact |
| 6 | **Two clean demo dry-runs** | So demo day is a performance, not an experiment |

Anything not serving one of these six is **out of scope until they are done**.

---

## 2. Task register

Priority key: 🔴 **MVP-critical** (project fails without it) · 🟠 **Important** (materially
improves the grade) · 🟢 **Optional** (only if genuinely ahead)

### 🔴 BLOCKING — must happen in the first 48 hours

| ID | Task | Owner | Est. | Definition of done |
|---|---|---|---|---|
| **B-1** | **Rotate the exposed TheHive API key.** It is currently in `elastalert/config.yaml`, in `notes/8.md`, and hardcoded in the original orchestrator source. Generate a new key, send it to Ayman privately (**not** into any repo file), confirm the old one returns 401 | **Badr** | 30 min | Old key rejected; ElastAlert still delivers alerts; no key string anywhere in the repo |
| ~~**A-1**~~ | ~~**Pipeline watchdogs.**~~ ✅ **DONE 2026-08-06** — 5 flatline rules live (`configs/elk/elastalert/rules/watchdog_*.yaml`): pfSense, Suricata, Windows, Linux-LAN, Juice Shop. Windows sized from 7 days of measured cadence; `limit_execution` gates to lab hours; `realert` gives one alert per outage. Validated **both** directions — replayed against the real 2026-08-05 outage (179 / 239 matches) and confirmed silent while data flows (0 matches on 10 + 72 hits). See `notes/15.md` | **Ayman** | 4 h | ✅ Met. **Still outstanding:** make Redis survive a pfSense reboot (carried to A-1b) |
| **A-1b** | **Make Redis survive a pfSense reboot** (split out of A-1). Redis has died silently 3× and does not come back after reboot | **Ayman** | 1 h | Reboot pfSense; Redis comes up unaided and `suricata-alerts-*` resumes without manual steps |
| **A-2** | **Dry-run the hardened orchestrator** against real TheHive alerts (`SOAR_DRY_RUN=1`) | **Ayman** | 3 h | 🟡 **MOSTLY DONE 2026-08-06.** Hosted on `soc-llm-aws` (`~/soar`, venv). Full chain proven on case `~123113560`: triage → case → 6/6 Cortex jobs → verdict `MALICIOUS` 0.95 → **guard REFUSED** (Tailscale CGNAT) → comment posted → audit complete, 514s, no unhandled exception. **4 defects found and fixed** (see `notes/15.md`). **Remaining:** one clean pass over ≥3 alerts on the *final* corrected code |
| **A-2b** | **Backlog + bounded-run mode.** TheHive holds **206 New alerts**; `main()` would process every one at ~6–8 min each. Needs a max-alerts bound and/or a backlog-drain policy before running unattended | **Ayman** | 1 h | Orchestrator can be pointed at a live queue without committing to days of LLM time |
| **A-2c** | **Fix broken ElastAlert alert titles.** Windows rules emit unrendered templates (`New Service on {match[host.name]}`) and attach **no observables** — useless to an analyst, un-actionable by the orchestrator | **Ayman** | 1 h | Titles render real values; alerts carry host/IP observables |

> **Why A-1 was not optional:** on 2026-08-04 we found Redis had been dead for **7 days**,
> silently killing WAN+DMZ+LAN detection entirely. That is the **third** occurrence of the
> same failure (`notes/9.md`, `notes/12.md`, `notes/14.md`) — every time discovered by
> accident. If it happens during demo week undetected, the demo fails.
>
> **Vindicated immediately.** While building A-1 on 2026-08-06 we found a **fourth**
> silent outage — pfSense `syslogd` had stopped forwarding, so `soc-logs-*` had been
> empty for ~2 days. `filterlog` was running and still writing `/var/log/filter.log`
> locally, so the firewall looked perfectly healthy. Found by accident again
> (`notes/15.md`). Replaying `watchdog_pfsense_filterlog` over that window fires 179
> times — it would have caught it in 30 minutes instead of 2 days.

### 🔴 THE CENTREPIECE — week 2

| ID | Task | Owner | Est. | Definition of done |
|---|---|---|---|---|
| **C-1** | **Arm the orchestrator and capture the successful block.** Real external attack (Juice Shop SQLi path is the strongest story) → full autonomous chain → attacker traffic verifiably dropped | **Both** | 4 h | Screen recording or timestamped screenshot series: attack → alert → case → AI comment → block → pfSense alias table showing the IP → traffic verifiably dropped. **Zero human clicks between attack and block** |
| **C-2** | **Capture the correct refusal.** Trigger an alert from an internal or Tailscale source that reaches a `malicious` verdict, and show the guard refusing | **Ayman** | 2 h | Case comment showing `❌ REFUSED` with reason; matching `containment_refused` entry in `soar_audit.jsonl`; pfSense alias table confirming nothing was blocked |
| **C-3** | **Verify the Cortex responder actually blocks.** Confirm `easyrule block wan <ip>` lands in the alias table and drops traffic, invoked via the API path the orchestrator uses | **Badr** | 1 h | Before/after alias table + a failed connection attempt from the blocked source |

### 🟠 EVIDENCE & COVERAGE — week 2–3

| ID | Task | Owner | Est. | Definition of done |
|---|---|---|---|---|
| **E-1** | **MITRE ATT&CK catalog.** Consolidate the ~16 validated techniques into one table: technique → tactic → target → detection layer → rule → evidence link. Badr's report §9.1 and §10.1 tables are already ~70% of this | **Ayman** | 3 h | Every validated attack maps to a technique ID with a working evidence pointer |
| **E-2** | **ATT&CK Navigator heatmap.** Generate a layer JSON from E-1 and render the colour-coded matrix (green = validated, yellow = partial, grey = blind) | **Ayman** | 2 h | A single image showing detection posture at a glance — the report's headline figure and demo opening slide |
| **E-3** | **Coverage-gap matrix.** Per MITRE tactic: what we cover, partially cover, and cannot see at all, with the reason (no EDR, no email/identity/cloud telemetry, DMZ has no egress, etc.) | **Ayman** | 3 h | Honest per-tactic table. This is a maturity assessment, and it is *more* defensible than a coverage claim |
| **E-4** | **Two multi-stage attack chains.** Not five. (a) Recon → Juice Shop SQLi → admin token theft → lateral movement attempt toward LAN → persistence on Linux host. (b) Windows foothold → privesc → credential dumping → lateral movement attempt. Document what was caught **at each stage, including misses** | **Both** | 6 h | Per-stage detection table for both chains. Missed stages are valuable content — keep them |
| **E-5** | **Metrics harvest.** MTTD (attack → alert), MTTR (alert → case → containment), FP rate before/after the SSDP fix, alert-to-case ratio, AI triage latency. All timestamps already exist in Elasticsearch and `soar_audit.jsonl` | **Ayman** | 3 h | A metrics table with real numbers. The before/after FP table is one of the strongest single figures available |
| **E-6** | **Master "SOC Overview" dashboard.** Single pane across all 5 sources plus case/response status | **Ayman** | 3 h | Saved, screenshotted, usable as the demo opening view |
| **E-7** | **Windows test-artifact cleanup.** Remove the backdoor account + admin group membership, test scheduled task, registry Run key, `sam.save` / `system.save` | **Badr** | 1 h | Each removal verified on-box; noted as *test* artifacts in the report |
| **E-8** | **Missing figures.** `socsoar.drawio.png` and `validation-screenshot.png` are referenced in Badr's report but are **not in the repo**. The architecture diagram also predates the AI layer and the 5-source collection design | **Badr** | 3 h | Both committed; diagram updated to include `soc-llm-aws`, the orchestrator, and all 5 sources |
| **E-9** | **SOAR screenshots.** Currently zero exist: TheHive case list, a case with observables + Cortex enrichment report, a Cortex analyzer job result, `PfSense_Blocker` alias table before/after | **Badr** | 2 h | All five captured while the environment is healthy |

### 🟠 REPORT — week 3–4, written in parallel with the above

| ID | Task | Owner | Est. | Definition of done |
|---|---|---|---|---|
| **R-1** | **Fix report inconsistencies.** §9.1 says "13 rules", §11.3 says "12" (it is **13**). §11.2 says the LLM is Groq — the code uses local Ollama on `soc-llm-aws`; the Groq reference must go or be reframed as a rejected alternative. §11.3 says `hive_severity`; it is `severity:` inside `hive_alert_config` | **Badr** | 1 h | No contradictions between report text and live config |
| **R-2** | **Ch.7 SOAR layer** — TheHive/Cortex deployment, analyzer selection rationale, the `PfSense_Blocker` build (HOCON syntax, `case_artifact` typing, the Alpine-no-python3 rewrite, the undocumented `output.json` schema), and the Phase 6 catalog recovery. Strong debugging material | **Badr** | 1 day | Chapter drafted with figures |
| **R-3** | **Ch.3 network segmentation** — zone design, DMZ isolation rationale, and the §8 subnet-router failure → direct-Tailscale-on-endpoints decision | **Badr** | half day | Chapter drafted |
| **R-4** | **Ch.2 state of the art** — SOAR/AI benchmark tables, plus the licence constraints found (Kibana webhook connector is Gold-only, Elastic ML is Platinum-only) | **Both** | half day | Chapter drafted |
| **R-5** | **Ch.4–6 collection, detection, validation** — 5 sources, delivery-mechanism evolution (UDP → TCP → Redis), 13 rules, the ~16 validated attacks | **Ayman** | 2 days | Chapters drafted with figures from E-1…E-6 |
| **R-6** | **Ch.8 AI layer** — model benchmark (5 models × 4 configs, 56 inferences), prompt evolution v1→v4, deployment decision and its reversal under concurrent load | **Ayman** | 1 day | Chapter drafted; `ai/results/*.md` is already most of the raw material |
| **R-7** | **Ch.9 "Toward autonomous L1" ⭐** — the guarded loop, the refusal case, the guardrail model, and the readiness criteria that would need to be met before widening autonomy | **Ayman** | 1 day | **This is where the grade is won.** Must include the v2 measured incident where the model recommended blocking our own host |
| **R-8** | **Ch.10 engineering incidents** — the Redis outages, the `em1` empty-ruleset finding, the stale API key, clock drift, the overlay/NAT conflict, the GUI-save-without-restart finding. All already written up in `notes/` | **Ayman** | half day | Chapter drafted — this is largely assembly, not writing |
| **R-9** | **Ch.11–12 limitations + conclusion** — Redis unauthenticated tradeoff, no EDR/email/identity/cloud telemetry, Elastic ML unavailable, fine-tuning as future work, autonomy widening blocked on measurement | **Both** | half day | Chapter drafted |

### 🔴 DEMO — hard dates

| ID | Task | Owner | Est. | Definition of done |
|---|---|---|---|---|
| **D-1** | **Demo runbook.** Copy-paste commands, no improvisation. Extend `demo/attack-scenarios.md` with the autonomous-loop scenario | **Both** | 3 h | Printed runbook that a stranger could follow |
| **D-2** | **Dry-run #1 — not later than 2026-08-24** | **Both** | 3 h | Full end-to-end from the runbook. **It will break something — that is the point** |
| **D-3** | **Dry-run #2 — not later than 2026-08-26** | **Both** | 3 h | Two clean consecutive runs, zero improvisation |

### 🟢 OPTIONAL — only if genuinely ahead of schedule

| ID | Task | Value |
|---|---|---|
| O-1 | **Detection-as-Code** — the 13 rules into git with a README (ATT&CK mapping, FP notes, the attack command that proves each fires) | Real maturity signal, ~1 h |
| O-2 | **Local vs cloud LLM comparison** — run the same golden set through Groq (Badr's original path) and `mistral:7b`, same prompt/schema. A genuine data-sovereignty vs capability tradeoff chapter | Strong report addition |
| O-3 | RAG for MITRE mapping — retrieve real technique descriptions instead of relying on the enum | Fixes the weakest benchmark metric |
| O-4 | Third attack chain / more techniques | Diminishing returns |

---

## 3. Week-by-week sequence

### Week 1 — Aug 4–10 · *make it safe and prove it runs*
```
Badr    B-1 key rotation (day 1)  →  E-7 Windows cleanup  →  R-1 report fixes
                                  →  C-3 verify responder blocks
Ayman   A-1 watchdogs ✅ DONE Aug 6  →  A-2 orchestrator dry-run  →  A-1b Redis
                                     →  E-1 MITRE catalog
```
**Gate:** by Aug 10 the orchestrator must run clean in dry-run and the watchdogs must fire.
Watchdog half of the gate is met (A-1, Aug 6). TheHive is back up, so **A-2 is unblocked**
and is now the next task.

### Week 2 — Aug 11–17 · *the centrepiece*
```
Both    C-1 successful autonomous block  ⭐
        C-2 correct refusal              ⭐
        E-4 two attack chains
Ayman   E-5 metrics  ·  E-2 Navigator heatmap
Badr    E-8 diagram  ·  E-9 SOAR screenshots  ·  R-2 Ch.7 draft
```
**Gate:** by Aug 17, MVP items #1 and #2 are captured on disk as evidence.

### Week 3 — Aug 18–24 · *evidence complete, writing hard*
```
Ayman   E-3 coverage matrix  ·  E-6 master dashboard  ·  R-5, R-6, R-7
Badr    R-3, R-4  ·  finish E-8/E-9 if outstanding
Both    D-1 demo runbook  →  D-2 DRY-RUN #1 (by Aug 24)
```
**Gate:** Aug 24 dry-run happens even if the report is unfinished.

### Week 4 — Aug 25–31 · *polish and buffer*
```
Aug 25-26   Fix whatever dry-run #1 broke  →  D-3 DRY-RUN #2
Aug 27      Report final assembly, figures, proofread
Aug 28-31   BUFFER — do not schedule work here
```

---

## 4. Sync points — the only 5 times you must coordinate

| When | What | Blocks |
|---|---|---|
| **Day 1** | Badr → Ayman: rotated API key (B-1) | A-2, everything downstream |
| **~Day 4** | Badr confirms Cortex responder blocks via API (C-3) | C-1 |
| **~Day 7** | Both: infrastructure up and healthy for C-1 | The centrepiece |
| **~Day 11** | C-1 + C-2 evidence captured | Ch.9, the demo |
| **Aug 24** | Dry-run #1 together | Everything |

**Coordination rule (learned the hard way):** never edit the same remote config file
simultaneously — a live `nano` collision was caught by luck once (`notes/12.md`).
Announce before touching shared infrastructure.

---

## 5. If time runs short — cut in this order

```
1st to cut:   O-1 … O-4  (all optional items)
2nd:          E-4 chain #2  (keep one chain)
3rd:          E-6 master dashboard
4th:          E-2 Navigator heatmap
```

**Never cut, under any circumstances:**
- **A-1** watchdogs — a silent outage during demo week ends the project
- **B-1** key rotation — blocks submission
- **C-1 + C-2** the block and the refusal — this *is* the deliverable
- **E-5** metrics — turns claims into evidence
- **D-2/D-3** dry-runs — never demo untested

---

## 6. Demo-day script

| Segment | Who | Shows |
|---|---|---|
| 1. Architecture + segmentation | Badr | Updated diagram (E-8), 3 zones, Tailscale mesh |
| 2. Coverage posture | Ayman | ATT&CK Navigator heatmap (E-2) + coverage matrix (E-3) |
| 3. Detection layer | Ayman | Master SOC dashboard (E-6), 5 sources live |
| 4. Live attack | Ayman | Juice Shop SQLi from the runbook |
| 5. Case + enrichment | Badr | TheHive case, observables, Cortex analyzer reports |
| 6. **AI triage → autonomous block** ⭐ | Ayman | AI comment on the case → guard passes → pfSense blocks → traffic dropped |
| 7. **The refusal** ⭐ | Ayman | Internal-source alert → `malicious` verdict → guard **refuses** → audit log |
| 8. Metrics | Ayman | MTTD / MTTR / FP-rate before-and-after |
| 9. Limits + future work | Both | What we cannot see, and what widening autonomy would require |

**Segment 7 is the one that separates this project.** Most demos show something working.
Very few show a system correctly refusing to act, with a documented reason and an audit
trail — and can explain, from their own measured data, why that guardrail exists.

---

## 7. The framing to defend it

> *"We built a multi-layer SOC across five telemetry sources, validated sixteen attack
> techniques end-to-end, benchmarked five self-hosted LLMs on our own labelled incident
> set, and deployed one fully autonomous detection-to-containment loop under
> code-enforced guardrails. We also documented precisely where autonomy must stop —
> including a measured case where the model recommended blocking one of our own internal
> hosts. Widening autonomy beyond that boundary is blocked on measurement, not
> engineering."*

Every clause in that sentence is backed by evidence on disk. It survives follow-up
questions. **"We automated everything" does not** — and would be the one claim capable
of sinking an otherwise excellent project.

---

## 8. Reference documents

| Document | Contents |
|---|---|
| `ROADMAP.md` | Background rationale, feasibility analysis, standing principles |
| `TASK-SPLIT.md` | Earlier ownership split (superseded by §2 above) |
| `REPORT-PLAN.md` | 12-chapter structure + evidence mapping + capture list |
| `AI-LAYER-PLAN.md` | LLM concepts, model shortlist, deployment reasoning |
| `soar/README.md` | Orchestrator usage, guardrail design, changes from the original |
| `ai/results/model-benchmark.md` | 5 models × 4 configs, 56 inferences, 10 findings |
| `ai/results/prompt-iteration-log.md` | v1→v4 prompt evolution, the v2 safety incident |
| `ai/results/deployment-latency.md` | Local vs AWS, and the reversal under concurrent load |
| `notes/1.md` … `notes/14.md` | Full chronological engineering history |
