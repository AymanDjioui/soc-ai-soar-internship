# Task Split — Ayman / Badr — Final Phase

**Created 2026-08-04 · Deadline 2026-08-31 · 27 days**
Companion to `ROADMAP.md`. Purpose: run both tracks in parallel so neither person waits.

---

## The split principle

**Ayman owns the critical path.** B3 → B4 → B5 (the AI triage service, its autonomous
trigger, and the gated auto-response) is sequential and cannot be parallelised. It is
the project's core deliverable and it runs end-to-end on Ayman's side.

**Badr owns everything that would otherwise block that path, plus his own half of the
report.** His tasks are deliberately front-loaded: the things Ayman needs from him
must land in the first 2 days, after which Badr works fully independently.

**Rule from experience (notes/12.md):** never edit the same remote config file at the
same time. A live `nano` collision was caught by luck once. Announce before touching
shared infrastructure.

---

## 🔴 BADR — Blocking items (do these FIRST, days 1–2)

These four gate Ayman's work. Nothing else Badr does matters until they're done.

### B-1. Rotate the exposed API keys ⚠️ *blocks report submission*
The TheHive API keys and Kibana encryption keys are exposed in `notes/8.md` and in
session logs. They must be rotated before anything is submitted or shared.

- Generate a new TheHive API key for the `devoteam-soc` org
- Send it to Ayman over a private channel (**not** into any file in this repo)
- Confirm the old key is rejected

**Done when:** old key returns 401; new key works from ElastAlert.

### B-2. Confirm TheHive can call an outgoing webhook *blocks B4*
Ayman's triage service needs to be triggered when a case is created. TheHive 5.x
supports outgoing webhooks — confirm it's configurable in your instance and report
back which of these works:

- **Option A (preferred):** TheHive webhook → POSTs to a URL on case creation
- **Option B (fallback):** if webhooks are awkward, say so early — Ayman will poll
  TheHive's API instead. Both are acceptable; **knowing which one, early, is what matters.**

**Done when:** Ayman has a definitive yes/no on outgoing webhooks.

### B-3. Make the Cortex responder callable from a script *blocks B5*
`PfSense_Blocker` currently runs when triggered from TheHive's UI. For the autonomous
loop, Ayman's service needs to invoke it programmatically.

- Confirm the Cortex API endpoint + auth to run a responder on an observable
- **Add a dry-run / test mode if possible** — a flag that logs what *would* be blocked
  without actually calling `easyrule`. This is needed for safe testing and is genuinely
  valuable for the report's safety story.

**Done when:** Ayman can trigger a block (or a dry-run block) via `curl`.

### B-4. Bring the lab VMs up and keep them up
Needed for attack-chain testing (C3) and the final demo:

- **Juice Shop** (DMZ, `172.16.0.10`) — has been down repeatedly
- **Windows LAN VM** (`192.168.10.30`) — needs console access to power on
- Both should stay reachable from ~Aug 10 onward

**Done when:** both respond, and stay up.

---

## 🟢 BADR — Independent work (days 3–20, no coordination needed)

### B-5. Clean up Windows test artifacts
Left over from the Task 2 attack validation, still on the box:
- Backdoor local account + its admin group membership
- Test scheduled task
- Registry Run key
- `C:\Users\Public\sam.save` and `system.save`

**Why it matters:** these contaminate later detection work and would be embarrassing if
spotted during a live demo.

### B-6. Capture SOAR evidence (screenshots) ⚠️ *currently zero exist*
`REPORT-PLAN.md` flags these as missing. Capture while the environment is healthy:
- TheHive case list view
- One case fully expanded: observables + Cortex enrichment report attached
- Cortex analyzer job output (VirusTotal or AbuseIPDB result)
- `PfSense_Blocker` in action: pfSense alias table **before and after** a block
- Proof the blocked IP's traffic is actually dropped

### B-7. Rebuild the architecture diagram ⚠️ *referenced but missing*
`socsoar.drawio.png` is cited in your Phase 1 report but **is not in this repo**. It also
predates several changes. Needs updating to show:
- 3 zones (WAN / LAN / DMZ) + Tailscale mesh
- All 5 telemetry sources → Logstash → Elasticsearch
- ElastAlert → TheHive → Cortex → pfSense auto-block loop
- **New:** `soc-llm-aws` (AI triage layer) and where it sits in the flow

This will be the report's main figure. Worth doing properly.

### B-8. Write your report chapters
You own these — see `REPORT-PLAN.md` for the full structure:
- **Ch.7 — SOAR layer:** TheHive/Cortex deployment, analyzer selection rationale,
  the `PfSense_Blocker` build (the HOCON syntax fix, the `case_artifact` typing issue,
  the Alpine-has-no-python3 rewrite, the undocumented `output.json` schema — that
  debugging story is strong material)
- **Ch.3 (partial) — network segmentation:** zone design and DMZ isolation rationale
- **Ch.2 (partial) — your SOAR/AI benchmark tables** from the Phase 1 report

---

## 🔵 AYMAN — Critical path (sequential, do not reorder)

### Phase 0 — Stabilize (Aug 4–6)
| Task | Detail |
|---|---|
| **A1** | Kill the SSDP false-positive flood — poisons AI triage input |
| **A2** | Pipeline watchdogs: "no events in N min" per source + Redis-survives-reboot |
| **A3** | Apply Badr's rotated key (B-1), refresh `configs/` mirror from live |

### Phase 1 — Ship the loop (Aug 6–10) ⭐
**B3 — the triage service.** Python, not Shuffle.
```
poll/webhook from TheHive → fetch case + observables
                          → fetch raw event from Elasticsearch
                          → POST to soc-llm-aws (mistral:7b, few-shot + enum)
                          → validate JSON
                          → POST back "🤖 AI Triage Draft — ..."
```
**Done when:** comments land on ≥3 different real case types, screenshotted.

### Phase 2 — Close the loop (Aug 10–14) ⭐⭐
- **B4** — autonomous trigger (webhook per B-2, or polling fallback)
- **B5** — gated auto-response: AI verdict → `policy_guard()` → Cortex responder
  - Guardrails: no RFC1918/CGNAT/gateway, confidence threshold, rate limit,
    audit trail, kill switch
  - **Must evidence both:** a successful autonomous block **and** a correct refusal

### Phase 3 — Evidence & coverage (Aug 14–18)
- **C1** MITRE catalog of the ~16 validated techniques
- **C2** Coverage matrix (covered / partial / blind, and why)
- **C3** 2 attack chains, per-stage detection table *(needs Badr's B-4 VMs up)*
- **C4** Master SOC Overview dashboard
- **Metrics:** MTTD, MTTR, FP rate before/after A1, alert-to-case ratio
- **ATT&CK Navigator heatmap** (2 hrs, biggest visual payoff in the report)

### Phase 4 — Report & demo (Aug 18–27)
- Write chapters as tracks complete
- **Dry-run #1 by Aug 24**, **dry-run #2 by Aug 26**
- **Aug 27–31 = buffer.** Never demo on the deadline.

---

## 🤝 Sync points — the only 4 times you must coordinate

| When | What | Blocks |
|---|---|---|
| **Day 1–2** | Badr delivers rotated key (B-1) | Ayman's A3 + all of B3 |
| **~Day 5** | Badr confirms webhook yes/no (B-2) | Ayman's B4 design |
| **~Day 8** | Badr confirms Cortex API + dry-run mode (B-3) | Ayman's B5 |
| **~Day 10** | Badr confirms VMs up (B-4) | Ayman's C3 attack chains |

Everything else runs independently. **If Badr goes offline after day 2, Ayman is not
blocked** — that's the point of front-loading his items.

---

## Demo-day split

Both present. Suggested narration split:

| Segment | Who |
|---|---|
| Architecture + network segmentation | Badr |
| Detection layer + dashboards | Ayman |
| Live attack → detection | Ayman |
| Case creation → Cortex enrichment | Badr |
| **AI triage → gated autonomous block** ⭐ | Ayman |
| **The refusal case** (guardrails declining to act) | Ayman |
| Coverage matrix + what we can't see | Either |

---

## What neither of you should do

- **Don't deploy Shuffle** — a Python service does the same job with no new platform risk
- **Don't do more model/infra benchmarking** — that question is closed and documented
- **Don't chase full MITRE coverage** — the coverage matrix is the honest answer
- **Don't add new tools** (Wazuh, another SIEM, etc.) — integration cost, zero deliverable value
- **Don't leave report writing to the last week** — write as each phase completes
