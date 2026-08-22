# Report Plan — SOAR and AI for Detection Improvement in the SOC

**Devoteam internship · Ayman Djioui + Badr · Deadline 2026-08-31**
Companion to `ROADMAP.md`. Written 2026-08-01.

---

## 1. Framing — the thesis to argue

Do **not** frame this as *"we built a SOC that detects and blocks everything automatically."*
It is unbounded, unprovable in the time available, and the first question in the defense
will dismantle it.

Frame it as:

> **"We built a multi-layer SOC, measured what it can and cannot see, automated the
> Tier-1 triage decision with a locally-hosted LLM, and established the guardrails under
> which that automation can safely act without a human — including the cases where it
> must refuse to act."**

This is stronger because every clause is evidenced by something we actually did. It also
converts the project's biggest apparent weakness (we did not automate *everything*) into
its main intellectual contribution (*we determined what may responsibly be automated,
and proved the boundary*).

**The three strongest assets, in order:**
1. **Full account takeover via SQLi** — a real admin JWT, not a 500 error. Concrete.
2. **The SSDP false-positive incident** — self-discovered, timestamped proof that naive
   autonomy would have blocked our own host. This is the intellectual spine of the AI chapter.
3. **The dual-layer detection split** — network IDS vs application logging catching
   genuinely different attack classes, already proven with an organized screenshot set.

---

## 2. Chapter structure and evidence mapping

Legend: ✅ evidence exists · 🟡 partial · ❌ must be produced

### Ch.1 — Introduction and context
Subject, Devoteam context, company-priority framing, 2-person split, objectives, what
"next-generation SOC" means here.
- ✅ `notes/1.md` (encadrant instructions verbatim, phase structure)
- ✅ `CLAUDE.md` (ownership split)

### Ch.2 — State of the art / benchmark
SIEM + SOAR + AI landscape; why each tool was chosen.
- ✅ Badr's SOAR benchmark table (TheHive+Cortex / Shuffle / StackStorm / n8n / Splunk SOAR)
  and AI benchmark table — `notes/badr_phase1_report (1).md` §6
- ✅ **Licence-constraint findings (strong, specific material):** Kibana webhook connector
  is Gold-only → ElastAlert2 chosen (`notes/6.md`); Elastic ML is Platinum-only → ruled out
- ✅ Self-hosted LLM rationale — data never leaves the network, no API key, no training
  data needed (`ROADMAP` archive §6.0)
- ❌ Short justification of the **final** LLM/orchestrator decision made in Task B1/B2

### Ch.3 — Lab architecture
Three-zone segmentation, Tailscale overlay, distributed AWS/local split.
- ✅ Zone table (WAN/LAN/DMZ) — Badr's report §7.2
- ✅ Bridged → NAT → Tailscale progression narrative — `notes/3.md` §2.4
- ✅ `Architecture.jpeg` (root)
- ❌ **Updated architecture diagram** — current one predates LAN Suricata (`em1`), the
  5-source collection layer, and the entire AI layer. `socsoar.drawio.png` referenced in
  Badr's report is **not in this repo** — obtain or redraw.

### Ch.4 — Data collection layer
Five heterogeneous sources; per-source delivery-mechanism reasoning.
- ✅ pfSense filterlog format decode + CSV quirks — `notes/3.md` §3.5
- ✅ **Delivery evolution as an engineering narrative** (excellent material):
  UDP → fragmentation failure → TCP+`json_lines` (`notes/3.md`) → `tail|nc` + cron watchdog
  (`notes/5.md`) → **native Redis output** (`notes/7.md`) — each step with a stated reason
- ✅ Filebeat ruled out (FreeBSD 15 ABI incompatibility) — recurring, well-documented
- ✅ Juice Shop chain: nginx JSON → rsyslog → socat/syslog-ng relay — `notes/9.md`, `notes/12.md`
- ✅ GeoIP + internal-IP labelling — `notes/5.md`, `notes/12.md`
- ❌ Final consolidated data-flow diagram (5 sources → indices)

### Ch.5 — Detection layer
Suricata on 3 interfaces, 13 ElastAlert rules, 5 dashboards.
- ✅ Suricata deployment + hardware-offload prerequisite — `notes/3.md` §4.4
- ✅ **`em1` silent-failure finding (flagship):** LAN interface captured traffic for days
  with a 389-line ruleset (vs 51,051 on DMZ) — could log flows but was *structurally
  incapable* of alerting. `notes/12.md`
- 🟡 Dashboards exist; **screenshots missing** — see §3
- ❌ Table of all 13 ElastAlert rules (name / index / logic / MITRE mapping)

### Ch.6 — Detection validation (attack scenarios)
~16 techniques across 4 target types.
- ✅ Network/IDS 4 scenarios — `screenshots/detected-by-firewall-ids/` (8 images, verified)
- ✅ App-layer 3 scenarios — `screenshots/detected-by-juiceshop-app/` (7 images)
- ✅ **The folder split itself is the argument** — network IDS vs app logging catch
  different classes. Present as a figure pair, not prose.
- ✅ Linux 3 + Windows 6 attack narratives — `notes/11.md`
- ✅ **Negative result kept on purpose:** path traversal normalized by nginx — `notes/10.md`
- ✅ Demo runbook — `demo/attack-scenarios.md`
- ❌ Linux/Windows attack **screenshots** (narratives exist, images do not)
- ❌ MITRE catalog table (ROADMAP C1)

### Ch.7 — SOAR layer (Badr)
TheHive/Cortex, analyzers, custom responder, closed loop.
- ✅ Full implementation + hurdles — Badr's report §3, §5
- ✅ Analyzer selection rationale (VirusTotal/AbuseIPDB/OTX/URLhaus) — §3.5
- ✅ `PfSense_Blocker` engineering detail (HOCON syntax, `case_artifact` typing, Alpine
  had no `python3` → rewritten in Bash, Cortex's undocumented `$1/output/output.json`
  schema) — genuinely good debugging content
- ✅ **Unplanned proof:** TheHive auto-created a "Windows Privilege Escalation" case from
  our test traffic with no prompting — `notes/11.md`
- ❌ Screenshots: case list, a case with observables + Cortex enrichment report, auto-block
  before/after on the pfSense alias table

### Ch.8 — AI-assisted triage (the new work) ⭐
- ❌ Everything — produced by ROADMAP Track B
- Must include: model/host decision + **why** (incl. the RAM constraint), the prompt
  template, raw alert → model output side-by-sides (B1), the workflow architecture, the
  labelled TheHive comment, measured end-to-end latency

### Ch.9 — Toward autonomous L1: what we automated, and what must not be ⭐⭐
**The most important chapter. This is where the project earns its grade.**
- ❌ The gated autonomous loop (B5): full timeline, zero human clicks
- ❌ **The refusal case** — guardrails correctly declining to act on a benign/internal
  trigger. Evidence the system knows its own limits.
- ✅ **The SSDP incident as the motivating example** — `notes/12.md`. A real, dated event
  where naive autonomy would have blocked our own Windows host.
- ❌ The guardrail model: no-RFC1918/CGNAT/gateway, confidence threshold, rate limit,
  audit trail, kill switch
- ❌ Readiness criteria: what would have to be *measured* before widening autonomy
  (FP/TP rates over time, coverage, rollback). Explicitly state we did not have the
  observation window to meet them — that honesty is the point.

### Ch.10 — Engineering incidents and lessons
Not filler. This is where real competence shows, and every item is already written up.
- ✅ **"Capture isn't detection"** — `em1` logged flows for days with no alerting capability
- ✅ **"The status check lied, the protocol didn't"** — `service redis status` reported
  "not running" while the process answered `PING`/`PONG`
- ✅ **"A bug I introduced while fixing a bug"** — a backup file left inside Logstash's
  pipeline directory silently doubled *every event platform-wide*
- ✅ **Overlay/NAT conflict** — a VM being both a NAT target and a native Tailscale peer
  black-holed one specific path while everything else looked healthy (`notes/8.md`)
- ✅ **Cascading side effect** — the 07-17 NAT fix silently broke Juice Shop log shipping,
  discovered 3 days later (`notes/9.md`)
- ✅ **Clock drift as silent data corruption** — three separate hosts; nothing looks broken
- ✅ **Windows doesn't audit scheduled tasks by default** — T1053.005 invisible out of the
  box, found by testing rather than assumed (`notes/11.md`)
- ✅ **Corporate-network MTU/fragmentation masquerading as an app outage** (`notes/11.md`)
- ✅ **Config drift across two contributors** — same file, different format assumptions
- ✅ **Stale API key** silently broke *all* Suricata→TheHive case creation while other rules
  kept working (`notes/12.md`)

### Ch.11 — Limitations and future work
- Redis unauthenticated on pfSense (firewall-ACL-only) — conscious, documented tradeoff
- No EDR / email / identity / cloud telemetry → structural blind spots (tie to C2 matrix)
- Elastic ML unavailable (Platinum)
- Fine-tuning on own alert data — designed, not built
- Autonomy widening blocked on measurement, not on engineering
- Lab-only tradeoffs: raw POST-body logging incl. attempted credentials; unredacted config mirror

### Ch.12 — Conclusion

---

## 3. Evidence capture list ⚠️

**Capture while the environment is healthy.** `demo/screenshots-2026-07-20/` is cited by
`demo/attack-scenarios.md` and **does not exist** — evidence has already been lost once.

### Dashboards (all 5 — none currently screenshotted)
- [ ] Firewall Overview
- [ ] IDS Detections (**including the new Alerts-by-Interface panel** showing em0/em1/em2)
- [ ] Juice Shop Traffic & Security
- [ ] Linux LAN Host
- [ ] Windows LAN SOC Investigation
- [ ] Master SOC Overview (once C4 built)

### Detection evidence gaps
- [ ] Linux attacks ×3 (terminal + dashboard pairs) — narratives exist, images do not
- [ ] Windows attacks ×6 (terminal + dashboard pairs) — same
- [ ] LAN Suricata `em1` alert (SID 2100498 + PowerShell UA signature) — proves Task 3
- [ ] Re-shoot the 5 demo scenarios to replace the missing `screenshots-2026-07-20/`

### SOAR evidence (none captured)
- [ ] TheHive case list
- [ ] A case: observables + Cortex enrichment report
- [ ] Auto-block: pfSense alias table before/after + attacker traffic dropped

### AI evidence (produced by Track B)
- [ ] B1 raw alert → model output side-by-sides ×5 (**incl. the SSDP false positive**)
- [ ] Workflow canvas / architecture
- [ ] Labelled AI comment on a real TheHive case
- [ ] **B5 full autonomous timeline, zero human clicks**
- [ ] **B5 refusal case — guardrails declining a benign/internal trigger**

### Metrics to record (currently only informally observed)
- [ ] Attack → Suricata alert latency
- [ ] Alert → TheHive case latency
- [ ] Case → AI comment latency
- [ ] Case → autonomous block latency (**the headline number**)
- [ ] Alert volume before/after the A1 noise tuning
- [ ] Model inference time per alert (and RAM footprint)

### Diagrams
- [ ] Updated architecture (3 zones + 5 sources + SOAR + AI layer)
- [ ] Data-flow diagram
- [ ] AI-triage workflow diagram
- [ ] MITRE coverage heatmap (from C1/C2)

---

## 4. Writing rules

1. **Never claim more than the evidence supports.** Every capability claim needs a
   screenshot, a query, or a measurement. Anything unmeasured is labelled "designed,
   not validated."
2. **Negative results are content, not embarrassment** — the failed path traversal, the
   refused auto-block, the missed attack-chain stages, the blind spots in C2.
3. **Quantify** wherever possible: 389 vs 51,051 rules, 4-day outage, 5-minute FP interval,
   ~16 techniques, N-second latency.
4. **Secrets:** `<PLACEHOLDER>` only. Rotate the keys exposed in `notes/8.md` and this
   session's logs before anything is submitted or shared (ROADMAP A3).
5. **Attribute honestly** — Badr's stack vs Ayman's stack, and joint work as joint.
6. Write each chapter as its ROADMAP track completes. Do not leave writing to the last week.
