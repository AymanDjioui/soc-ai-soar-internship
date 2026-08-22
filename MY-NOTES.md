# My Notes — Ayman's side of the SOC project (for Badr)

Written 2026-08-21. This is a synthesized writeup of everything I've done on the ELK/AI
side across the internship, organized by topic instead of by session, so it's readable
in one sitting. Full session-by-session detail lives in `notes/1.md` through `notes/20.md`
if you want the blow-by-blow; the live current state is always `PROJECT-STATE.md` and
(for the new agent work) `AGENT-ROADMAP.md`.

Credentials are placeholder'd here — pull live values from `PROJECT-STATE.md` /
`configs/` if you need them, don't rely on this file for that.

---

## 1. Who owns what (recap)

- **Me (Ayman)**: ELK stack (Elasticsearch/Logstash/Kibana), pfSense/Suricata config,
  Elastalert2 → TheHive bridge, the AI layer (LLM triage, then the agent), the SOAR
  orchestrator, red-team tooling (`redteam-mcp`, Burp integration).
- **You (Badr)**: TheHive/Cortex (AWS), the Cortex `PfSense_Blocker` responder + Flask
  webhook, network segmentation (WAN/LAN/DMZ), Juice Shop, the mailer integration, the
  Cortex analyzer roster (you've since added GreyNoise + Shodan — see §5).

---

## 2. Architecture, current state

```
pfSense (firewall + Suricata IDS on 3 interfaces: WAN/em0, LAN/em1, DMZ/em2)
   │ filterlog (syslog) + Suricata EVE JSON (native Redis output)
   ▼
ELK (Elasticsearch / Logstash / Kibana) ── Elastalert2 (13 detection rules)
   │ webhook (hivealerter)
   ▼
TheHive (case mgmt) ── Cortex (enrichment: VirusTotal, AbuseIPDB, AlienVault OTX,
   │                              URLhaus, + your new GreyNoise, Shodan)
   ▼
Two parallel "brains" that can read/act on TheHive cases:
  1. e2e_soc_orchestrator.py — the PROVEN, ARMED, production pipeline.
     Two fixed LLM calls (triage, then verdict) + a deterministic policy_guard().
     Runs as a systemd service on the GPU VM, permanently armed since 2026-08-15.
  2. soc_agent.py + agent_orchestrator.py — NEW this week. A genuine ReAct agent
     with tool-calling autonomy over investigation, same deterministic guard reused
     unchanged. Parallel/optional mode, not yet a service. See §7.
   │ (either brain, when malicious+eligible)
   ▼
Cortex PfSense_Blocker responder → SSH → pfSense easyrule block (your side, working)
```

Everything runs over a Tailscale mesh; every host is reached by its Tailscale IP.

---

## 3. Timeline overview

| Phase | What | Status |
|---|---|---|
| Phase 1 | ELK basics: pfSense filterlog + Suricata WAN, dashboards | Done (July) |
| Phase 1b | Suricata on DMZ, then LAN (em1) — found LAN had lost its ruleset silently | Done |
| Phase 2 | LAN hosts (Linux + Windows/Sysmon), dashboards, validated attacks | Done |
| Phase 3 | Noise cleanup, delivery migration (nc→Redis), pipeline watchdogs | Done |
| Phase 4 | AI layer: model benchmark, CPU→GPU migration | Done |
| Phase 5 | SOAR orchestrator: guardrails, C-1/C-2/C-3 captures | Done |
| Phase 6 (this week) | AI **agent**: ReAct loop, tools, RAG, benchmark, deployment, attack campaign | Done, see §7 |
| Remaining | Evidence backlog (E-1..E-9), report (R-1..R-9) | Not started — the real bottleneck |

---

## 4. ELK / SIEM — the foundation

### 4.1 Delivery pipeline
- **Tier 1**: pfSense filterlog (CSV-ish syslog) → Logstash grok+CSV → `soc-logs-*`.
  Protocol-aware parsing added later (TCP/UDP/ICMP have different column counts —
  the original fixed-29-column mapping silently misaligned non-TCP traffic).
- **Tier 2**: Suricata EVE JSON. Started as `tail|nc` over UDP (fragmented on large
  alerts), moved to TCP+`json_lines`, then **migrated to native Redis output**
  (Suricata → Redis list on pfSense → Logstash `redis` input) — more reliable, no
  cron-watched forwarder script needed. Redis runs unauthenticated (`protected-mode
  no`), access scoped by a pf rule to the ELK VM's Tailscale IP only — same pattern
  used for the Ollama endpoint later.
- **Suricata coverage**: WAN (em0) → DMZ (em2) → **LAN (em1)**, in that order. LAN was
  the trickiest: it silently had its rule-category selection lost twice (389 lines vs
  DMZ's 51,051) despite the GUI showing "Select All" — capture worked, alerting
  didn't, for a while, undetected until a deliberate signature-match test.

### 4.2 Dashboards
- Firewall Overview (`soc-logs-*`), IDS Detections (`suricata-alerts-*`), Linux LAN
  Auth & Activity, Windows LAN SOC Investigation, Juice Shop Traffic & Security.
- GeoIP enrichment on all source/dest IPs (MaxMind GeoLite2), with a fix for
  RFC1918/Tailscale ranges showing "Internal (LAN)" instead of a missing-value error.

### 4.3 Noise cleanup (a whole session's worth, 2026-08-12)
The single highest-ROI cleanup pass:
- **Tailscale STUN noise** (SIDs 2016149/2016150) — was ~67% of all Suricata alerts.
  Suppressed on the (undocumented until then) LAN/em1 instance.
- **`pfsense_portscan.yaml` rewritten** from a broken frequency rule (matched almost
  any traffic) to a proper cardinality rule (15+ distinct dest ports/min).
- **SSDP false positive** — benign Windows UPnP discovery misread as "amplification
  scan." Suppressed globally for that signature.
- **`LOCAL Possible Port Scan Detected`** (a custom WAN-only rule, SID 9000001) — same
  bug class as the broken portscan rule, also noise, also suppressed.
- **Historical backlog cleanup**: 246 unprocessed alerts / 164 cases → down to ~70,
  via `Ignored`/`FalsePositive` (not deleted — reversible, shared instance).
- **Stable `sourceRef` for dedup** — every hivealerter POST used to get a random
  UUID, so repeated firings never merged. Required patching the installed
  `elastalert2` package (`configs/elk/elastalert/patches/thehive.py`, mounted via
  docker-compose) since 2.19.0's HiveAlerter doesn't template `sourceRef` natively.
  Hit a real bug mid-rollout: TheHive's `/api/alert` **hard-rejects** a duplicate
  `sourceRef` (400, not a merge) — patched to catch that response as a successful
  dedup instead of an error.

### 4.4 Pipeline watchdogs (A-1)
5 ElastAlert flatline rules watching each log source for silence, cron-gated to lab
hours (`* 8-19 * * *` — NOT an interval cron, that has a real croniter bug where it
never fires, documented in notes/15.md), sized from 7 days of measured real cadence
per source, not guessed.

### 4.5 Recurring incidents (worth knowing about, they'll probably recur)
- **Redis-on-pfSense not surviving reboot** — happened **4+ times** across the
  project before being root-caused (2026-08-12): `/var/run` is tmpfs, wiped every
  reboot, Redis's PID-file dir doesn't exist post-boot, nothing recreates it. Fixed
  with two cron jobs: `@reboot` recreates the dir + restarts Redis, `*/15` health-check
  (`redis-cli ping || service redis restart`).
- **pfSense syslogd silently stops *forwarding only*** (local logging keeps working) —
  happened twice, same signature both times. Fixed with a 20-min cron restart plus the
  existing 30-min watchdog as backstop.
- **ElastAlert's own TheHive API key going stale** after a key rotation that only got
  applied orchestrator-side — every `hivealerter` POST silently 401'd until caught.

---

## 5. AI layer — model choice and the enrichment discipline

### 5.1 Model benchmark
Built a real empirical benchmark (not literature-only) against a 7-case golden set
sourced from real lab attacks (2 of 7 are false positives that must never auto-block —
that ratio alone is a finding). `mistral:7b` beat 8 other models including
larger/newer ones across 3 experiments (`ai/results/model-benchmark.md`). Big lesson:
**prompt/schema tuning (few-shot + enum-constrained MITRE technique) gained 6 points;
picking the best model over 2nd-best gained 1.** Configuration beat model choice 6-to-1.

### 5.2 CPU → GPU migration
Started on an AWS EC2 CPU box (177.6s/triage), migrated to a GCP L4 GPU
(`ollama-l4-server-spot`, now a Spot instance for cost — 2.5s/triage warm, 71x faster).
Spot means it can be preempted; there's an auto-schedule (weekdays 09:00-17:00
Casablanca) and I've now personally watched it get preempted and self-recover mid-session
(the pipeline service is `enabled` + `Restart=on-failure`, comes back up armed and
correct automatically — verified live, twice, including once this week).

### 5.3 The enrichment-summary bug (the flip-flopping mystery, solved)
For a while, verdicts on the same alert would flip-flop between runs. Root cause: the
enrichment step was reading Cortex taxonomies from the wrong object
(`report["summary"]["taxonomies"]` on the raw job status, which doesn't have a
`summary` key at all) — silently returning empty evidence every time, so every verdict
was running on zero data and defaulting to benign. Real taxonomies live on
`api.observable.get(id)["reports"]`. Fixed and verified against live data at three
checkpoints, not just synthetic mocks — that discipline (verify against a real live
Cortex job, not hand-shaped test data) matters, see §9.

---

## 6. SOAR orchestrator (`e2e_soc_orchestrator.py`) — the proven, armed pipeline

### 6.1 Design principle
**"The model informs, code decides."** The LLM answers "what is this?" and "is this
malicious?" — it is never asked whether to block anything. A deterministic, veto-only
`policy_guard()` decides containment eligibility (RFC1918/CGNAT/Tailscale/protected-asset
refusal, confidence floor, rate limit, kill switch). This came directly from a measured
incident: an early prompt version with a `safe_to_auto_block` field recommended
auto-blocking our own Windows host over normal UPnP traffic.

### 6.2 The centrepiece captures
- **C-1 (autonomous block)**: a real, currently-active Cobalt Strike C2 IP
  (sourced from ThreatFox), full chain alert→triage→case→enrichment→verdict→guard→
  **CONTAINMENT EXECUTED**, independently confirmed via `pfctl` on pfSense directly
  (not just trusting the app's own success message).
- **C-2 (correct refusal)**: proved the guard overrides a malicious verdict on our own
  infrastructure two ways — a real Tailscale IP (guard refuses, general CGNAT check,
  not just a hardcoded list) and a sanity check that the same confidence level is
  correctly *allowed* against a genuine external threat.
- **C-3**: confirmed the responder actually adds a pfSense block rule, not just reports
  success.
- Re-armed 2026-08-17 after a Spot-migration recovery (see §4.5-style incident, this
  time on the GPU VM) — validated dry-run first with a fresh IOC before re-arming.

### 6.3 Nine real bugs found and fixed here (worth the list, it's a strength)
1. Suricata ElastAlert rule dropping 100% of alerts (missing `query_key` → one
   chatty host permanently closed the realert silence window for everyone)
2. Same defect in the Windows brute-force rule
3. `observables_count` always 0 (TheHive doesn't return observables on the alert
   object — has to be fetched separately)
4. Cortex responder called by name instead of resolved hash id (fails async, after
   the code already thought it succeeded)
5. **The audit log claiming a block succeeded when Cortex had actually rejected the
   job** — the worst one. Fixed by waiting for Cortex's real status before writing
   `containment_executed`.
6. `select_containment_target` picking the wrong IP on outbound alerts (would have
   blocked the victim, not the attacker)
7. Kill-switch/audit-log paths relative to CWD instead of absolute (a kill switch
   that depends on which directory you're standing in is not a kill switch)
8. Rate limiter failing open on an unreadable audit log
9. Confidence values unbounded in the schema (a `95` instead of `0.95` would clear
   the threshold trivially)

---

## 7. NEW — the AI agent (built this week, 2026-08-20/21)

This is the newest work and probably what you most need context on.

### 7.1 What changed vs. the orchestrator
The orchestrator asks the LLM two fixed questions in a fixed sequence. The **agent**
(`soar/soc_agent.py`) runs a real ReAct loop: the LLM chooses which of 5 tools to
call, with what argument, and when to conclude — genuine tool-calling autonomy over
**investigation**. The containment decision is still 100% the same deterministic guard,
**imported unchanged** from `e2e_soc_orchestrator.py` — that invariant was never touched.

**The honest framing** (useful if you're explaining this to anyone): *"An AI agent with
autonomy over investigation, operating inside a deterministic policy boundary for
action."* Not "fully autonomous" (deliberately not built) and not "just an LLM call"
(it's real tool-use, benchmarked).

### 7.2 The 5 tools + RAG (`soar/agent_tools.py`, `soar/agent_kb/`)
- `search_elasticsearch` — SIEM history for an IP/signature
- `search_past_cases` — **RAG over your 310 closed TheHive cases**, live-queried (not
  a separate offline index) — returns disposition history (e.g. "10 prior
  FalsePositive → weigh toward benign"). This is the single strongest false-positive
  reducer in the whole design.
- `get_mitre_context` — a MITRE KB (`agent_kb/mitre.json`), 13 lab-validated
  techniques with references, tools observed, and inline false-positive notes
- `get_playbook` — 10 playbooks (`agent_kb/playbooks/`) covering every technique in
  the KB — SQLi, C2, SSH/Windows brute-force, recon, cred-dumping, persistence,
  PowerShell, privesc, valid-accounts
- `run_analyzer` — **wired for real this week**: triggers a live Cortex job
  (reuses the orchestrator's own `wait_for_analyzer_job`) and returns real
  taxonomies. Includes your new **GreyNoise** and **Shodan** analyzers — I found them
  live in the Cortex registry and wired them into both the pipeline's
  `ANALYZER_NAME_PREFIXES` and the agent's tool list. (Note: that analyzer-list change
  is local-only so far, not yet redeployed to the GPU VM.)

### 7.3 Tiered L1/L2 autonomy (`soar/agent_orchestrator.py`)
This is new and answers the "autonomous vs human-in-loop" question concretely:

| Verdict + guard outcome | Tier | Action |
|---|---|---|
| benign, confidence ≥ 0.85, not a recognized attack signature | **L1** | auto-close FalsePositive |
| malicious, external, **contained** | **L1** | auto-close TruePositive |
| malicious but guard-refused / not armed | **L2** | escalate to human |
| inconclusive / low-confidence | **L2** | escalate to human |

Deterministic, code-side, same veto philosophy as containment — the LLM never decides
to close a case either.

### 7.4 Benchmark results (`ai/results/agent-benchmark.md`)
Ran the golden 7-case set through 3 prompt iterations. **Safety held at 5/5 in every
single run** (guard-enforced, independent of verdict quality). Detection accuracy went
3/7 → 6/7 → 4/7 across tuning — the last two versions **bracket a real precision/recall
tradeoff** (6/7 with 1 false positive vs. 4/7 with zero false positives). Landed on the
zero-false-positive version as the safer default, matching this project's whole thesis.

### 7.5 A real safety defect found and fixed live
Running real attacks (see §7.6) through the agent, it tried to **auto-dismiss real
SQLi/XSS as false positives** because the traffic came from our own red-team Kali —
conflating "authorized source" with "not an attack." Fixed two ways: prompt correction,
plus a **deterministic code-side veto** (`is_attack_signature()`) that refuses to
auto-close-as-FalsePositive anything whose signature names a known attack class,
regardless of what the LLM says. Verified live afterward: the LLM *still* sometimes
gets this wrong, but the code catches it every time. Same "model informs, code
decides" thesis, now proven on a second axis (auto-close, not just auto-block).

Also found and fixed a genuine **hallucination**: on an alert with zero IP observables
(realistic for host-only alerts like a scheduled task), one stray wrong tool call
late in the trace pulled the final verdict onto a completely unrelated alert. Fixed by
re-anchoring the verdict call with the original alert content. Verified fixed across
repeated runs.

### 7.6 Live verification
- **A real armed L1 capture**: injected a fresh, real ThreatFox C2 IOC, ran the agent
  armed → `malicious 0.9 T1071.001` → guard allowed → blocked on pfSense → case
  auto-closed TruePositive, zero human clicks. Independently confirmed via `pfctl`
  and a TheHive query, not just trusted the app.
- **A full attack campaign via `redteam-mcp`** (nmap, sqlmap-confirmed SQLi, XSS, LFI,
  login brute-force against Juice Shop; SMB/SSH brute-force against the LAN hosts).
  Confirmed the E-3 coverage gap live again: DMZ attacks all hit Suricata; LAN attacks
  over Tailscale are **invisible to Suricata** (no capture on the `tailscale0`
  pseudo-interface — same finding as the very first WAN/DMZ recon test, notes/7.md);
  Linux SSH brute-force was silently dropped by host-level fail2ban before
  authentication, starving the SIEM rule of the pattern it expects.
- Container-escape attempt on Juice Shop (Scenario 1) — tried, no RCE found via HTTP
  vectors on this build. Honest documented boundary, not a gap.

### 7.7 Deployment
Deployed to the GPU VM (`~/soar/`), checksum-verified identical to local. **Deliberately
NOT a systemd service** — it must not compete with the armed pipeline for the same
alerts. It's an explicitly-invoked entry point, dry-run by default
(`SOAR_AGENT_DRY_RUN=1`). The armed pipeline and its service are completely untouched.

### 7.8 Demo account for you / the teacher
TheHive's free license caps at 2 users (yours is one). Created a second:
`soc-l2@thehive.local` — a real analyst account so the demo/defense isn't run on your
admin login. Mapping: the **agent = automated L1**, `soc-l2` = the human L2 reviewer
who sees what the agent escalated.

### 7.9 What's still open
See `TOMORROW-TODO.md` for the live punch list. Headline items: wire real case
**assignment** to `soc-l2` on escalate (currently just leaves the case open + generic
mailer), redeploy this week's fixes to the VM, evidence screenshots, final locked
bench of the whole pipeline (not just the verdict layer).

---

## 8. Red-team tooling

- **`redteam-mcp`** (`redteam-mcp/`) — a custom MCP server exposing 14 offensive tools
  (nmap, sqlmap, hydra, nikto, gobuster, netexec, Impacket secretsdump/wmiexec/psexec,
  linpeas, msfvenom, plus two custom HTTP tools built after hydra proved unreliable
  against JSON APIs) via SSH into a Kali VM on the tailnet. Has its own scope guard —
  refuses anything outside the lab, refuses our own SOC infra, same philosophy as
  `policy_guard()` on the blue side.
- **Burp Suite MCP** — PortSwigger's official extension, wired in after fighting
  hydra's colon-escaping on JSON bodies. Used for the real admin-token-theft proof
  (boolean-based SQLi bypass on `/rest/user/login`, real JWT with `role: admin`
  returned) — which also **surfaced and got fixed** a severe detection gap:
  `juiceshop_sqli`'s keyword filter didn't match boolean/comment-based payloads with
  no SQL keyword, so the actual admin takeover was completely invisible until the
  rule was widened.
- **E-4 attack chains** (`PENTEST-PLAN.md`) — Scenario 1 (WAN→DMZ, real path via the
  NAT'd 8080) and Scenario 2 (LAN foothold via assumed phishing) kept **deliberately
  separate**, because Kali reaches every lab host over the flat Tailscale mesh,
  bypassing pfSense's DMZ/LAN segmentation entirely — testing LAN hosts from Kali
  proves detection, not segmentation. A real DMZ→LAN pivot test would need actual
  code execution on the Juice Shop host itself.

---

## 9. Patterns worth knowing about this project (methodology, not just results)

A few things that recur enough to be worth stating explicitly, since they'll probably
matter again:

- **Verify against the firewall/API directly, never just the app's own success
  message.** The "audit log claimed a block that never happened" bug (§6.3) is why —
  every containment claim since gets independently confirmed via `pfctl`.
- **Test fixes against real live data, not hand-shaped synthetic data.** The
  enrichment bug (§5.3) shipped because the original fix was only tested against a
  synthetic schema assumption — it silently broke on the real Cortex response shape.
- **A GUI "Save" doesn't always mean "applied."** Suricata's suppress-list save
  doesn't restart the process; the running instance kept alerting until manually
  restarted. Checked with a fresh PID, not just "I clicked Save."
- **A silently-degraded pipeline looks identical to "no attacks happening."** This is
  the throughline behind the watchdogs (§4.4), and it recurred again this week: 13
  detection rules were silently disabled and ElastAlert's own TheHive key was stale
  for an unknown period before anyone noticed — found only while testing something
  unrelated.

---

## 10. Where things live

| What | Where |
|---|---|
| Current full project state | `PROJECT-STATE.md` |
| Agent build details, phase-by-phase | `AGENT-ROADMAP.md` |
| Live punch list | `TOMORROW-TODO.md` |
| Roadmap / task register | `FINAL-ROADMAP.md` |
| Pentest scenarios | `PENTEST-PLAN.md` |
| Session-by-session detail | `notes/1.md` – `notes/20.md` |
| AI benchmark results | `ai/results/` |
| Agent code | `soar/soc_agent.py`, `agent_tools.py`, `agent_orchestrator.py`, `agent_kb/` |
| Proven orchestrator | `soar/e2e_soc_orchestrator.py` (backup: `soar/backups/`) |
| Red-team MCP | `redteam-mcp/` |

Credentials: pull current live values from `PROJECT-STATE.md`'s credentials table or
`configs/` — not duplicated here on purpose.
