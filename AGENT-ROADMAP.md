# Agent Roadmap — evolving the AI layer from pipeline to SOC agent

Written 2026-08-20. Companion to `FINAL-ROADMAP.md` (evidence/report tasks) and
`AI-LAYER-PLAN.md` (model selection, prompting concepts). Deadline **2026-08-31**;
Aug 24 dry-run gate still stands.

**Goal.** Turn the AI layer from a fixed two-call pipeline into a genuine ReAct-style
SOC agent that *chooses what to investigate* — while keeping the deterministic
containment guard that the whole Ch.9 argument rests on completely untouched.

**Why.** Adds real, sellable value to Devoteam's SOC: an L1 agent that produces a full,
auditable investigation trace per alert, reusable across clients by swapping
tools/playbooks, running on a **local model** so no client incident data leaves their
infrastructure.

---

## Confirmed decisions (2026-08-20)

1. **Scope: investigation-autonomy only.** The agent decides which tools to call and in
   what order. It gets **zero** autonomy over the block decision. `containment_allowed()`
   / `policy_guard()` are UNCHANGED.
2. **Parallel mode, not replacement.** New behaviour lives behind `SOAR_AGENT_MODE=1`.
   The proven 4-phase pipeline stays the default and the demo fallback. If tool-calling
   turns flaky before the demo, we demo the pipeline and agent-mode becomes a
   "built-and-measured" chapter — no catastrophic failure mode.
3. **RAG over both**: the 238 closed TheHive cases (real TP/FP dispositions) **and** MITRE
   ATT&CK, **plus** ~4 hand-written playbooks.
4. **Tiered autonomy = human-in-the-loop by default, auto-respond only when clearly safe.**
   This is *already* how the guard behaves; see below.

---

## The invariant — do not touch this

The grade rests on Ch.9: **"the model informs, code decides."** The measured incident
(prompt v2 recommending an auto-block of our own Windows host over normal UPnP) is the
story. Therefore:

- ✅ Agent autonomy over **investigation** — which analyzer, whether to pull past cases,
  whether to query Elasticsearch for history, whether it has enough to conclude.
- ❌ Agent autonomy over **containment** — none. Execute-vs-escalate stays deterministic.

This makes Ch.9 *stronger*, not weaker: "we gave the AI real agentic autonomy over its
reasoning and the deterministic gate still held" beats "the AI answered two fixed
questions."

## Autonomy tiers (decision 4, already implemented)

The guard is not all-or-nothing — it already implements exactly the tiering asked for:

| Situation | Action | Enforced by |
|---|---|---|
| Confident + external routable + not protected + under rate limit + kill-switch off | **AUTO-RESPOND** (Cortex block) | `containment_allowed()` |
| Low confidence, or internal/Tailscale/protected target, or rate-limited, or kill-switch on | **ESCALATE to human** | same function, veto path |

The agent does **not** change this table. It changes the *quality of the evidence* feeding
the confidence, so the "is this clear-cut?" call is better-founded than it is today.

---

## Architecture — mapping the target diagram to a concrete build

```
ELK/SIEM → alert → SOC AI AGENT (mistral:7b)
                        │
             ┌──────────┴──────────┐
           RAG                   TOOLS
        (playbooks,          (ES, TheHive,
         MITRE, past          Cortex, threat
         cases)               intel)
             └──────────┬──────────┘
                   AGENT LOOP  (Observe → Reason → Act → Observe … max N)
                        │
                 Evidence + Decision
                        │
              POLICY / GUARDRAIL   ← UNCHANGED
                   ┌────┴────┐
                EXECUTE   ESCALATE
              (Cortex)   (assign + mailer)
```

| Diagram box | Concrete build | Exists today? |
|---|---|---|
| TOOLS | 5 callable tools (below) | 2 of 5 already exist as functions |
| RAG | MITRE corpus + 238 closed cases + playbooks | ❌ none yet |
| AGENT LOOP | Bounded ReAct loop, every step audited | ❌ (fixed pipeline today) |
| POLICY/GUARDRAIL | `containment_allowed()` | ✅ unchanged |
| EXECUTE | `PfSense_Blocker` responder | ✅ |
| ESCALATE | assign case + Mailer (real path, not just a comment) | ⚠️ partial |

### The 5 tools the agent can choose from

| Tool | Purpose | Status |
|---|---|---|
| `run_analyzer(observable, name)` | VT / AbuseIPDB / OTX / URLhaus on demand | logic exists, expose as a *choice* |
| `search_elasticsearch(query)` | pull related events / history for an IP or host | new thin wrapper |
| `search_past_cases(ip \| technique)` | RAG over the 238 closed cases — "seen 3× before, all FalsePositive" | new |
| `get_mitre_context(technique)` | RAG over ATT&CK descriptions | new (doubles as E-1) |
| `get_playbook(alert_type)` | retrieve the matching SOP | new |

### Tool-calling mechanism — build on what's already proven

Two options; **we build on (B)**:

- (A) Ollama native `tools` API — cleaner, but mistral:7b reliability at it is unproven.
- (B) **Manual ReAct via constrained decoding** — the LLM emits
  `{"action": "...", "args": {...}}` as schema-constrained JSON, which we have already
  *measured at 56/56 valid* on this exact model/host. Code parses, executes, feeds the
  result back as the next turn.

(B) is lower-risk **and** a reportable design decision: "we grounded agentic tool-calling
in the constrained-decoding reliability we had already measured, rather than trusting an
unbenchmarked native tool-calling path."

### Non-negotiable loop safety

- **Max iterations cap** (~4–5). Prevents runaway cost/latency; a hard code limit, not a
  prompt request.
- **Every step audited** to `soar_audit.jsonl` (reason → tool chosen → args → result).
  This trace is the report's centrepiece figure.
- **Fail-safe**: any loop error → leave the alert for a human, exactly as `triage==None`
  does today. Never let an agent failure produce an automated action.
- Guard is called **after** the loop, on the loop's structured output — same as today.

---

## Phased plan

| Phase | What | Est. | Gate / note |
|---|---|---|---|
| **A** | **Spike**: constrained-decoding ReAct loop with ONE fake tool. Prove mistral:7b reliably picks and calls it. | 3 h | ✅ **DONE 2026-08-20 — GO (4/4).** Valid JSON every turn, tool-before-conclude every time, clean 2-step termination, ~4 s warm. Lesson: use **two schemas** — an action-schema for the loop + a dedicated verdict-schema for the conclusion (mirrors existing `TRIAGE_SCHEMA`/`VERDICT_SCHEMA`; avoids conditional-required schema tricks). Bonus: model returned `inconclusive 0.50` on a no-reputation recon → auto-escalates under the 0.75 floor, i.e. tiered autonomy emerges naturally. Spike script kept at `scratchpad/agent_spike.py` (throwaway). |
| **B** | Build the 5 tools as clean functions (2 wrap existing code). | half day | ✅ **DONE 2026-08-20.** `soar/agent_tools.py` (standalone, does not touch the orchestrator). All 5 self-tested live: `get_mitre_context`, `get_playbook`, `search_elasticsearch` (histogram+samples), `search_past_cases` (IP→observable→case traversal + disposition `hint`), `run_analyzer` (interface only — wired in D). |
| **C** | RAG corpus: index MITRE (**= E-1 evidence task**) + the 238 closed cases. | 1 day | ✅ **MOSTLY DONE 2026-08-20.** MITRE KB built at `soar/agent_kb/mitre.json` (13 lab techniques w/ tactic+desc+detection — E-1 source). Past-case RAG done via **live** TheHive query in `search_past_cases` (310 cases) — no separate offline index needed. Remaining: expand playbooks (Phase E). |
| **D** | Agent loop + audit-trace logging, behind `SOAR_AGENT_MODE`. Guard untouched. | 1 day | ✅ **DONE 2026-08-20** (standalone; wire-behind-`SOAR_AGENT_MODE` still pending). `soar/soc_agent.py` — ReAct loop over the 5 live tools, **imports the REAL `containment_allowed`/`select_containment_target` from the orchestrator unchanged** (venv at `soar/.venv`, `thehive4py` installed). Self-tested read-only over real cases: clean traces, ~21 s/case, guard correctly routes to AUTO-RESPOND vs ESCALATE-TO-HUMAN. Hardened after first real-data run: repeat-call dedup, empty-arg rejection, confidence-range validation (out-of-range → forced 0.0/escalate), loose MITRE-name + playbook matching, prompt tightened on confidence semantics + early conclusion. **Known gap → Phase F**: agent is currently conservative (tends `inconclusive 0.30` → escalate) on thin/ambiguous alerts; needs golden-set prompt/few-shot tuning to confidently fire the auto-respond path on clear-cut cases. |
| **E** | Write 4 playbooks (SQLi/Juice Shop, SSH brute-force, beaconing/C2, Windows logon brute-force). Wire the real Escalate path. | half day | ✅ **DONE 2026-08-20.** 4 playbooks in `soar/agent_kb/playbooks/` (sqli-juiceshop, c2-beacon, ssh-bruteforce, windows-logon-bruteforce), indexed in `agent_tools._PLAYBOOK_INDEX`. Driven by real testing: an injected C2 alert first escalated to L2 (`no matching playbook`), then handled correctly once the C2 playbook + calibration were added — the L1/L2 learning loop, demonstrated. Escalate path = leave case open + Mailer notify. |
| **F** | **Bench agent-mode vs pipeline-mode** on the golden 7-case set: accuracy, latency, tool-call quality, extra evidence gathered. | half day | ✅ **DONE 2026-08-20.** `soar/agent_bench.py`; results `ai/results/agent-benchmark.md`. 3 iterations (v1→v3). **SAFETY 5/5 in every run** (guard-enforced, independent of verdict quality — the thesis). Detection: v1 3/7 → v2 6/7 (1 FP) → v3 4/7 (0 FP). v2/v3 **bracket the precision/recall tradeoff**; v3 (conservative, zero false positives) recommended as default per the project's safety-first thesis. Two fixes re-derived the pipeline's own lessons (enum-constrained technique + few-shot). Prompt-only tuning shown to shift borderline cases at 7B/temp-0 rather than lift all — reported as a finding. Case 05 = the demo centrepiece: agent calls critical SQLi `malicious T1190`, guard **still escalates** (Tailscale source) → detection & safety proven independent. Agent LOCKED at v3. |
| **G** | Fold into the demo runbook (D-1) + rewrite Ch.9/Ch.11 around the agent. | half day | 🟡 **Integration DONE 2026-08-20; report/demo write-up pending.** `soar/agent_orchestrator.py` — SEPARATE parallel entry point that imports the proven orchestrator's helpers (guard, Cortex/mailer/audit) unchanged; the live armed pipeline + its systemd service are untouched. Adds deterministic **L1 auto-close / L2 escalate** tiering (`l1_disposition()` — code decides, model informs). Defaults to `SOAR_AGENT_DRY_RUN=1`; case-close + block gated behind explicit arming + kill switch. Proven live (dry-run) on injected alerts: benign SSDP → **L1 close FalsePositive** (via past-case RAG); ThreatFox C2 IP `202.61.130.163` → `malicious T1071.001`, guard allows → L1-close-TP-when-armed; ambiguous → **L2 escalate**. **Remaining: Ch.9/Ch.11 write-up + demo runbook (the report).** |

**✅ Attack campaign DONE (2026-08-20).** Full E-4 run from Kali via `redteam-mcp`: DMZ Juice Shop (nmap-NSE, sqlmap **confirmed SQLi**, XSS, path-traversal/LFI, login brute-force — all detected by Suricata → TheHive) + LAN (Windows SMB brute-force detected via **host logs**, not Suricata; Linux SSH **dropped by fail2ban**, no SIEM signal; Suricata **blind** to all Tailscale-path LAN attacks). Live re-confirmation of the E-3 coverage gaps. 7 alerts reached TheHive. Running the agent over the real alerts surfaced + fixed the auto-close safety defect (see `ai/results/agent-benchmark.md`). Container-escape (Scenario 1) attempted — no RCE via HTTP vectors, an honest boundary (SQLi is the confirmed-exploitable vuln).

**✅ DEPLOYED to the GPU VM (2026-08-20).** `soc_agent.py`, `agent_tools.py`, `agent_orchestrator.py`, `agent_bench.py`, `agent_kb/` (MITRE + 4 playbooks) scp'd to `~/soar/` on `ollama-l4-server-spot`, **checksum-verified identical to local** (soc_agent `775b1487…`, agent_tools `e144993e…`, agent_orchestrator `a8ac8b8c…`). Runs against the VM's own unchanged `e2e_soc_orchestrator.py` guard. **NOT a systemd service** (deliberate — it must not compete with the armed pipeline for alerts); it is an explicitly-invoked parallel entry point, `SOAR_AGENT_DRY_RUN=1` by default. Live functional test on the VM (local Ollama): C2 → `malicious 0.9 T1071.001` → AUTO-RESPOND. The armed pipeline + its service are untouched.

**✅ `run_analyzer` wired for real + Cortex analyzer roster synced (2026-08-21).**
Badr added **GreyNoise_3_2** and **Shodan_Host_1_0** to Cortex (the two highest-priority
recommended additions from PROJECT-STATE item 10) — registered in both
`e2e_soc_orchestrator.py`'s `ANALYZER_NAME_PREFIXES` (local copy; NOT yet deployed to the
VM) and exposed to the agent. `agent_tools.run_analyzer()` now does a real
`create_analyzer_job` → `wait_for_analyzer_job` (reused from the orchestrator, not
reimplemented) → taxonomy read, instead of the "not_wired" stub. Required promoting the
case BEFORE calling `soc_agent.investigate()` (previously after) so real case-observable
ids exist for the agent to act on — `agent_orchestrator.process_alert_agent()`
restructured accordingly. Verified live against a real case: `AbuseIPDB` → `Score=0,
Reports=0, Usage=Data Center/Web Hosting/Transit`; `GreyNoise` → "not observed scanning
in 90 days". Both real Cortex jobs, ~9s each, test case closed after.

**Two real bugs found and fixed during this work:**
1. **Silent orphaned case on LLM failure.** Since promotion now happens before the LLM
   call, a GPU-VM outage (see below) left a promoted case with zero explanation when the
   agent couldn't reach Ollama. Fixed: `process_alert_agent` now posts a labelled failure
   comment on the case before returning, matching the pipeline's "always leave the
   reasoning visible" principle. Retroactively fixed the one orphaned case
   (`~245780648`, closed `Other`).
2. **Empty-argument flailing.** The model repeatedly called `search_past_cases()` with no
   `value` field — up to 6 times, the entire iteration budget, because the retry message
   only said "provide a non-empty argument" without naming which field. Fixed: the retry
   message now names the exact required field per action (`REQUIRED_FIELD` map), and
   empty-arg failures are capped at 3 (forces conclusion) the same way duplicate calls
   already were. Verified: the same alert that previously flailed 6× on an empty
   `search_past_cases()` now self-corrects after 1 empty call.

**Also caught live: a real GPU VM Spot-preemption incident**, same class as the
2026-08-17 recovery documented in `PROJECT-STATE.md` — Tailscale showed the node offline
mid-session. User restarted from the GCP console; a stale Tailscale SSH approval needed
re-accepting. Recovered cleanly: model digest unchanged (`6577803a...`, not a snapshot
revert), pipeline service `active` again automatically post-boot (`enabled` +
`Restart=on-failure`), confirming the unit survives this failure mode unattended, same
as the prior documented incident.

**Not yet deployed to the VM**: today's `ANALYZER_NAME_PREFIXES` change (local repo
only) and the `run_analyzer`/reorder/reliability fixes (all local). Redeploy + checksum
re-verify before next relying on the VM copy for a demo.

**✅ RAG enrichment — playbooks + MITRE catalog coverage (2026-08-21).**
Added 6 new playbooks (`recon-scanning`, `credential-dumping`, `windows-persistence`,
`powershell-execution`, `privilege-escalation`, `valid-accounts`) covering every
technique in `agent_kb/mitre.json` that previously had none (10 playbooks now cover
all 13 KB techniques). Two of the new playbooks (`windows-persistence`,
`powershell-execution`) explicitly encode a real finding from the 2026-08-20 campaign:
the "Scheduled Task Created" and "Suspicious PowerShell" alerts that escalated
inconclusively were both **documented false positives** already noted in
`PROJECT-STATE.md` (a genuine Windows Update task, a benign `$global:?` variable
check) — the playbooks teach the agent to check task-path/script-content patterns
before assuming malice, the same class of fix as the SSDP/ET-INFO noise rules. MITRE
KB entries deepened with reference links, tools actually observed in this lab, and
inline false-positive notes.

**Three real bugs found and fixed while wiring this in:**
1. `get_mitre_context()` didn't resolve a bare parent id (`T1053`) to its
   sub-techniques (`T1053.005`/`T1053.003`) — fixed, returns all matching
   sub-techniques.
2. `get_playbook()`'s loose matching had a generic-keyword collision: a bare
   `"windows"` index key made `"windows_persistence"` incorrectly match the
   brute-force playbook instead of the new persistence one (first-match-wins on an
   unsorted dict). Fixed: normalize underscores to spaces, try longest index keys
   first.
3. **A real hallucination, found live**: with zero IP observables (realistic for a
   pure host-telemetry alert like a scheduled task — no network address exists), one
   stray wrong tool call late in the trace (an irrelevant playbook fetched by
   mistake) dominated recency and pulled the final verdict onto a **completely
   different alert** — a Windows persistence alert got assessed as `malicious 0.95
   T1190` (the Juice Shop SQLi playbook's own content). Fixed by re-stating the
   original alert content in the final verdict call, not just "give your verdict now"
   — re-anchors against exactly this failure mode. Verified fixed, reproducibly, across
   2 repeated runs of the exact scenario that triggered it (both now land on the
   correct, safe `inconclusive T1053.005`).
   **Note for the report**: even after the fix, the agent does NOT confidently call
   the Windows Update task `benign` despite fetching the correct playbook — a real 7B
   capability limit, not a bug. Safe either way (no IP observable means the guard
   structurally cannot act on it), just not maximally efficient (L2 instead of the
   ideal L1). Consistent with yesterday's "prompt-only tuning has diminishing
   returns" finding — not chased further tonight.

**Demo accounts (2026-08-20):** `soc-l2@thehive.local` / `${SOC_L2_DEMO_PASSWORD}` (password redacted 2026-08-22, see docs/SECURITY.md; analyst, human L2 reviewer) — the teacher demos on this, not Badr's account. TheHive free license caps at 2 users, so agent=automated-L1 (via API), one human account=L2. Demo cases: `~327905496` (SSDP → L1 auto-close FP), `~328003784` (C2 → L1 block+close TP), plus a live SQLi→L2 escalation.

**✅ Armed L1 close-TruePositive CAPTURED + independently verified (2026-08-20).** Injected a fresh real C2 IOC (`202.61.130.163`, AdaptixC2, ThreatFox conf 100%, first-seen same day) as a synthetic-tagged alert; paused the live pipeline service to avoid a race; ran `agent_orchestrator.py` **armed** (`SOAR_AGENT_DRY_RUN=0`, kill switch pre-verified to halt it). Result: agent → `MALICIOUS 0.9 T1071.001` → guard allowed → **CONTAINMENT EXECUTED** → **case `~328003784` auto-closed as TruePositive at L1** — zero human clicks. **Independently confirmed**: `202.61.130.163` present in pfSense `EasyRuleBlockHostsWAN` via direct `pfctl` (not the app's report — the C-1 discipline); case status `TruePositive`/`Closed` via TheHive query. Live pipeline service restarted after. **A real bug was found + fixed en route** (first armed attempt failed cleanly with "target observable not found" → honest L2 escalation, no false success): `_execute_containment` fetched case observables once, before they were copied asynchronously — fixed by reusing the orchestrator's `OBSERVABLE_FETCH_ATTEMPTS` retry. Rollback if ever needed: `pfctl -t EasyRuleBlockHostsWAN -T delete 202.61.130.163`.

### New tiering capability (decision 4 realised)

`l1_disposition()` — deterministic, code-side, model-informed:
| Verdict + guard outcome | Tier | Action |
|---|---|---|
| benign, confidence ≥ 0.85 | **L1** | close FalsePositive (analyst time saved) |
| malicious, external, **contained** | **L1** | close TruePositive (threat handled) |
| malicious but guard-refused / not-armed | **L2** | escalate to human |
| inconclusive / low-confidence | **L2** | escalate to human |

**Total ≈ 4.5 days of focused work**, deliberately overlapping the evidence backlog
(Phase C = E-1). Must NOT cannibalise the report/evidence work that determines the grade
(`FINAL-ROADMAP.md` §0: *"the risk is not capability, the risk is not finishing"*).

---

## Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| mistral:7b tool-calling unreliable | Medium | Phase A spike gates the whole effort; parallel mode means the pipeline still demos |
| Agent eats time the report/evidence needs | High | Time-box; Phase C doubles as E-1; cut agent before cutting evidence |
| Loop latency (3–6 calls vs 2) | Low | Warm ~2.5 s/call; max-iteration cap; fine for demo volumes |
| Encadrant wants human-in-loop only | Low | Tiered autonomy already *is* human-in-loop by default; auto-respond only on clearly-safe cases |
| GPU VM cost / preemption | Known | Existing auto-schedule + kill switch; stop between sessions |

---

## How it lands in the report

- **Ch.8 (AI layer)** — add agent architecture + the agent-vs-pipeline benchmark (Phase F).
- **Ch.9 (Toward autonomous L1) ⭐** — reframed: agentic investigation autonomy + the
  deterministic guard holding the line = the strongest version of the thesis. Keep the v2
  measured incident.
- **Ch.11 (limitations/future)** — native tool-calling and full workflow autonomy as
  deliberately-scoped future work, blocked on measurement not engineering.

## Open items still owned elsewhere

- Encadrant question 3 (autonomous vs human-in-loop) — proceeding with tiered/human-in-loop
  framing; ping if a reply lands.
- Evidence backlog E-2..E-9 and report R-1..R-9 remain the real bottleneck to finishing.
