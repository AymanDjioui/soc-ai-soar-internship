# Tomorrow's TODO — close out the technical phase

Written 2026-08-20 EOD. Goal: finish everything below, then STOP touching code and
move fully to the report (`REPORT-PLAN.md` / `FINAL-ROADMAP.md` R-1..R-9, E-1..E-9).
Read `AGENT-ROADMAP.md` first for full context on what was built today.

## 1. Cortex analyzers — verify + wire properly — ✅ DONE 2026-08-21

- [x] Confirmed Badr added `GreyNoise_3_2` and `Shodan_Host_1_0` (queried Cortex's live
      analyzer registry directly). Registered both in `ANALYZER_NAME_PREFIXES`
      (local `e2e_soc_orchestrator.py` — **not yet deployed to the VM**).
- [x] `agent_tools.run_analyzer()` wired for real — reuses the orchestrator's proven
      `create_analyzer_job`/`wait_for_analyzer_job` path. Verified live against a real
      case: `AbuseIPDB` (Score=0, Reports=0) and `GreyNoise` (not observed scanning in
      90 days) both returned real Cortex data, ~9s each.
- [x] Fixed two bugs found while wiring this: (1) promoting the case now happens
      BEFORE the LLM call (was after) so real observable ids exist for run_analyzer —
      this also meant a GPU-VM outage could leave a silently orphaned case, fixed with
      an explanatory failure comment; (2) the agent was flailing on empty-argument
      tool calls (up to 6× on the same broken call) — retry message now names the
      exact missing field, capped at 3 before forcing conclusion. Full detail in
      `AGENT-ROADMAP.md`.
- [ ] **Remaining: redeploy to the VM.** Today's changes (`ANALYZER_NAME_PREFIXES`,
      `run_analyzer`, the reorder, the reliability fixes, AND the item-2 RAG
      enrichment — 6 new playbooks, deepened MITRE KB, the playbook-matching +
      hallucination-reanchoring fixes) are ALL LOCAL ONLY. Re-run the same scp +
      checksum-verify process used for the first deploy (including the new
      `agent_kb/playbooks/*.md` files) before relying on the VM copy for anything
      (a demo, another armed test).
- [ ] The agent didn't spontaneously choose `run_analyzer` in the one live trace seen
      so far (chose history search instead — a reasonable call, not a bug). If richer
      enrichment on unknown/ambiguous IPs matters for the demo, consider nudging the
      prompt to prefer it for exactly that case (unknown IP, no clear history).

## 2. Enrich the RAG data — playbooks + MITRE catalog coverage — ✅ DONE 2026-08-21

- [x] 6 new playbooks written (recon-scanning, credential-dumping,
      windows-persistence, powershell-execution, privilege-escalation,
      valid-accounts) — all 13 MITRE KB techniques now have playbook coverage
      (10 playbooks total).
- [x] `get_mitre_context()` now resolves a bare parent id (`T1053`) to its
      sub-techniques.
- [x] MITRE KB deepened: reference links, tools observed in this lab, inline
      false-positive notes for T1053.005/T1059.001.
- [x] Re-ran the two escalated campaign alerts. **Two real bugs found and fixed**
      along the way (a playbook-matching keyword collision, and a genuine
      hallucination on sparse-context alerts — see `AGENT-ROADMAP.md` for full
      detail). Both alerts now land on a correct, safe, on-topic verdict
      (`inconclusive T1053.005` / escalate) instead of a wrong or confused one.
      **Known remaining limit, not chased further**: the agent still doesn't
      confidently call the Windows Update task `benign` despite fetching the right
      playbook — a real 7B capability ceiling, safe either way (no IP observable
      means the guard can't act on it regardless), documented as a report finding.

## 3. Real auto-escalation to SOC L2

Today's escalate path (`agent_orchestrator.py`) only leaves the case open + fires the
generic mailer to hardcoded emails. It does not use the new `soc-l2` TheHive account
at all.

- [ ] When `l1_disposition()` returns `tier: L2`, **assign the case to
      `soc-l2@thehive.local`** (TheHive case owner/assignee field) instead of just
      leaving it unassigned.
- [ ] Verify: log in as `soc-l2` / `${SOC_L2_DEMO_PASSWORD}` (redacted 2026-08-22, see
      docs/SECURITY.md) and confirm an escalated case shows up as assigned to them, not
      just floating in the general queue.
- [ ] Re-run one of today's real escalation examples (the SQLi-from-Kali case) through
      this updated path and confirm the assignment lands.

## 4. Evidence capture — screenshots (needed before writing Ch.8/9)

- [ ] TheHive case `~328003784` (the verified C2 auto-block+close) showing the
      `🤖 SOC Agent` comment
- [ ] pfSense `EasyRuleBlockHostsWAN` table showing `202.61.130.163`
- [ ] `soc-l2` login + dashboard, showing an assigned/escalated case (pairs with #2)
- [ ] One full terminal capture of an agent trace (readable ReAct loop output)

## 5. Clean up leftover campaign cases

- [ ] Give the 7 real-attack alerts from today's campaign + the 2 rehearsal cases a
      final disposition (TruePositive/Other), same discipline as the Aug-17 backlog
      cleanup — don't leave the case list messy before a demo.

## 6. Close-guard coverage check

- [ ] `is_attack_signature()` in `agent_orchestrator.py` uses a hand-picked keyword
      list. Check it against the **actual titles of all live detection rules**
      (not just the ones tested today) — a rule whose title matches none of those
      keywords would bypass the guard uncaught. ~20 min.

## 7. Final locked benchmark — the whole pipeline, not just the verdict

- [ ] Today's golden-set bench (`agent_bench.py`, v1→v3) only tested
      `soc_agent.investigate()` (the verdict). The close-guard + L1/L2 tiering came
      AFTER and have never been benchmarked as a whole.
- [ ] Run the golden 7 (+ a couple of real campaign alerts) through the full
      `l1_disposition()` path. Get final numbers: L1-vs-L2 accuracy, false-auto-close
      rate. **This is the table that goes in the report.**

## 8. VM + safety sanity pass

- [ ] Confirm no `KILL_SWITCH` file lingering, local or on the VM
- [ ] Confirm the armed pipeline (`soar-orchestrator.service`) is still `active` and
      untouched
- [ ] Write down (in `AGENT-ROADMAP.md` or a short README) exactly how to invoke the
      agent on the VM — env vars, command — so it's not something only remembered
      from today

## 9. Demo runbook

- [ ] A short, copy-paste script: which alert to inject, which command runs the
      agent, what to point at on the `soc-l2` screen. This is `FINAL-ROADMAP`'s own
      D-1 requirement ("a stranger could follow it").

## Explicitly NOT doing (already a closed, honest boundary)

- Container escape (Scenario 1) — attempted, no RCE via HTTP vectors found on this
  Juice Shop build. Documented boundary, not unfinished work. Don't chase further.
- Burp-based extra attacks — optional variety only, skip unless there's spare time.

## When all of the above is done

Mark the technical phase CLOSED in `PROJECT-STATE.md` / `AGENT-ROADMAP.md`, then move
fully into report writing — Ch.8, Ch.9 (the two-axis guardrail thesis), Ch.10, and the
still-unstarted E-1..E-9 / R-1..R-9 backlog. No more technical detours after this file
is checked off.
