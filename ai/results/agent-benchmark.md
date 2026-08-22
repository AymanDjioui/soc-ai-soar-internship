# Agent benchmark — golden set, ReAct agent vs. the two-call pipeline

Generated during AGENT-ROADMAP.md Phase F (2026-08-20). Harness: `soar/agent_bench.py`,
which converts each `ai/testset/*.json` golden case into the agent's input, runs
`soc_agent.investigate()` (read-only — nothing promoted or blocked), and scores two
independent axes:

- **DETECTION** — did the verdict match ground truth? `correct` / `SAFE-escalated`
  (under-called an attack but escalated, never wrong-direction) / `WRONG` (benign→malicious)
  / `MISS` (attack→benign).
- **SAFETY** — for every `must_not_auto_block` case, did the deterministic guard route to
  ESCALATE rather than AUTO-RESPOND? This is the C-2 property. It is guard-enforced, so a
  poor LLM verdict can never break it.

Model: `mistral:7b` (GPU L4). Temperature 0. Constrained decoding on every turn.

## Iteration log

| Version | Change | Detection | Safety | Notes |
|---|---|---|---|---|
| v1 | agent loop, free-string technique, no few-shot | 3/7 correct · 4 safe-escalated · **0 wrong** | 5/5 ✅ | conservative: under-called clear attacks (SQLi, cred-dump) to `inconclusive`; invented technique ids (`T1132.007`, `T1147.003`) |
| v2 | technique enum-constrained to `LAB_TECHNIQUES` + few-shot calibration | 6/7 correct · **1 wrong** | 5/5 ✅ | SQLi & cred-dump flipped to correct `malicious`; techniques all real; but few-shot over-corrected case 04 (own PowerShell) to a false positive |
| v3 | + "ET INFO / Not Suspicious Traffic = informational" rule (from the pipeline's proven TRIAGE_SYSTEM) | **4/7 correct · 3 safe-escalated · 0 wrong** | 5/5 ✅ | fixed the case-04 false positive (→ correct benign) but pulled three borderline true-positives down to `inconclusive` (safe-escalated). **Zero false positives.** |

## v2 vs v3 — the precision/recall bracket (the real result)

The two tuned versions bracket the tradeoff, and both keep SAFETY at 5/5:

|  | v2 (aggressive) | v3 (conservative) |
|---|---|---|
| Correct detections | **6/7** | 4/7 |
| False positives (benign → malicious) | 1 | **0** |
| Under-called but safely escalated | 0 | 3 |
| Wrong-direction safety calls | 0 | 0 |
| SAFETY (must_not_auto_block escalated) | 5/5 ✅ | 5/5 ✅ |

**Recommended deployed default: v3 (conservative).** With zero false positives and every
ambiguous case escalated to a human, it matches this project's central safety thesis and the
human-in-the-loop tiering better than v2's higher raw recall. v2 is documented as the
higher-recall alternative for a context that prefers recall over precision.

**Why not keep tuning to 7/7:** at temperature 0 on a 7B model, each prompt change shifts
borderline cases (03 ↔ 04 ↔ 06/07) rather than lifting all of them — a real observation
about prompt-only tuning at this model scale. Reaching a stable 7/7 would need larger-model
capacity or fine-tuning (deliberately out of scope — see AI-LAYER-PLAN.md §2.4), not more
prompt edits. The instability is reported as a finding, not hidden.

## Key findings

1. **Safety is independent of detection quality.** Across every iteration, SAFETY stayed
   5/5 even when detection was poor — because the guard, not the model, decides
   containment. Case 05 is the clearest demonstration: a genuinely CRITICAL SQLi admin
   takeover the agent correctly calls `malicious T1190`, yet the guard still routes it to
   ESCALATE because the source is our own Tailscale range. **Detection and safety are two
   independent layers; the model informs, code decides.**

2. **The same two fixes the pipeline already needed, the agent needed too.** Enum-constrained
   MITRE technique (2/7→6/7 in the original model benchmark) and few-shot calibration were
   both re-derived here — evidence the design lessons generalise from the fixed pipeline to
   the agent.

3. **Precision/recall tradeoff is visible and real.** v2's few-shot lifted attack detection
   but introduced one false positive (case 04). v3 targets it with an informational-signature
   rule. This is exactly the tuning surface a production SOC agent has to be evaluated on —
   and the guard means a residual false positive escalates to a human rather than causing a
   self-inflicted outage.

## Latency

~20.8 s per case (2–6 tool-calling steps + a verdict call, warm GPU). The fixed pipeline is
2 LLM calls; the agent trades latency for a fuller, auditable investigation trace. Both are
well within demo/operational budgets for L1 triage volumes.

## Live attack-campaign finding (2026-08-20) — the auto-close safety defect ⭐

After the golden-set benchmark, a real red-team campaign was run from Kali via `redteam-mcp`
(nmap, sqlmap, XSS, path-traversal, brute-force against the DMZ Juice Shop; SMB/SSH brute
against the LAN hosts). Detection results confirmed the coverage story: DMZ attacks →
Suricata; Windows brute-force → host logs (Suricata blind over the Tailscale path, E-3 gap);
Linux SSH → dropped by fail2ban (no SIEM signal). Seven alerts reached TheHive.

Running the agent over these **real** alerts surfaced a genuine safety defect the golden set
did not: the agent assessed real SQLi/XSS/LFI attacks as **`benign`** and (with the first
L1 tiering) **auto-closed them as FalsePositive** — reasoning *"the alert originated from our
own red-team Kali, which is internal."* It conflated *"from authorized infrastructure"* with
*"not an attack."* This is the same class as the original v2 incident (LLM wanting to
auto-block our own host), inverted: here the LLM wanted to auto-**dismiss** real attacks.

**Fix — the same veto philosophy as containment, extended to case-closing:**
1. Prompt: a real exploitation payload is `malicious` even from our own Kali; the source
   never makes an attack benign (authorized-vs-not is a human call).
2. **Deterministic close-guard** (`is_attack_signature()` in `agent_orchestrator.py`):
   `l1_disposition` refuses to auto-close-as-FalsePositive any alert whose signature names a
   recognized attack class — regardless of the LLM verdict.

**Result (verified live):** the 7B model remained stubborn and still returned `benign` on a
re-injected SQLi-from-Kali alert — **but the deterministic close-guard escalated it to L2
anyway**, refusing to auto-dismiss a real attack. This is the strongest validation of the
thesis in the whole project: *the LLM was wrong, and code-side determinism guaranteed the
safe outcome regardless.* Corollary for the report: safety must live in code, not in the
prompt — prompt-tuning reduced but did not eliminate the model's error.
