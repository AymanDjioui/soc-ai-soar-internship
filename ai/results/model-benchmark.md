# Local LLM Benchmark for SOC Alert Triage

**Empirical evaluation of five open-weight models and four prompt/schema configurations
on our own labelled incident set.**

Devoteam internship — *SOAR and AI for Detection Improvement in the SOC*
Run 2026-08-01 · **56 inferences** · raw outputs in `raw/` · scored table in `results.csv`

> Directly answers the encadrant's original instruction #3 (`notes/1.md`): *"make a
> benchmark of AI and SOAR solutions that can be used with ELK."* The benchmark in
> `notes/badr_phase1_report (1).md` §6 is a **literature** comparison; this is a
> **measured** one, on real alerts from this lab.

---

## 1. Method

| | |
|---|---|
| Host | `soc-llm` VM — Ubuntu 24.04.4, 4 vCPU, 8 GB RAM, **CPU-only** |
| Runtime | Ollama 0.32.5, `temperature = 0` (deterministic) |
| Output | JSON Schema via Ollama's `format` parameter (constrained decoding) |
| Test set | 7 real alerts from this lab; ground truth known because we ran the attacks |
| Scoring | 3 pts/case — `is_false_positive`, `severity`, `mitre_technique` (exact match) |

**Test-set composition** — deliberately not 7 obvious attacks:

| | Count |
|---|---|
| True positives | 5 |
| **Benign / false positives** | **2** |
| Cases that must **never** be auto-blocked | **5 of 7** |

The benign cases matter: a model that flags everything as malicious *fails* this
benchmark. That 5-of-7 figure is itself a finding — most alerts in this environment
originate from internal hosts or our own Tailscale range, so a naive "AI says malicious
→ block" design would be wrong the majority of the time.

**Two separate experiments**, one variable at a time:
1. **Model comparison** — 5 models, configuration held fixed
2. **Configuration tuning** — best model, 4 prompt/schema combinations

---

## 2. Experiment 1 — model comparison

Fixed: `v3-zeroshot` prompt, `v3-pattern` schema. Only the model varies.

| Model | Params | Disk | JSON | **FP** | Sev | MITRE | **Total** | Latency |
|---|---|---|:--:|:--:|:--:|:--:|:--:|---|
| `mistral:7b` | 7 B | 4.4 GB | 7/7 | **7/7** ⭐ | 4/7 | 2/7 | **13/21** | 68.2 s |
| `phi4-mini` | 3.8 B | 2.5 GB | 7/7 | 5/7 | 5/7 | 3/7 | **13/21** | **24.1 s** ⚡ |
| `llama3.1:8b` | 8 B | 4.9 GB | 7/7 | 5/7 | 5/7 | 2/7 | 12/21 | 47.5 s |
| `qwen2.5:7b` | 7 B | 4.7 GB | 7/7 | 3/7 | 3/7 | 4/7 | 10/21 | 43.2 s |
| `llama3.2:3b` | 3 B | 2.0 GB | 7/7 | 2/7 | 2/7 | 1/7 | **5/21** | 19.6 s |

### Finding 1 — parameter count does not predict performance

```
 3 B  →  5/21     ← collapse
3.8 B → 13/21
 7 B  → 13/21  and  10/21     ← same size, 30% apart
 8 B  → 12/21     ← largest model, not the best
```

The relationship is **non-monotonic**. The largest model tested was not the best, and the
two 7 B models differ by 30%. This directly contradicts the common default of "pick the
biggest model that fits in RAM."

### Finding 2 — model family matters more than model size

A controlled same-size comparison:

| | `mistral:7b` | `qwen2.5:7b` |
|---|---|---|
| Parameters | 7 B | 7 B |
| False-positive accuracy | **7/7** | 3/7 |
| Total | 13/21 | 10/21 |

Identical parameter counts, very different behaviour. Training data and instruction-tuning
quality dominate raw size at this scale. **Model selection for a narrow structured task
must be measured, not assumed from a leaderboard.**

### Finding 3 ⭐ — mode collapse below ~3.8 B

`llama3.2:3b` returned **the identical response for all 7 alerts**:
`is_false_positive: true`, `severity: low`, `mitre_technique: T1003.002` — regardless of
input.

It is not "24% accurate"; it is **non-functional**, with one accidental hit (case 06
genuinely is `T1003.002`). Its low latency is meaningless because it isn't reading the
input. This establishes a hard capability floor for the task and is only visible because
a deliberately undersized model was included.

### Finding 4 — different models are good at different sub-tasks

`qwen2.5:7b` scored **worst on false positives (3/7) but best on MITRE technique (4/7)**
in this experiment. Capability is not a single axis — which suggests routing or
ensembling as future work.

---

## 3. Experiment 2 — configuration tuning

Fixed: `mistral:7b` (winner of Experiment 1). Prompt and schema vary.

| Prompt | Schema | JSON | FP | Sev | MITRE | **Total** | Latency |
|---|---|:--:|:--:|:--:|:--:|:--:|---|
| few-shot | **enum** | 7/7 | 7/7 | **6/7** | **6/7** | **19/21 (90%)** ⭐ | 74.1 s |
| few-shot | pattern | 7/7 | 7/7 | 5/7 | 5/7 | 17/21 (81%) | 65.0 s |
| zero-shot | enum | 7/7 | 7/7 | 4/7 | 3/7 | 14/21 (67%) | 85.0 s |
| zero-shot | pattern | 7/7 | 7/7 | 4/7 | 2/7 | 13/21 (62%) | 68.2 s |

### Finding 5 ⭐ — configuration tuning gained more than model selection

```
Best model vs 2nd-best model  :  13/21 → 12/21   (+1 point)
Worst config vs best config   :  13/21 → 19/21   (+6 points)
```

**Prompt and schema engineering was six times more valuable than the choice of model.**
For a project with limited time, that is the single most useful practical result here:
effort spent on the prompt beats effort spent shopping for models.

### Finding 6 — few-shot: harmful, then beneficial (the same change, opposite results)

| Version | Effect of few-shot |
|---|---|
| v2 (schema included `safe_to_auto_block`) | **Harmful** — model copied the example pattern into the safety field and recommended blocking our own internal host |
| v3 (that field moved to code) | **Beneficial** — +4 points, no regression in FP accuracy |

The reconciliation: few-shot examples make the model imitate patterns strongly. When a
safety-critical decision was inside the model's remit, that imitation was dangerous. Once
containment eligibility was moved to deterministic code (`policy_guard()`), the same
technique became purely helpful.

**Lesson: evaluate prompt changes per-field, not as a single "better/worse" verdict.**

### Finding 7 — enum constraint stops fabrication but does not create understanding

With the free-form `pattern` schema, models invented plausible-but-wrong IDs
(`T1132.002`, `T1048.007`, `T1055.001`). The enum makes off-list output *physically
impossible* under constrained decoding.

- enum alone: MITRE 2/7 → 3/7 (+1)
- enum **with** few-shot: 5/7 → 6/7 (+1, on an already-improved baseline)

The constraint prevents nonsense but the model must still reason to choose correctly —
which is why it only pays off in combination with better prompting.

### Finding 8 — the model never admits ignorance

The `v4-enum` schema included an **`OTHER`** option plus a `technique_reasoning` field,
specifically so an unrecognised technique could be flagged for human escalation rather
than forced into a wrong ID.

**`OTHER` was selected 0 times in 21 opportunities.** The model always produced a
confident answer. This is a well-documented LLM behaviour (reluctance to express
uncertainty) and it **undermines escape-hatch designs that rely on the model
self-reporting doubt**. Uncertainty must be inferred externally — from the `confidence`
value, from disagreement between models, or from signature-to-technique lookup — not
requested politely.

### Finding 9 — schema-constrained decoding is 100% reliable

**56/56 valid, schema-conformant JSON** across every model, prompt and schema — including
the model that had entirely mode-collapsed. No prose, no markdown fences, no truncation,
no parsing logic required.

The *output-format* problem for LLM integration is fully solved by constrained decoding
and is not a differentiator between models. Worth stating plainly, since unreliable
formatting is the most commonly cited obstacle to LLM automation in production.

### Finding 10 — latency does not track parameter count either

`mistral:7b` (7 B) is consistently **slower** than `llama3.1:8b` (8 B). Quantisation and
architecture dominate. The fastest *useful* model (`phi4-mini`, 24.1 s) is ~3× faster than
the most accurate configuration (74.1 s).

---

## 4. Operational infrastructure finding (discovered by failure)

The first few-shot run **crashed the whole Ollama service**:

```
llama-server invoked oom-killer ... Out of memory: Killed process (llama-server)
```

Ollama keeps models resident for ~5 minutes after use. Running three models
back-to-back (`llama3.2:3b` 2 GB → `qwen2.5:7b` 4.7 GB → `mistral:7b` 4.4 GB with a
longer few-shot context) exceeded the 8 GB VM.

**Fix** — `/etc/systemd/system/ollama.service.d/override.conf`:
```ini
[Service]
Environment="OLLAMA_MAX_LOADED_MODELS=1"
Environment="OLLAMA_KEEP_ALIVE=60s"
Environment="OLLAMA_NUM_PARALLEL=1"
```

**Sizing rule:** RAM must cover the *largest* model plus KV cache, not the average, and
concurrent residency must be explicitly capped. Notably, after this fix latencies
*improved* (few-shot 65 s vs zero-shot 68 s), indicating the earlier zero-shot timings
were inflated by memory pressure.

---

## 5. Decision

**Deployment configuration: `mistral:7b` + few-shot prompt + enum-constrained schema —
19/21 (90%), 74.1 s per alert, CPU-only.**

Rationale:
1. **Only model achieving 7/7 false-positive accuracy** — the metric with the highest
   operational cost when wrong. It alone caught both the credential dump and the Nmap
   scan that `phi4-mini` and `llama3.1:8b` dismissed as benign.
2. Its original weaknesses (severity, technique) were **fixed by configuration**, not by
   changing model (Finding 5).
3. Remaining error is a single case whose ground truth is itself arguable.

**Accepted tradeoff:** 74.1 s CPU latency, ~3× slower than `phi4-mini`. Acceptable for
asynchronous triage (a case comment within ~1 minute). Reassessed for live demo — see
the deployment-latency benchmark (ROADMAP D3).

**Retained as alternative:** `phi4-mini` at 24.1 s, if demo latency becomes the binding
constraint and its false-negative rate can be fixed at the prompt level.

**Rejected:** `llama3.1:8b` (largest, no dimension on which it wins), `qwen2.5:7b`
(poor FP accuracy), `llama3.2:3b` (non-functional).

---

## 6. Threats to validity

- **Small test set (n = 7).** Sufficient to expose systematic failures and mode collapse;
  not sufficient for stable accuracy rates. One case moves the score ~5%.
- **Single run per configuration.** `temperature = 0` is deterministic, but there is no
  variance estimate across repeated runs.
- **Ground truth assigned by us**, the same people who ran the attacks. Case 01
  (testmyids canary) and case 03 are genuinely ambiguous.
- **Exact-match scoring is harsh.** On case 05, `T1078` (Valid Accounts) was scored wrong
  against `T1190`, though for a SQLi auth-bypass that stole an admin token it is
  defensible. Severity "high" vs "critical" scores the same as "low" vs "critical".
- **Experiment 2 was run only on the winning model.** Configuration gains may not
  transfer identically to other models.
- CPU-only latencies are hardware-specific.

---

## 7. What this feeds

- **ROADMAP B5** (gated autonomous loop) — Findings 3, 6 and 8 all argue for narrow,
  validated scope plus code-side guardrails rather than trusting model judgement.
- **Guardrail design** — 5 of 7 cases must never be auto-blocked; no model is ever asked
  to make that call. `policy_guard()` is deterministic, code-side, veto-only.
- **REPORT-PLAN Ch.8** — this document is the chapter's core evidence.

## 8. Reproducing

```bash
# run (on soc-llm)
python3 benchmark.py --models mistral:7b --prompt v3-fewshot --schema v4-enum

# rebuild the scored table from preserved raw outputs, without re-running inference
python3 rescore.py
```

Scoring is deliberately separated from execution: `raw/` is the immutable record of what
each model actually said; `results.csv` is derived from it. Scoring rules can therefore be
revised without re-running 56 inferences.

---

# 9. Experiment 3 — do bigger / newer / "security-recommended" models win? (2026-08-10)

Experiments 1–2 ran on CPU, where a 27B model was impractical to even test. The GPU host
(NVIDIA L4, 24 GB — see `deployment-latency.md` §6) removed that constraint, so the
obvious question could finally be answered: **was `mistral:7b` chosen because it was
best, or because it was all the hardware allowed?**

Candidates were taken from a public "best local LLMs for cybersecurity / security
automation" recommendation, not chosen by us — deliberately, to avoid picking opponents
we expected to beat.

## 9.1 What did not fit

| Model | Weights | Fits 24 GB VRAM? |
|---|---|---|
| `qwen3.6:35b` (the top recommendation) | **23.9 GB** | ❌ no headroom for KV cache |
| `llama3.3:70b` | **42.5 GB** | ❌ |

Worth stating plainly: **the most-recommended model could not run on a 24 GB GPU at all.**
General "best model" advice is written without reference to anyone's actual VRAM budget.

## 9.2 Result — same 7-case golden set, same prompt (`v3-fewshot`), same schema (`v4-enum`)

| Model | Weights | JSON | **FP** | Sev | MITRE | **Total** | Latency |
|---|---|:--:|:--:|:--:|:--:|:--:|---|
| **`mistral:7b`** ⭐ | **4.4 GB** | 7/7 | **7/7** | **5/7** | **7/7** | **19/21 (90%)** | **2.8 s** |
| `qwen3.5:27b` | 17 GB | 7/7 | 7/7 | 3/7 | 4/7 | 14/21 (67%) | 48.9 s |
| `qwen3-coder:30b` | 18 GB | 7/7 | 5/7 | 4/7 | 5/7 | 14/21 (67%) | 2.4 s |
| `gemma4:12b` | 7.6 GB | 7/7 | 6/7 | 3/7 | 3/7 | 12/21 (57%) | 57.6 s |
| `qwen3:30b-a3b` (MoE) | 18 GB | **6/7** | 3/7 | 2/7 | 5/7 | 10/21 (48%) | 23.5 s |

### Finding 11 ⭐ — the smallest model won, by a wide margin

`mistral:7b` is **4× smaller** than the next-best candidates and scored **19/21 vs 14/21**.
Every externally recommended model lost. This is Finding 1 (parameter count does not
predict performance) reproduced on **newer model generations, on different hardware, with
candidates selected by a third party** — which is a considerably stronger form of the
claim than the original in-house result.

### Finding 12 — "best for cybersecurity" does not mean "best at *this* security task"

The recommendations were for general security work: incident parsing, threat-intel
reasoning, writing remediation code. Our task is narrow — classify one alert into four
constrained fields. Those are different capabilities, and the ranking did not transfer.

**Benchmark on your own task; published rankings are a starting point for the candidate
list, not a substitute for measurement.**

### Finding 13 ⚠️ — Finding 9 needs correcting: constrained decoding is not *fully* reliable

Finding 9 claimed 56/56 valid JSON and concluded the output-format problem was solved.
`qwen3:30b-a3b` broke that: **6/7**, on case `03-attack-response-lan`.

The failure was **not malformed JSON** — the model returned an **empty string** after
45.9 s. The distinction matters:

- Constrained decoding guarantees that **if** the model emits content, it conforms.
- It does **not** guarantee the model emits content at all.

Empty output is a separate failure mode, and any integration must handle it explicitly
rather than assuming a schema-constrained call always yields a parseable object.
(`call_llm()` in the orchestrator already returns `None` on unusable output, so the
pipeline fails safe — but the guarantee in Finding 9 was overstated.)

### Finding 14 — the enum field can contradict the model's own reasoning

`qwen3.5:27b`, case 07 (external Nmap scan of the DMZ), emitted:

```json
"mitre_technique": "T1547.001",
"technique_reasoning": "Active scanning of internet-exposed assets aligns with
                        T1592 (Gather Victim Host Information) reconnaissance"
```

The constrained field says **T1547.001** (Boot/Logon Autostart Execution — unrelated);
its own free-text reasoning names **T1592**; the expected answer was **T1046**. Three
different techniques in one response.

This sharpens Finding 7. The enum guarantees a *valid* value, not a *considered* one —
and when the model's preferred answer is not on the list, it does not fail loudly, it
silently substitutes an in-list value that contradicts its own explanation. A reviewer
reading only the technique field would have no way to see this.

### Finding 15 — a dangerous failure class: over-applying prompt context

`gemma4:12b`, same external-scan case, reported:

> "**Internal administrator on the Tailscale VPN** performed an Nmap scan against the DMZ
> Juice Shop server. This is likely authorized testing activity."
> `is_false_positive: true`

The source was **external**. The model took the network baseline from the system prompt
(Tailscale = our own administrative range) and applied it to traffic it did not describe,
then dismissed a real external scan as benign.

This is the exact inverse of the v2 failure in `prompt-iteration-log.md` (where the model
wanted to block our own host). Both are the same underlying defect: **the model pattern-
matches context rather than reading the specific alert.** It is also the strongest
argument for `policy_guard()` being deterministic — a false *negative* like this silently
suppresses a real detection, and no schema constraint catches it.

### Finding 16 — MoE size does not buy quality, and latency is not size-ordered

`qwen3:30b-a3b` (Mixture-of-Experts, ~3B active parameters) was expected to be fast and
capable. It scored **lowest of all five (10/21)** and was the only model to fail JSON.

Latency also did not track size: `qwen3-coder:30b` (18 GB) answered in **2.4 s** while
`gemma4:12b` (7.6 GB) took **57.6 s** — a 24× spread with the *larger* model faster.
Architecture and generation behaviour dominate weight count, on GPU as well as CPU
(consistent with Finding 10).

## 9.3 Decision — `mistral:7b` retained

The original choice is **confirmed under conditions that could have overturned it**: a
GPU with 5× the VRAM the model needs, and four newer, larger, externally recommended
competitors. It won on total score, on the safety-critical false-positive field (7/7),
on MITRE technique (7/7), and was second-fastest.

This is now a *tested* decision rather than a constrained one — a materially stronger
claim for the report than "it was the best that fit".

## 9.4 Threats to validity

- **n = 7 cases per model.** One case is worth ~4.8 points; the 19 vs 14 gap is ~1 case
  wide at the margin. The ranking is clear, the exact percentages are not precise.
- **One run per model per case.** No variance estimate. Output is deterministic within a
  host, but that says nothing about how close near-tie tokens were.
- **The prompt was tuned on `mistral:7b`** (Experiment 2). The competitors were tested on
  a prompt optimised for the incumbent, which plausibly disadvantages them. A fair
  re-match would tune the prompt per model — not done, and this caveat should be stated
  in the report rather than claiming a clean win.
- Default Ollama quantisation per model; quantisation levels were not normalised.
- `qwen3.6:35b` and `llama3.3:70b` were excluded on VRAM, not tested and beaten.
