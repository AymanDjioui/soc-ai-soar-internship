# AI Layer — Model Selection, Concepts, and Solo Work Plan

Written 2026-08-01. Companion to `ROADMAP.md` (Track B) and `REPORT-PLAN.md` (Ch.8–9).
Audience note: written for someone doing local LLMs for the first time.

---

## 1. Decision: where does the LLM run?

### Ruled out immediately: Badr's AWS instance
7.6 GB RAM already running 7 containers — TheHive, Cortex, *two* Elasticsearch instances,
Cassandra, two nginx proxies (Badr's report §3.2). He already fought the OOM-killer there
once (§4.2 — the kernel killed TheHive's JVM). A 5 GB model doesn't slow that box down, it
**kills the SOAR stack**. Never deploy here.

### The three real options

**Important: a second VM on the same laptop does not create RAM.** It's the same 16 GB,
minus an extra guest OS, with *fixed* allocation instead of shared free memory — and
VMware splits the same 4 CPU cores. A separate VM is strictly worse than a host install
for this workload.

```
Host Ubuntu          ~2 GB
ELK VM               ~8 GB   (Elasticsearch + Logstash + Kibana + ElastAlert2)
──────────────────────────
Free                 ~6 GB

Ollama on host:    model only        → phi4-mini 2.3 GB ✓ · llama3.1:8b ~5 GB ⚠️ tight
Ollama in new VM:  model + guest OS  → phi4-mini 3.5 GB ✓ · llama3.1:8b ~6 GB ✗ swaps
```

| Option | Cost | Verdict |
|---|---|---|
| **Laptop host** | $0 | ✅ Best RAM efficiency, no setup, no network hop |
| New VM on same laptop | $0 | ❌ Same physical RAM + guest-OS overhead + fixed allocation |
| **Your own AWS** (`c6i.xlarge`) | ~$0.17/hr ≈ $122/mo if always on | 🟡 Only if the benchmark proves you need 7–8B |
| Your own AWS (`t3.*`) | cheaper | ❌ **Burstable** — sustained inference exhausts CPU credits and throttles hard |
| GPU (`g4dn.xlarge`) | ~$380/mo | ❌ Out of scope |

### ✅ DECISION (2026-08-01): dedicated EC2 instance in Ayman's own AWS account

**Rationale:**
- $120 of credits available, with stop-when-idle discipline → realistic spend $25–50 for
  the remainder of the internship (~18–36% of budget). Comfortable margin.
- The laptop has only ~5.7 GB free with the desktop running; a local VM would reserve RAM
  it does not have.
- **Badr's TheHive/Cortex already runs on AWS.** Co-locating the LLM means the SOAR
  workflow's calls stay in-cloud and do not depend on Ayman's laptop being awake and
  tailnet-connected — a real robustness win for the final demo.

**Build:**
```
Instance   c6i.xlarge  (4 vCPU, 8 GB, compute-optimised)
OS         Ubuntu 24.04 LTS
Storage    40 GB gp3
Region     eu-north-1   (same region as TheHive → low latency)
Network    Tailscale — joins the lab mesh as its own node
Firewall   SSH from own IP only; port 11434 NEVER public, Tailscale-only
Billing    AWS Budgets alert at $20
```

⚠️ **Do NOT use `t3.*`** — burstable instances allocate a CPU-credit baseline. LLM
inference is sustained 100% CPU, so a t3 either throttles hard or silently bills surplus.
Wrong family for this workload.

⚠️ **Security-group discipline is itself report content.** Exposed Ollama endpoints are
actively scanned and abused in the wild. Binding to Tailscale only mirrors exactly what
this project already did for Redis on pfSense (6379 scoped to a single Tailscale IP) —
same reasoning, same pattern, worth one sentence in the report.

**Demo-day option:** instance type can be changed on a *stopped* instance, keeping the
same disk and downloaded models. Switch `c6i.xlarge` → `g4dn.xlarge` (T4 GPU,
~$0.53/hr) for dry-runs and the live demo — inference drops from ~30–60 s to ~2–5 s,
which materially changes how the demo lands. Switch back afterwards. Requires installing
NVIDIA drivers on the instance first.

**Cost-control habit (the thing that actually matters):** stop the instance at the end of
every session. A forgotten `c6i` over a weekend ≈ $9; a forgotten `g4dn` ≈ $25.
Also verify **credit expiry date** and any region/service restrictions on the credits.

**Narrative note:** the report claim becomes *"self-hosted open-weight model on
infrastructure we control — no third-party LLM API, no incident data sent to
OpenAI/Anthropic/Google."* Slightly weaker than pure on-premise, still fully defensible.

---

## 2. Concepts — what you are actually doing (and not doing)

There are four ways to make an LLM behave like a SOC analyst. They are **not** alternatives
to pick one from — they stack, cheapest first.

### 2.1 Prompting — *this is 90% of your project*
You send the model instructions + the alert data. It answers. **The model file is never
modified.** No training, no GPU, no dataset. You "program" it by writing better English.

```
System: You are a SOC Tier-1 analyst. Given an alert, return ONLY JSON with keys:
        summary, severity, mitre_technique, is_false_positive, recommended_action.
User:   <the actual Suricata alert JSON>
```

That is it. This is what you will build. Do not let anyone tell you it is "not real AI
work" — prompt design, schema enforcement, and evaluation *is* the engineering.

### 2.2 Few-shot prompting — *free accuracy, do this*
Put 2–4 solved examples **inside** the prompt before the real question:

> Example 1: `<SSDP alert>` → `{"is_false_positive": true, "reason": "benign Windows
> UPnP discovery to the LAN gateway"}`
> Example 2: `<SQLi auth bypass>` → `{"is_false_positive": false, "severity": "critical"}`
> Now analyse: `<new alert>`

The model imitates the pattern. Costs nothing, no training, big quality jump. **This is
how you teach it your environment's quirks** — like the fact that SSDP traffic from
`192.168.10.30` is normal here.

### 2.3 RAG (Retrieval-Augmented Generation) — *the sophisticated middle ground*
You still don't touch the model. Instead, **at question time** you look up relevant facts
and paste them into the prompt:

- the MITRE technique description for the matched signature
- what asset `192.168.10.20` actually is (Linux LAN host, non-critical)
- how the last 3 similar alerts were resolved

This gives you most of the benefit of a custom-trained model with **zero training**. It is
current best practice in the literature (see §7) and is a legitimate, impressive addition
if time allows. Treat it as a stretch goal after the base loop works.

### 2.4 Fine-tuning — *you will NOT do this, and you should say why*
Continuing training on your own labelled examples, permanently changing the model's
weights. Requires: hundreds-to-thousands of labelled alert→triage pairs, a GPU, hours-days
per run, and an ML pipeline.

You have ~16 validated attacks. That is not a dataset — it is a test set. Fine-tuning here
would produce a *worse* model than good prompting, and eat your entire remaining month.

**Report line:** *"Fine-tuning was evaluated and deliberately rejected: with ~16 labelled
incidents, few-shot prompting with schema-constrained decoding outperforms fine-tuning at
a fraction of the cost. Fine-tuning is documented as future work contingent on
accumulating a labelled incident corpus."* That is a mature, defensible answer — much
better than not having considered it.

### 2.5 One technical thing that matters a lot: **structured outputs**
Ollama (v0.5+) accepts a **JSON Schema** in the `format` parameter and uses constrained
decoding (XGrammar) to force the output to match it. Two consequences:

- **Reliability:** you get valid JSON instead of "Sure! Here's the analysis: ```json…"
- **Speed:** measured ~6.4× faster in one benchmark (31.8s → 5.0s) because the model
  can't wander off generating prose

Use this from day one. It removes an entire category of parsing bugs. *(Caveat: if the
model runs out of tokens mid-object you can still get truncated JSON — always wrap the
parse in a try/except and have a "flag for manual review" fallback path.)*

---

## 3. Model shortlist (researched 2026-08-01)

Your hardware: **i5-1155G7 (4 cores / 8 threads), 16 GB RAM, no GPU.** The ELK VM takes a
large slice when running, so assume **~6 GB free** for the model in the worst case.

Rule of thumb: RAM needed ≈ *parameters in billions × 0.6* at Q4 quantisation.

| Model | Size (Q4) | Speed on CPU | Why it's a candidate |
|---|---|---|---|
| **Phi-4-mini (3.8B)** | ~2.3 GB | ~12 tok/s | Best-rated CPU-only model of 2026; strong reasoning per byte; runs comfortably *alongside* the ELK VM |
| **Qwen3.5 4B** | ~2.5 GB | fast | Widely rated best all-round CPU-only pick for 2026 |
| **Mistral 7B** | ~4.1 GB | moderate | Long-standing reliable baseline, good instruction following |
| **Llama 3.1 8B** | ~5 GB | slower | Best quality of the four; the "one model for everything" pick on 16 GB — but tightest fit |

**Recommendation:**
- **Start with Phi-4-mini** — smallest, fastest, lets you iterate on the prompt quickly
  without waiting 60s per answer.
- **Benchmark all four** (§4) and pick the final one on *your own measured data*.
- If a 7–8B model wins on quality but is too slow with the VM running, that is itself a
  finding worth reporting (the classic accuracy-vs-latency tradeoff).

⚠️ **Verify exact Ollama tags before pulling** — registry names change (`phi4-mini`,
`qwen3.5:4b`, etc.). Run `ollama list` / check the Ollama library page rather than
trusting a tag from any document, including this one.

---

## 4. The benchmark IS your contribution ⭐

Go back to `notes/1.md` — your encadrant's **original instruction #3** was:

> *"Make a benchmark of AI and SOAR solutions that can be used with ELK."*

Badr wrote a *literature* benchmark (tables comparing tools on paper). Nobody has run an
**empirical** one. So do this:

> **Benchmark 4 local LLMs on your own real SOC alerts, measuring accuracy, latency,
> RAM, and false-positive discrimination — then justify the final model choice with data.**

Why this is the strongest possible move right now:
- Directly answers the assignment as originally given
- **Requires no VMs and no Badr** — you can do it today
- Produces tables + charts = ready-made report chapter
- Justifies your model choice with evidence, not "we picked the popular one"
- Almost no student project does this; most just call an API and call it AI

Metrics to record per model, per alert:
`correct severity? · correct MITRE technique? · FP correctly identified? · valid JSON? ·
latency (s) · RAM peak (GB) · tokens/s`

---

## 5. Golden test set — build it from what you already have

You do **not** need the VMs running. These are real alerts already documented in your
notes. Ground truth is known because *you ran the attacks*. Save as `ai/testset/*.json`.

| # | Alert | Source | Ground truth |
|---|---|---|---|
| 1 | `GPL ATTACK_RESPONSE id check returned root` (SID 2100498), testmyids, WAN | notes/3.md | TP, but a **canary/test** — medium. Nuance test |
| 2 | `ET DOS Possible SSDP Amplification Scan` — `192.168.10.30 → 192.168.10.2`, em1 | notes/12.md | **FALSE POSITIVE**, benign Windows UPnP. Must NOT auto-block ⭐ |
| 3 | SID 2100498 on **em1**, `217.160.0.187 → 192.168.10.20`, GeoIP Germany | notes/12.md | TP, medium-high — external host returned root-shell content to an internal host |
| 4 | `ET INFO Windows Powershell User-Agent Usage`, em1 | notes/12.md | Informational / benign — our own `Invoke-WebRequest`. Low |
| 5 | `POST /rest/user/login` body `' OR 1=1--` → HTTP 200 + admin JWT | notes/10.md | **TP, CRITICAL** — full account takeover (T1190) ⭐ |
| 6 | Sysmon proc-create: `reg save HKLM\SAM` / `HKLM\SYSTEM` | notes/11.md | TP, HIGH — credential dumping (T1003.002) |
| 7 | `ET SCAN Nmap Scripting Engine User-Agent Detected` (142 alerts) | notes/7.md | TP, medium — recon (T1046) |

**Why this set is good:** it is not 7 obvious attacks. It contains **2 benign cases (#2, #4)**
and one low-impact canary (#1). A model that flags everything as critical *fails* this set.
That is exactly what makes it a real evaluation rather than a demo — and case #2 is the
one that decides whether autonomous blocking is safe (ROADMAP §0.3).

---

## 6. Starting prompt + schema

Iterate on this — it is a starting point, not the answer.

```
SYSTEM:
You are a Tier-1 SOC analyst for a lab network. Be precise and conservative.

Network context:
- 192.168.10.0/24 = internal LAN. 192.168.10.2 = pfSense gateway.
  192.168.10.20 = Linux host. 192.168.10.30 = Windows host.
- 172.16.0.0/24 = DMZ. 172.16.0.10 = OWASP Juice Shop (deliberately vulnerable).
- 100.64.0.0/10 = Tailscale VPN (administrative access, usually legitimate).
- Internal-to-internal traffic on common discovery protocols (SSDP/UPnP/mDNS)
  is normally benign in this environment.

Return ONLY a JSON object. No prose, no markdown fences.

USER:
<alert JSON>
```

Schema for Ollama's `format` parameter:

```json
{
  "type": "object",
  "properties": {
    "summary":            {"type": "string"},
    "severity":           {"type": "string", "enum": ["low","medium","high","critical"]},
    "is_false_positive":  {"type": "boolean"},
    "confidence":         {"type": "number"},
    "mitre_technique":    {"type": "string"},
    "recommended_action": {"type": "string"},
    "safe_to_auto_block": {"type": "boolean"}
  },
  "required": ["summary","severity","is_false_positive","confidence",
               "mitre_technique","recommended_action","safe_to_auto_block"]
}
```

`confidence` and `safe_to_auto_block` exist specifically to feed the ROADMAP B5 guardrails —
the model must be able to say *"I'm not sure, escalate to a human."*

⚠️ The model's `safe_to_auto_block` is **an opinion, not permission.** The hard guardrails
(never act on RFC1918/CGNAT/gateway IPs, rate limits, kill switch) are enforced in code
*outside* the model and can only ever veto, never approve. Case #2 must be blocked by
code even if the model gets it wrong.

---

## 7. Related work worth citing (found 2026-08-01)

Useful for `REPORT-PLAN.md` Ch.2 — shows the approach is current research, not improvised:

- **CORTEX** — collaborative LLM agents for high-stakes alert triage ([arxiv 2510.00311](https://arxiv.org/pdf/2510.00311))
- **Retrieval-Augmented LLMs for Security Incident Analysis** ([arxiv 2603.18196](https://arxiv.org/html/2603.18196v1)) — the RAG approach in §2.3
- **Policy-Guided Threat Hunting: LLM framework with Splunk SOC triage** ([arxiv 2603.23966](https://arxiv.org/html/2603.23966v1))
- **AI in the SOC: Benchmarking LLMs for Autonomous Alert Triage** ([Simbian](https://simbian.ai/blog/the-first-ai-soc-llm-benchmark)) — direct precedent for §4
- Practitioner precedent: local Gemma-via-Ollama L1 agent triaging overnight SIEM alerts
  and escalating to an L2 — the same L1/L2 split as ROADMAP B5

---

## 8. Solo work plan — no VMs, no Badr, starting now

Roughly 3–4 days of genuine progress with zero dependencies. Ordered.

### Step 1 — Install Ollama and confirm it runs (30 min)
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama --version
ollama pull phi4-mini          # verify the exact tag first
ollama run phi4-mini "Reply with the word OK and nothing else."
```

### Step 2 — Confirm structured output works (30 min)
Send one request with a `format` JSON schema and check you get schema-valid JSON back.
If this works, the riskiest technical unknown in the whole AI layer is gone.
```bash
curl http://localhost:11434/api/chat -d '{
  "model": "phi4-mini",
  "messages": [{"role":"user","content":"Summarise: nmap scan from 1.2.3.4"}],
  "format": { "type":"object",
              "properties":{"summary":{"type":"string"},
                            "severity":{"type":"string","enum":["low","medium","high","critical"]}},
              "required":["summary","severity"] },
  "stream": false
}'
```

### Step 3 — Build the golden test set (1–2 h)
Write the 7 cases from §5 into `ai/testset/01…07.json`, each with a sibling
`expected.json` holding the ground truth. Source them from the notes.

### Step 4 — Write the benchmark harness (2–3 h)
A single Python script: for each model × each test case → send prompt, capture output,
measure latency, compare to ground truth, append a row to `ai/results.csv`.

### Step 5 — Pull and benchmark the other 3 models (半 day, mostly waiting)
Downloads are a few GB each. Run the harness. **Kill the ELK VM first** so the 7–8B
models get fair RAM.

### Step 6 — Iterate the prompt (2–3 h)
Zero-shot → few-shot (§2.2) → with network context. Re-run the harness after each change.
**Keep every version** — "prompt v1 vs v2 vs v3 accuracy" is a real result and a chart.

### Step 7 — Write Ch.8 first draft (half day)
You will have: model comparison table, latency/RAM numbers, prompt evolution, the FP
discrimination result. That is an entire chapter, written before Badr is back.

### Also available offline (no LLM needed)
- **MITRE ATT&CK catalog (ROADMAP C1)** — pure desk work from the notes. Report backbone.
- **Coverage-gap matrix (C2)** — the honest maturity assessment.
- **Report chapters 1, 2, 3, 10** — context, state of the art, architecture, and the
  incident/lessons chapter (all source material is already written in `notes/`).
- **Redraw the architecture diagram** — current one predates LAN Suricata and the AI layer.

### When Badr is back — the merge points
1. Ollama reachable from the SOAR host over Tailscale
2. TheHive API key (rotated — ROADMAP A3) for reading cases / posting comments
3. Fire real attacks → capture live end-to-end evidence
4. Wire the gated autonomous loop (B5) into the existing `PfSense_Blocker` responder

---

## 9. Honest framing for the defense

If asked *"did you build an AI that replaces a SOC analyst?"* — the answer is not yes,
and it should not be:

> *"We built and measured an LLM-based Tier-1 triage layer running entirely on local
> hardware, benchmarked four open models against our own labelled incident set, and
> demonstrated one fully autonomous detection-to-containment loop under explicit
> guardrails. We also demonstrated the boundary: a real false positive in our own
> environment that would have caused a self-inflicted outage had it been automated
> naively. Widening autonomy beyond that boundary is blocked on measurement, not on
> engineering."*

That answer survives follow-up questions. "We automated everything" does not.
