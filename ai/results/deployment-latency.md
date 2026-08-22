# Deployment Comparison — Local VM vs AWS EC2

Companion to `model-benchmark.md`. Tests **where** to run the winning configuration
(`mistral:7b`, few-shot, enum schema, 19/21 on the golden test set), not which model —
that question is already answered. Here, only the hardware varies.

Run 2026-08-04.

---

## 1. Method

Identical model file (`mistral:7b`, hash `6577803aa9a0` — byte-for-byte the same weights
on both machines), identical prompt, identical schema, `temperature = 0`, same 7-case
golden test set, same `benchmark.py`, same `OLLAMA_MAX_LOADED_MODELS=1` /
`OLLAMA_KEEP_ALIVE=60s` service config. Only the host changed.

| | `soc-llm` (local) | EC2 `m7i-flex.large` |
|---|---|---|
| Hypervisor | VMware (laptop) | AWS |
| vCPU | 4 | 2 |
| **Physical cores** | **4** (dedicated) | **~1** (2 vCPU = 1 hyperthreaded core) |
| RAM | 8 GB | 7.6 GB |
| Cost | $0 (owned hardware) | $0.10175/hr on-demand |
| Region | — | eu-north-1 |

**Note on instance selection:** this was not the originally planned comparison.
`c6i.2xlarge` (8 vCPU / 4 physical cores — a fair core-matched comparison) was blocked
outright by the AWS account's free-tier restriction ("This instance type is not eligible
under the Free Plan"). `m7i-flex.large` was the smallest/cheapest instance in the
allowed list with enough RAM to hold the model at all. The result below is therefore an
honest comparison of *what was actually available*, not a controlled experiment on
matched cores — stated plainly rather than presented as more rigorous than it is.

---

## 2. Result

| | `soc-llm` VM | EC2 `m7i-flex.large` | Difference |
|---|---|---|---|
| FP accuracy | 7/7 | 7/7 | — |
| Severity accuracy | 6/7 | 6/7 | — |
| MITRE accuracy | 6/7 | 6/7 | — |
| **Total** | **19/21** | **19/21** | **identical** |
| Mean latency | **74.1 s** | **116.1 s** | **+57% slower** |
| Fastest case | — | 81.4 s | |
| Slowest case | — | 202.8 s (likely cold-load) | |

### Finding 1 — accuracy is invariant to hardware

**Every one of the 7 answers was identical between machines** — same false-positive
calls, same severities, same MITRE technique IDs, matching to the value. This is the
expected result for a deterministic model (`temperature = 0`) with byte-identical
weights, and it is worth stating explicitly rather than assumed: **accuracy is a
property of the model and prompt, not the deployment target.** Model/prompt evaluation
never needs to be re-run per environment; only latency does.

### Finding 2 — fewer physical cores costs real time, roughly in proportion

EC2 was **~57% slower** on ~1 physical core versus the VM's 4. This is consistent with
CPU-bound transformer inference scaling with physical core count (not vCPU/hyperthread
count) — a 4:1 physical-core ratio producing less than a 4x latency difference reflects
that the workload is not perfectly parallel, but the direction and rough magnitude match
expectations.

### Finding 3 — the laptop-throttling hypothesis was not confirmed (on this hardware)

The original motivation for testing cloud CPU was that a laptop under 60-90s of
sustained all-core load might thermally throttle, and a datacentre CPU holding turbo
indefinitely could end up *faster* despite equal or fewer cores. **That did not happen
here** — the local VM was faster despite running on laptop silicon, because the EC2
instance's core-count disadvantage outweighed any throttling. This is a legitimate
negative result: the hypothesis was reasonable and worth testing, and testing it
disproved it for this specific hardware pairing.

---

## 3. Decision — Phase 1 (isolated benchmark)

**Deploy on `soc-llm` (local VM).** Rationale: no accuracy cost (Finding 1), meaningfully
faster (Finding 2), zero marginal cost, no dependency on the AWS account's free-tier
instance-type restrictions.

This decision held for as long as the local VM was tested **in isolation** — i.e., as
the only heavy process running on the laptop. It did not survive contact with actual
operating conditions. See §3a.

---

## 3a. Decision reversed — tested under realistic concurrent load

The isolated benchmark answers "how fast is inference on idle hardware," which is not
the same question as "how fast is inference under the conditions this project actually
runs in." In practice, the analyst's laptop must simultaneously run:

- `soc-llm` (the model host)
- `soc-elk` (Elasticsearch + Logstash + Kibana + ElastAlert2 — needed continuously)
- A browser with Kibana/pfSense dashboards open — needed continuously, not incidentally

Re-ran the identical benchmark (`mistral:7b`, few-shot, enum schema) with `soc-elk`
running concurrently on the same 15 GB / 8-thread laptop:

| | Isolated (Phase 1) | Concurrent (`soc-elk` + browser load) | Change |
|---|---|---|---|
| FP accuracy | 7/7 | 7/7 | — |
| Severity accuracy | 6/7 | 5/7 | −1 |
| MITRE accuracy | 6/7 | 6/7 | — |
| Total | 19/21 | 18/21 | −1 |
| Mean latency | 74.1 s | **124.5 s** | **+68%** |
| Slowest case | — | 299.5 s (cold load under swap pressure) | |
| Host swap | not exercised | **100% full** (4.0/4.0 GB) at peak | |
| Host free RAM | — | as low as ~210 MB | |

The VM did not crash and accuracy held almost steady, but host swap saturated
completely during the run, and a **separate, unrelated incident earlier in the same
session did produce a full host hang** requiring a hypervisor-level reset — consistent
with this level of memory pressure being a real operational risk, not just a
performance inconvenience.

**Reversed decision: production inference moves to AWS EC2** (`m7i-flex.large`,
`soc-llm-aws`), despite being slower in isolation (116 s vs 74 s). The deciding factor
is not raw speed but **not competing with the tools the analyst must keep open
continuously**. Under the realistic condition (`soc-elk` + browser both required), EC2's
116 s isolated is *faster* than the local VM's 124.5 s contended — and comes with zero
risk of taking down the SIEM or the dashboard browser to get there.

**Report framing:** this reversal is a legitimate engineering narrative in its own
right — the first benchmark was correct on its own terms but insufficiently
representative of production conditions; testing under the actual concurrent workload
changed the conclusion. Worth stating plainly rather than presenting only the final
answer, since the reasoning trail is the more defensible artifact.

### Final architecture

`soc-llm-aws` joined the Tailscale mesh (hostname `soc-llm-aws`, `100.96.231.95`),
consistent with every other node in this project (pfSense, TheHive, ELK) — reachable
by IP, not dependent on the instance's public IP (which changes on every stop/start,
since no Elastic IP is allocated — deliberately, to avoid its small continuous cost for
an instance that is stopped most of the time). Ollama bound to `0.0.0.0:11434` so it
answers on the Tailscale interface; the AWS security group still only permits inbound
SSH from an admin IP, so the model endpoint is reachable **only** over the tailnet, not
the public internet — same access-control pattern already used for Redis on pfSense
(port 6379 scoped to one Tailscale IP).

**Operating discipline (unchanged from the original AWS plan):** start-per-session, not
always-on. `m7i-flex.large` at $0.10175/hr keeps a full working session under $1;
always-on would be ~$73/month, more than half the available credit in a single month.

**What would still change this decision:** a GPU quota increase
(`g4dn.xlarge`, currently blocked on this account) would likely cut inference to ~3-5s
and is worth requesting ahead of the final demo purely as a speed option — it would not
change the "why AWS" reasoning above, only make the AWS side faster still.

### Azure explored, not adopted (2026-08-04)

Briefly evaluated Azure as an alternative before settling on staying with AWS:

- **CPU option** (`Standard_B2ms`, 2 full physical cores per Azure's own spec sheet —
  not hyperthreaded like AWS's vCPU counting — 8 GB RAM, $0.083/hr) looked plausibly
  faster than the tested `m7i-flex.large` at a lower price, but was never actually
  provisioned or benchmarked. Estimate only, not evidence.
- **GPU option** (`Standard_NC4as_T4_v3`, T4 GPU, $0.526/hr on-demand or ~$0.18/hr
  Spot) exists in the regional catalog (confirmed via `az vm list-sizes`), but
  Microsoft's own documentation states Azure for Students accounts are capped at 3
  vCPUs total and cannot provision GPU-enabled VMs at all — a harder, subscription-level
  block than AWS's soft GPU quota (which just needs a request). Not confirmed against
  the actual subscription via `az vm list-skus --all` (the precise check) before the
  decision to stop exploring was made.

**Decision:** stay on `soc-llm-aws` (AWS). Revisit Azure only if a specific need arises
(e.g., GPU speed becomes necessary for the live demo and the AWS GPU quota request
hasn't been approved in time) — not pursued further purely for comparison's sake, given
limited remaining project time and that the actual triage workflow (ROADMAP B2-B5) had
not yet been started.

---

## 4. Threats to validity

- **Not a core-matched comparison** — 4 physical cores vs ~1, not 4 vs 4. The magnitude
  of the slowdown cannot be attributed cleanly to "AWS vs local"; a fair comparison
  would need `c6i.2xlarge` or equivalent, unavailable on this account.
- **n = 1 run per case, single host pairing.** No variance estimate; a repeat run could
  differ by the noted cold-load effect on case 01.
- **`m7i-flex.large` is a burstable-adjacent "flex" family** — baseline performance with
  some burst allowance, not a dedicated high-clock instance. Results may differ on a
  standard `m7i.large` or similar non-flex type.
- Local VM shares the physical laptop with the host OS; EC2 is a dedicated (virtualised)
  guest with no such contention. This works in EC2's favour and still lost.
- **Concurrent-load test (§3a) is n=1, informal desktop state.** Browser tab count and
  other host activity were not controlled or logged; the specific 124.5 s figure is not
  reproducible exactly, only the qualitative result (severe swap pressure, ~+68%
  latency) is expected to replicate.
- The concurrent-load host hang that motivated this section was a separate incident
  (network/VM-reset trouble), not captured in the same controlled run as the 124.5 s
  measurement — cited as supporting context for the operational risk, not as part of
  the timed result itself.

## 5. Reproducing

```bash
# same benchmark.py and testset/, run on either host:
python3 benchmark.py --models mistral:7b --prompt v3-fewshot --schema v4-enum
```
Raw outputs preserved in `raw/` (soc-llm) and `raw-ec2/` (EC2) for audit;
`results.csv` and `results-ec2.csv` hold the scored tables.

---

# 6. Third host: GPU (added 2026-08-10)

The CPU results above made the pipeline impractical — a single alert took **514.4 s**
end to end (see `soar-dryrun-evidence/`), and the TheHive backlog of 206 alerts would
have needed ~28 hours of inference. A GPU host was added to test whether that is a
hardware limit or a design limit.

## 6.1 Host

| | EC2 `m7i-flex.large` (§1) | GCP `g2-standard-4` |
|---|---|---|
| Accelerator | none (CPU only) | **NVIDIA L4, 24 GB VRAM** |
| vCPU / RAM | 2 / 7.6 GB | 4 / 16 GB |
| Region | eu-north-1 | europe-west4-c |
| Driver / CUDA | — | 580.173.02 / CUDA 13.0 |
| Cost | $0.10175/hr | ~$0.92/hr on-demand |

**Same model file** — digest `6577803aa9a0`, byte-identical to both earlier hosts.
Same prompt, same enum-constrained schema, same `OLLAMA_TIMEOUT`. Only hardware varies.

Model is fully GPU-resident — Ollama reports `size_vram 4.95 GB` of `size 4.95 GB`
(**100% on GPU**, no CPU offload).

**Procurement note:** the T4 originally planned was unobtainable — capacity errors in
`europe-west1`, `us-central1`, `northamerica-northeast1` and `europe-west3`. The L4 was
available immediately. T4 is the cheapest GPU on GCP and correspondingly the most
contended; this is worth planning around rather than treating as bad luck.

## 6.2 Result — identical alert, three warm runs

```
run 1:  37.7 s   <- cold start (loading 4.95 GB into VRAM)
run 2:   2.5 s
run 3:   2.5 s
```

| | CPU (EC2) | GPU (L4) | Change |
|---|---|---|---|
| Triage, warm | **177.6 s** | **2.5 s** | **71x faster** |
| Triage, cold start | ~202 s | 37.7 s | 5.4x faster |
| Full alert (triage + verdict + Cortex) | 514.4 s | ~15-20 s (projected) | ~30x |
| 206-alert backlog (projected) | ~28 h | **~20 min** | — |

Output was **identical across all three runs on this host** — `severity=medium`,
`is_false_positive=False`, `confidence=0.85`, `mitre_technique=T1190` — consistent with
`temperature=0` and enum-constrained decoding. `policy_guard()` 6/6 on the golden IPs.

## 6.2b Golden set re-run on GPU — same score, *different errors*

Full 7-case golden set, same `v3-fewshot` / `v4-enum` config, model warmed first:

```
JSON 7/7 · FP 7/7 · SEV 5/7 · TECH 7/7 · total 19/21 · avg 2.8s
```

**19/21 — the same total as both CPU hosts.** But the per-case breakdown is *not* the
same:

| Case | EC2 CPU | GPU (L4) |
|---|---|---|
| `01-testmyids-wan` | severity ✅ `medium` | severity ❌ `high` |
| `03-attack-response-lan` | severity ❌, technique ❌ | severity ❌, technique ✅ |
| all others | ✅ | ✅ |

The GPU **lost** a severity judgement on case 01 and **gained** a technique judgement on
case 03. Net score unchanged; behaviour changed.

**This matters more than the score.** The model is deterministic *within* a host — three
consecutive runs of the same alert produced byte-identical output — but **not across
hosts**, despite identical weights, prompt, schema and `temperature=0`. CPU and GPU
kernels take different floating-point paths, so tokens that are near-ties resolve
differently.

Consequences worth stating in the report:

- A benchmark result is **host-specific**. "90% on the golden set" is a property of
  model + prompt + schema **+ hardware**, not of the model alone.
- Validating on one host does not guarantee the same per-case behaviour on another.
  Any host change should trigger a re-run, not an assumption of equivalence.
- The earlier §2 claim that "accuracy is invariant to hardware" holds **in aggregate**
  across these three hosts (19/21 every time), but not case by case. That is a weaker
  and more accurate claim than the one originally written.

## 6.3 Finding

**The latency was a hardware limit, not a design limit.** Model, prompt and schema were
unchanged; only the accelerator differed. This retires the main objection to the
approach — that local LLM triage is too slow to be operationally useful. At 2.5 s a
Tier-1 triage draft is available well within the time an analyst takes to open the case.

It also changes an architectural decision: with CPU inference, bounded-run mode
(ROADMAP A-2b) was a hard requirement to avoid committing days of compute. At GPU speed
the full backlog drains in about 20 minutes, so bounding becomes a safety convenience
rather than a necessity.

## 6.4 Threats to validity

- **Latency: n = 3, single alert.** Enough to establish the order of magnitude, not a
  distribution. Accuracy is now *measured* on this host (§6.2b, 19/21) rather than
  assumed — and that measurement showed the assumption of per-case equivalence would
  have been **wrong**.
- **n = 1 per case on the golden set.** The per-case differences in §6.2b are from a
  single run each. Given output is deterministic within a host, repeating would produce
  the same answers — but it does not tell us how *close* those near-tie tokens were, so
  the CPU/GPU divergence could be larger or smaller on a different case mix.
- **Cold start is real and matters operationally.** 37.7 s on the first call after idle.
  Ollama unloads the model after `OLLAMA_KEEP_ALIVE`; a demo that sits idle then fires
  one alert will show the cold number, not 2.5 s. Warm the model before demonstrating.
- **Not a cost-normalised comparison.** The GPU host is ~9x the hourly cost. The correct
  reading is "latency is solvable with money", not "the GPU is better value" — for a
  batch workload with no latency requirement, CPU at 1/9 the price may still win.
- Cost control matters more here: at ~$0.92/hr an instance left running for a week is
  roughly $150. Stop it between sessions.
