# Prompt Iteration Log — LLM Triage

Experimental record for REPORT-PLAN Ch.8. Every run is a real measurement on the
`soc-llm` VM, not an estimate.

**Environment**
| | |
|---|---|
| Host | `soc-llm` VM (VMware, on Ayman's laptop) |
| Specs | Ubuntu 24.04.4 LTS · 4 vCPU · 8 GB RAM · 48 GB disk |
| Runtime | Ollama 0.32.5, CPU-only (no GPU) |
| Baseline speed | ~22 tokens/sec (phi4-mini) |
| Date | 2026-08-01 |

**Test case used:** the SSDP false positive from `notes/12.md` — a real, benign Windows
UPnP/SSDP broadcast (`192.168.10.30` → `192.168.10.2`, the pfSense gateway) that matched
`ET DOS Possible SSDP Amplification Scan in Progress` and was creating a TheHive case
every ~5 minutes.

**Ground truth:** `is_false_positive: true` · `severity: low` · `mitre_technique: N/A` ·
**must never be auto-blocked** (internal host → own gateway).

---

## v1 — zero-shot, schema-constrained

Schema-constrained generation via Ollama's `format` parameter (JSON Schema →
constrained decoding). System prompt contained a plain-language network baseline
including *"internal-to-internal discovery protocols are normally benign."*

```json
{
  "summary": "Detected potential SSDP Amplification Scan from internal host to pfSense gateway.",
  "severity": "medium",
  "is_false_positive": false,
  "confidence": 0.85,
  "mitre_technique": "CVE-2021-33775, CVE-2019-0708",
  "recommended_action": "Investigate and monitor the source host (192.168.10.30)...",
  "safe_to_auto_block": false
}
```

| Metric | Result |
|---|---|
| Valid schema-conformant JSON | ✅ |
| `is_false_positive` | ❌ wrong (said malicious) |
| `mitre_technique` | ❌ returned **CVE numbers**, not ATT&CK technique IDs |
| `safe_to_auto_block` | ✅ correct (`false`) |
| Latency | 27.3 s (includes cold model load) |

**Findings:** the delivery mechanism works perfectly — 100% schema compliance, no prose,
no markdown fences, no parsing needed. Two content defects: the model ignored the
benign-baseline hint, and it confused *CVE* with *MITRE ATT&CK technique*.

---

## v2 — few-shot + schema-enforced technique format

Changes: (a) added `"pattern": "^(T[0-9]{4}(\\.[0-9]{3})?|N/A)$"` to `mitre_technique`;
(b) sharpened the baseline rules; (c) added **two few-shot examples**.

*Methodology note:* the few-shot examples were deliberately **not** the SSDP case — a
benign mDNS query and an external SQL-injection attempt were used instead, so SSDP
remained a genuinely held-out test rather than something the model had been shown.

```json
{
  "summary": "Internal Windows host attempted an SSDP amplification scan against the pfSense gateway.",
  "severity": "medium",
  "is_false_positive": false,
  "confidence": 0.85,
  "mitre_technique": "T1190",
  "recommended_action": "Investigate further to confirm if this is malicious or benign internal traffic.",
  "safe_to_auto_block": true
}
```

| Metric | v1 | v2 |
|---|---|---|
| Valid JSON | ✅ | ✅ |
| `mitre_technique` format | ❌ CVE | ✅ `T####` enforced by schema |
| `mitre_technique` semantics | ❌ | ❌ still wrong (`T1190`; should be `N/A`) |
| `is_false_positive` | ❌ | ❌ |
| **`safe_to_auto_block`** | ✅ `false` | ❌ **`true` — REGRESSION** |
| Latency | 27.3 s | **68.4 s** (~2.5× prompt tokens) |

### ⚠️ The key result

**v2 recommended auto-blocking `192.168.10.30` — our own internal Windows host — for
emitting normal UPnP discovery traffic.**

This is the exact self-inflicted-outage scenario predicted in `ROADMAP.md` §0.3, now
reproduced as a measured experimental result rather than a hypothetical risk.

Probable cause: the model pattern-matched few-shot example #2 (attack-shaped signature →
`safe_to_auto_block: true`) and overrode the explicit RFC1918 rule in the system prompt.

### Two conclusions

**1. Architectural — never ask a model a question whose wrong answer causes an outage.**
`safe_to_auto_block` is being **removed from the schema entirely** for v3. Whether an IP
may be blocked is *deterministic policy* — is it RFC1918 / CGNAT / a gateway? — and is
three lines of code. The model's job is summary, severity, technique, and FP-assessment.
The containment decision is code that can only ever **veto**, never approve.

**2. Empirical — few-shot prompting can regress safety-critical fields** while
simultaneously improving format compliance. Prompt changes must be evaluated per-field,
not as a single "better/worse" judgement.

---

## v3 — zero-shot, safety field removed, explicit rule-shaped baseline

Changes from v2:
1. **`safe_to_auto_block` removed from the schema entirely.** Containment eligibility is
   now `policy_guard()` in `ai/benchmark.py` — deterministic code checking RFC1918 /
   loopback / link-local / Tailscale CGNAT. It can only ever **veto**, never approve.
2. Network baseline rewritten from a soft hint into **explicit rules** ("signatures
   labelling internal discovery traffic as amplification/scan/DoS are FALSE POSITIVES
   unless there is rate/volume evidence"; "ET INFO / Not Suspicious Traffic categories
   are informational").
3. Few-shot dropped (measured separately as `v3-fewshot`).

Run: `phi4-mini`, all 7 golden cases, temperature 0.

| Case | FP | Sev | Tech | Notes |
|---|:--:|:--:|:--:|---|
| 01 testmyids WAN | ✓ | ✓ | ✗ | invented `T1190`, expected `N/A` |
| **02 SSDP false positive** | ✓ | ✓ | ✓ | **3/3 — the v1/v2 failure is fixed** |
| 03 attack-response LAN | ✓ | ✓ | ✗ | invented `T1191` |
| **04 PowerShell UA** | ✓ | ✓ | ✓ | 3/3 — correctly read ET INFO as informational |
| 05 SQLi account takeover | ✓ | ✗ | ✓ | severity `medium`, should be `critical` |
| **06 credential dump** (`reg save HKLM\SAM`) | ✗ | ✗ | ✗ | **called real credential dumping benign** |
| **07 Nmap scan** | ✗ | ✓ | ✗ | **called an active scan benign** |

**Score: 13/21 (62%)** · JSON 7/7 · FP 5/7 · Severity 5/7 · Technique 3/7 · **avg 24.1 s**

### Result 1 — the critical false positive is fixed

| | v1 | v2 | v3 |
|---|:--:|:--:|:--:|
| SSDP correctly called benign | ✗ | ✗ | **✓** |

What worked was not a *softer* hint but a **harder, rule-shaped** one. v1/v2 said
"discovery protocols are normally benign"; v3 says "signatures labelling such traffic
amplification/scan/DoS **are FALSE POSITIVES** unless there is rate/volume evidence."
The model follows explicit rules far better than descriptive context.

### Result 2 ⭐ — fixing false positives created false negatives

Cases **06** (credential dumping via `reg save HKLM\SAM` — a genuine technique that
Defender did not block, per `notes/11.md`) and **07** (an active Nmap scan against the
DMZ) were both dismissed as benign. The model over-generalised "internal ⇒ benign" and
swept in a host-based attack and a Tailscale-sourced scan.

This is the **precision/recall tradeoff measured in our own environment**, not quoted
from literature: tuning away the alert flood that was burying the SOC directly produced
misses on two real attacks. It is the strongest available argument for why an autonomous
L1 layer needs a *narrow, well-chosen* scope (ROADMAP B5) rather than blanket authority
over every alert class.

### Result 3 — latency

Removing few-shot cut mean latency **68.4 s → 24.1 s** (~2.8×), because the few-shot
examples nearly tripled the prompt token count. Relevant to the demo: 24 s is tolerable,
68 s is not.

### Open questions for the model benchmark

- Is the 06/07 false-negative failure a **prompt** limit or a **model-size** limit?
  → test `mistral:7b` and `llama3.1:8b` on the identical prompt.
- Does `v3-fewshot` recover 06/07 now that the dangerous field is gone?
- MITRE technique accuracy is the weakest metric (3/7). The model invents plausible-looking
  IDs (`T1190`, `T1191`) rather than returning `N/A`. Candidate fix: constrain to an
  enum of techniques actually relevant to this lab, rather than free-form `T####`.

---

## Report angles unlocked

- **"We measured the AI recommending we block our own host."** A concrete, dated,
  reproducible justification for guardrails-in-code — far stronger than citing a blog post.
- **"Schema-constrained decoding solved the format problem completely, but not the
  reasoning problem."** A clean separation between *delivery reliability* (solved) and
  *judgement reliability* (not solved by formatting).
- **"Few-shot prompting improved format compliance and regressed a safety-critical
  field in the same change."** Argues for per-field evaluation and a held-out test set.
- **Honest methodology:** few-shot examples deliberately excluded the test case, so the
  evaluation was not contaminated.
