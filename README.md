# SOAR + AI for SOC Detection Improvement

Devoteam internship project: a small SOC lab (pfSense, Suricata, ELK,
TheHive/Cortex) wired to a SOAR orchestrator that uses a locally-hosted LLM
to triage alerts and, under a deterministic, code-side safety gate, can
autonomously contain and close the cases it's confident about — escalating
everything else to a human.

## Objective

Reduce SOC analyst toil on the alert types that are safe to automate,
without ever letting a model decide, on its own, whether to touch the
firewall. The central design claim tested by this project: **the model
informs, code decides.**

## Architecture

```
pfSense (WAN/LAN/DMZ) --Suricata IDS--> Redis --> Logstash --> Elasticsearch
                                                                     |
                                                                ElastAlert2
                                                                     |
                                                                  TheHive  <-- Cortex (enrichment + pfSense-block responder)
                                                                     |
                                                          SOAR orchestrator (soar/)
                                                                     |
                                                    local LLM triage (Ollama, GPU-hosted)
                                                                     |
                                                    deterministic L1/L2 policy gate
                                                       /                        \
                                          L1: auto-contain + close      L2: assign to human analyst
```

- **Detection**: Suricata (3 interfaces: WAN/LAN/DMZ) → Redis → Logstash →
  Elasticsearch, watched by ElastAlert2, which opens TheHive cases.
- **Response**: Cortex's `PfSense_Blocker_1_0` responder executes firewall
  blocks; verification always re-checks pfSense state directly (`pfctl`),
  never trusts a reported success.
- **AI layer**: a GPU-hosted `mistral:7b` (Ollama) produces a structured
  verdict (severity, confidence, MITRE technique) from case context — see
  `ai/results/model-benchmark.md` for why this model was chosen over 4
  alternatives, and `ai/results/deployment-latency.md` for the CPU→GPU
  migration (177.6s → 2.5s warm-triage latency).
- **SOAR**: `soar/agent_orchestrator.py` (agentic, tool-calling) and
  `soar/e2e_soc_orchestrator.py` (linear pipeline) both wrap the model's
  verdict in the same deterministic `l1_policy.py` gate before any
  containment action is even considered.
- **Offense**: `redteam-mcp/` — a custom MCP server that drives a lab-scoped
  Kali box, used to generate real, honest attack traffic to validate what
  the pipeline actually detects (see `demo/attack-scenarios.md`).

See `Architecture.jpeg` for the full network diagram and
`docs/REPOSITORY-MAP.md` for what every directory in this repo is.

## Directory structure

```
soar/            SOAR orchestrator, policy gate, idempotency, tests (632 checks)
ai/               Prompts, benchmark harness, results, Dataset A/B test fixtures
redteam-mcp/      Offensive MCP server (lab-scoped attacker tooling)
configs/          Real ELK/pfSense config mirrors (gitignored) + sanitized .example templates
report/           LaTeX report source + compiled PDF
demo/             Demo attack-scenario script
screenshots/      Detection evidence, organized by source and scenario
docs/             This documentation set (repository map, setup, security)
```

Full breakdown, including exactly which files are tracked vs. gitignored
and why: `docs/REPOSITORY-MAP.md`.

## Current phase status

The agentic AI layer (`soar/soc_agent.py` + `agent_tools.py` +
`agent_orchestrator.py`) is built, benchmarked, and deployed as a standing
production service: verified live armed L1 auto-containment (real,
independently-confirmed-malicious IOC blocked + case auto-closed,
pfctl-verified — not just Cortex's self-reported success) alongside verified
correct L2 escalation and fail-closed refusal on unconfirmed IOCs.
Dataset B (real, historical TheHive cases, dual-reviewed and adjudicated)
is **locked** at 60 cases — see `soar/review_overlays/DATASET_B_LOCK_v1.json`.
Full verification history and every live-capture test run: `soar/L1-L2-SAFETY-AUDIT.md`.

## Safety model: L1 vs L2

- **L1 (autonomous)**: high-confidence, rule-eligible cases with no
  protected-asset conflict may be auto-contained and auto-closed.
- **L2 (human-in-the-loop)**: anything ambiguous, low-confidence,
  rule-ineligible, or touching a protected asset (internal ranges, the
  SOC's own infrastructure) is assigned to a human, never auto-contained.
- A deterministic policy gate (`soar/l1_policy.py`) is veto-only — it can
  refuse an action the model recommends, never authorize one on its own.
- Full design rationale, every verification pass, and the credential
  incidents referenced in `docs/SECURITY.md` live in
  `soar/L1-L2-SAFETY-AUDIT.md`.

## Installation

See `docs/SETUP.md` for the full walkthrough (Python env, `.env`, ELK
Docker stack, pfSense reference mirror, red-team MCP server).

## Offline tests

```bash
cd soar
for f in test_*.py; do ./.venv/bin/python3 "$f"; done
```

**632 checks, 0 failures.** None touch live infrastructure.

## Shadow-mode / dry-run deployment

Every orchestrator entry point defaults to (or can be forced into) dry-run:

```bash
cd soar
SOAR_DRY_RUN=1 SOAR_ALERT_ID="~<id>" ./.venv/bin/python3 e2e_soc_orchestrator.py
```

A `SOAR_KILL_SWITCH` file halts any armed run immediately. See
`docs/SECURITY.md` §1 and `soar/README.md` for the full gating model before
ever setting `SOAR_DRY_RUN=0`.

## Security limitations

This repository's `configs/elk/` and `configs/pfsense/` are real,
credential-bearing mirrors of lab infrastructure, kept local and gitignored
by design — they are not meant to leave this machine. A broad secret scan
run during repository preparation (2026-08-22) found and remediated several
plaintext credentials that had drifted into tracked documentation; **some
credentials remain unrotated as of this writing** (see `docs/SECURITY.md`
for the complete, current list and what to do before any push). Read
`docs/SECURITY.md` before pushing this repository anywhere, including a
private remote.

## Report / reproducibility artifacts

- `report/benchmark-report.tex`, `report/Local_LLM_Benchmark.pdf` — the
  written report and its LaTeX source.
- `ai/results/` — model-benchmark and deployment-latency results backing
  the report's hardware/model comparisons; raw per-case outputs
  (`ai/results/raw*/`) are gitignored (large, regenerable via
  `ai/benchmark.py`) but the aggregate summaries are tracked.
- `soar/review_overlays/FINAL_LABELS_v1.json` and `DATASET_B_LOCK_v1.json`
  — the locked Dataset B ground truth (60 cases) and its content hashes,
  used for the safety-metric numbers in the report. **Do not modify.**
- `soar/L1-L2-SAFETY-AUDIT.md` — the full verification trail, including
  every live-capture test run and its output.
