# Repository map

What each top-level path is, and whether it's tracked in git. "Tracked"
means it survives the `.gitignore` rules added during the 2026-08-22
repo-hygiene pass — see `REPO-CLEANUP-REPORT.md` for the full proposed
tracked/ignored lists.

## Source code

| Path | What | Tracked? |
|---|---|---|
| `soar/` | The SOAR orchestrator: L1/L2 policy gate (`l1_policy.py`), idempotency store (`idempotency.py`), the two orchestrator entry points (`agent_orchestrator.py` — agentic/tool-calling version; `e2e_soc_orchestrator.py` — the linear pipeline version), pfSense verification (`pfsense_verify.py`), sanitization (`sanitization.py`), dataset/review tooling (`review_dataset.py`, `review_rubric.py`, `export_dataset_b_candidates*.py`), and 12 `test_*.py` suites (632 checks total). | Mostly yes — see exceptions below |
| `ai/` | Prompt versions (`prompts/`), the benchmark harness (`benchmark.py`), rescoring (`rescore.py`), results (`results/`), and the Dataset A/B test fixtures (`testset/`). | Mostly yes — see exceptions below |
| `redteam-mcp/` | A custom MCP server exposing offensive tools (nmap, sqlmap, impacket, netexec, msfvenom, ...) against a Kali box, scoped to the lab's own IP ranges only. Used to generate real attack traffic for detection validation. | Source yes; the bundled `burp-proxy/mcp-proxy-all.jar` (15 MB third-party binary) is not. |
| `/e2e_soc_orchestrator.py` (repo root) | An early prototype pipeline (mock-LLM triage, no deterministic policy gate, no idempotency, no kill switch) predating `soar/e2e_soc_orchestrator.py`, which is the actively maintained, hardened orchestrator this project actually uses. Previously excluded for a hardcoded TheHive API key; that key has been manually revoked (2026-08-22) and the file sanitized to read `THEHIVE_API_KEY` from the environment only, failing closed if unset — see `docs/SECURITY.md`. Kept as a historical/reference artifact, not a second production entry point. | Yes (no longer excluded). |

### Exceptions inside `soar/` and `ai/` (not tracked, and why)

- `soar/.venv/`, `soar/__pycache__/`, `**/__pycache__/`, `*.pyc` — regenerable.
- `soar/idempotency_store/`, `soar/LIVE_CHECKPOINT_*/`, `soar/soar_audit.jsonl` — real runtime/operational state from live runs, not source.
- `soar/backups/`, `soar/e2e_soc_orchestrator.py.bak-*` — superseded snapshots of the orchestrator; the current file is what's tracked.
- `soar/review_overlays/*` **except** `FINAL_LABELS_v1.json` and `DATASET_B_LOCK_v1.json` — everything else in that directory (`reviewer-a.jsonl`, `reviewer-b.jsonl`, `adjudication.jsonl`, `ASSIGNMENTS*.json`, `*-PROPOSALS.json`) is in-progress reviewer working state; only the two final, locked outputs are tracked.
- `ai/results/raw/`, `ai/results/raw-*/` — large, regenerable raw model-benchmark output; the aggregate `.md`/`.csv` summaries one level up in `ai/results/` are tracked.
- `ai/testset/dataset_b_candidates/`, `ai/testset/dataset_b_candidates_v2/` — sanitized-but-unlocked candidate records derived from real historical TheHive cases; kept local until formally reviewed/locked. `ai/testset/dataset_a_draft/` and `ai/testset/dataset_a_synthetic/` (synthetic, not derived from real cases) are tracked.

## Configuration

| Path | What | Tracked? |
|---|---|---|
| `configs/elk/` | Real ELK stack config pulled from the live box: `docker-compose.yml`, `.env`, `elastalert/config.yaml`, `elastalert/patches/`, `logstash/`. Kept unredacted locally per a standing project decision (see `CLAUDE.md`) — **never meant to leave this machine.** | The three files with live credentials are gitignored (each has a sanitized `.example` sibling that IS tracked). `logstash/pipeline/logstash.conf` uses `${ELASTIC_PASSWORD}`-style interpolation already and has no hardcoded secret, so it's tracked as-is. `elastalert/patches/thehive.py` (a patched vendor file, no secrets) is tracked. |
| `configs/pfsense/` | Real pfSense `config.xml` export (full firewall/NAT/interface config + a bcrypt admin-password hash), plus two small shell scripts. Same "never publish" standing decision as above. | No — entire directory gitignored. |
| `.env.example` | Root-level template documenting every environment variable the project's Python code actually reads (compiled by grepping `os.environ` across `soar/`, `ai/`, `redteam-mcp/`). | Yes. |
| `.mcp.json`, `.claude/settings.local.json`, `.codex/config.toml` | Local AI-tool wiring (MCP server commands, Claude Code permission allow-list, Codex MCP config). `.claude/settings.local.json` was found to contain hardcoded SSH passwords in its Bash permission strings (see `docs/SECURITY.md`). | No — all gitignored. |

## Documentation

| Path | What | Notes |
|---|---|---|
| `PROJECT-STATE.md` | The living, current-state document — architecture, credentials reference (redacted), what's done/not-done, house rules. The single most up-to-date file in the repo. | Tracked; sanitized during this pass (see `docs/SECURITY.md`). |
| `CLAUDE.md` / `AGENTS.md` | Byte-identical project instructions for AI coding assistants (Claude Code reads `CLAUDE.md`; other tools follow the `AGENTS.md` convention). Intentional duplication, not accidental — if you edit one, edit both. | Both tracked. |
| `ROADMAP.md` → `FINAL-ROADMAP.md` → `AGENT-ROADMAP.md` | Three successive planning documents, each explicitly marking itself as superseding the last for *task planning* while noting the earlier ones remain valid for background rationale. `notes/archive-roadmap-2026-07-20.md` is one generation further back. See `REPO-CLEANUP-REPORT.md` for a recommendation on consolidating the "which roadmap is current" signal. | All tracked (historical value); none deleted or reordered. |
| `AI-LAYER-PLAN.md`, `REPORT-PLAN.md`, `TASK-SPLIT.md`, `PENTEST-PLAN.md` | Companion planning docs for the AI layer, the final report, the Ayman/Badr task split, and the red-team attack chains, respectively. | Tracked. |
| `MY-NOTES.md` | Ayman's synthesized, topic-organized writeup of the ELK/AI side of the project, written as a readable companion to the session-by-session `notes/`. | Tracked. |
| `TOMORROW-TODO.md`, `RUNBOOK-2026-08-11.md` | Dated, session-scoped working documents (a TODO list, a runbook for a specific working session). Historical value, not living docs. | Tracked. |
| `notes/1.md` … `notes/20.md` | Session-by-session working log, chronological. `notes/6.md` was sanitized during this pass (a real API key value was quoted in prose; see `docs/SECURITY.md`). | Tracked. |
| `notes/badr_phase1_report (1).md` / `(2).md` | Two versions of the same report; `(2)` is a superset of `(1)` (619 vs 284 lines, `(1)`'s content is a strict prefix). Likely a duplicate-download artifact. See `REPO-CLEANUP-REPORT.md`. | Both currently tracked (not deleted per this pass's constraints); flagged for manual consolidation. |
| `soar/L1-L2-SAFETY-AUDIT.md` | The authoritative incident/verification log for the SOAR safety model, including the credential-exposure incidents referenced throughout this pass. | Tracked. |
| `soar/README.md` | Usage reference for the orchestrator (env vars, commands, safety notes). | Tracked. |
| `docs/` (this directory) | `README.md`, `REPOSITORY-MAP.md` (this file), `SETUP.md`, `SECURITY.md` — added by this pass. | Tracked. |

## Report / demo artifacts

| Path | What | Tracked? |
|---|---|---|
| `report/` | LaTeX report source (`benchmark-report.tex`), a chapter draft (`ch9-autonomous-l1.md`), a coverage matrix, and a compiled PDF (`Local_LLM_Benchmark.pdf`). | Yes. |
| `demo/attack-scenarios.md` | Narrative description of the demo attack scenarios. | Yes. |
| `screenshots/` | Evidence screenshots/terminal captures organized by detection source (firewall/IDS, Juice Shop app) and by red-team scenario. No secrets found in any `.txt` capture during the secret scan. | Yes. |
| `Architecture.jpeg` | Architecture diagram. | Yes. |
| `graphify-out/` | A generated knowledge-graph of this codebase (nodes, `graph.html`, `GRAPH_REPORT.md`). `graphify-out/cache/` (AST/semantic caches, regenerable) is gitignored; the rest is tracked as-is per this pass's explicit instructions, though it is itself a regenerable artifact and a candidate for exclusion in a future pass (see `REPO-CLEANUP-REPORT.md`). | Partial (cache excluded). |

## Not present

There is no `LICENSE` file and no `CONTRIBUTING.md`. Both are out of scope
for this pass (not requested), but worth deciding on before any wider
sharing of the repository, even privately.
