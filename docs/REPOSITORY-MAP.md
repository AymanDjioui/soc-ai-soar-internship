# Repository map

What each top-level path is, and whether it's tracked in git. This repo
went through two hygiene passes: 2026-08-22 (secret-scan and gitignore
rules) and 2026-08-25 (scope cut — removed everything that wasn't the SOAR
pipeline, TheHive/Cortex integration, the AI agent, or the red-team MCP
server, so the repo is exactly what's needed to understand or continue the
project, nothing else). Superseded planning docs, session-by-session notes,
and a generated knowledge-graph cache were removed from tracking in the
second pass; their content was consolidated into `PROJECT-ARCHIVE-LOCAL.md`
first so no context is lost — that file is gitignored and stays local only.

## Source code

| Path | What | Tracked? |
|---|---|---|
| `soar/` | The SOAR orchestrator: L1/L2 policy gate (`l1_policy.py`), idempotency store (`idempotency.py`), the two orchestrator entry points (`agent_orchestrator.py` — agentic/tool-calling version; `e2e_soc_orchestrator.py` — the linear pipeline version), pfSense verification (`pfsense_verify.py`), sanitization (`sanitization.py`), dataset/review tooling (`review_dataset.py`, `review_rubric.py`, `export_dataset_b_candidates*.py`), and 12 `test_*.py` suites (632 checks total). | Mostly yes — see exceptions below |
| `ai/` | Prompt versions (`prompts/`), the benchmark harness (`benchmark.py`), rescoring (`rescore.py`), results (`results/`), and the Dataset A/B test fixtures (`testset/`). | Mostly yes — see exceptions below |
| `redteam-mcp/` | A custom MCP server exposing offensive tools (nmap, sqlmap, impacket, netexec, msfvenom, ...) against a Kali box, scoped to the lab's own IP ranges only. Used to generate real attack traffic for detection validation. | Source yes; the bundled `burp-proxy/mcp-proxy-all.jar` (15 MB third-party binary) is not. |

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
| `README.md` | Project overview, architecture, safety model, setup pointer. Start here. | Tracked. |
| `CLAUDE.md` | Project context/instructions for AI coding assistants working in this repo (ownership, architecture history, standing rules). Doubles as a concise project history. | Tracked. |
| `soar/L1-L2-SAFETY-AUDIT.md` | The authoritative incident/verification log for the SOAR safety model, including every credential-exposure incident and every live-capture test run. | Tracked. |
| `soar/README.md` | Usage reference for the orchestrator (env vars, commands, safety notes). | Tracked. |
| `docs/` (this directory) | `REPOSITORY-MAP.md` (this file), `SETUP.md`, `SECURITY.md`. | Tracked. |
| `PROJECT-ARCHIVE-LOCAL.md` (repo root) | Consolidated session-by-session working notes, superseded roadmap drafts, and the old `PROJECT-STATE.md` — kept as report-writing context. | **No — gitignored, local only.** |

## Report / demo artifacts

| Path | What | Tracked? |
|---|---|---|
| `report/` | LaTeX report source (`benchmark-report.tex`), a chapter draft (`ch9-autonomous-l1.md`), a coverage matrix, and a compiled PDF (`Local_LLM_Benchmark.pdf`). | Yes. |
| `demo/attack-scenarios.md` | Narrative description of the demo attack scenarios. | Yes. |
| `screenshots/` | Evidence screenshots/terminal captures organized by detection source (firewall/IDS, Juice Shop app) and by red-team scenario. No secrets found in any `.txt` capture during the secret scan. | Yes. |
| `Architecture.jpeg` | Architecture diagram. | Yes. |

## Not present

There is no `LICENSE` file and no `CONTRIBUTING.md`. Both are out of scope
for this pass (not requested), but worth deciding on before any wider
sharing of the repository, even privately.
