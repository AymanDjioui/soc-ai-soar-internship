# Local artifacts manifest

Everything below stays on this machine and is not pushed to git, per the
`.gitignore` rules added 2026-08-22. No sensitive values are included here —
this is an inventory of *what* and *why*, not *contents*.

## Python environments (regenerable)

| Path | Why local |
|---|---|
| `soar/.venv/` | Standard Python virtual environment. Rebuild with `python3 -m venv .venv && pip install ...` — see `docs/SETUP.md`. |
| `**/__pycache__/`, `*.pyc` | Bytecode cache, regenerated automatically on every run. |

## Credential-bearing operational configs (real, unredacted, never leave this machine)

| Path | Why local |
|---|---|
| `configs/elk/.env` | Real Elasticsearch/Kibana stack passwords. Sanitized template: `configs/elk/.env.example`. |
| `configs/elk/docker-compose.yml` | Real Kibana encryption keys hardcoded inline. Sanitized template: `configs/elk/docker-compose.yml.example`. |
| `configs/elk/elastalert/config.yaml` | Real TheHive API key + Elasticsearch password. Sanitized template: `configs/elk/elastalert/config.yaml.example`. |
| `configs/pfsense/` (entire directory) | Real pfSense config.xml export (bcrypt admin-password hash + full firewall/NAT/interface config) and two shell scripts. Kept as a local reference mirror per a standing project decision (see `CLAUDE.md`) — explicitly never for external sharing, private repo included. |
| `.mcp.json`, `.claude/settings.local.json`, `.codex/config.toml` | Local AI-tool wiring. `settings.local.json` was found to carry hardcoded SSH passwords in its Bash permission allow-list — see `docs/SECURITY.md`. |

**Resolved and no longer excluded:** `/e2e_soc_orchestrator.py` (repo root)
previously had a hardcoded TheHive API key and was listed here as a local,
credential-bearing artifact. That key was manually revoked 2026-08-22 and
the file sanitized to read `THEHIVE_API_KEY` from the environment only,
failing closed if unset — see `docs/SECURITY.md`. It is proposed for
tracking like any other source file (see `docs/REPOSITORY-MAP.md` for its
status as a superseded prototype kept for historical reference).

## Runtime / operational state (real lab activity, not source)

| Path | Why local |
|---|---|
| `soar/idempotency_store/`, `soar/LIVE_CHECKPOINT_*/` | Idempotency records from real (including live-armed) orchestrator runs; may reference real, masked TheHive case numbers. |
| `soar/soar_audit.jsonl` | The orchestrator's operational audit log. |
| `soar/KILL_SWITCH` | The runtime kill-switch file itself (its mere presence halts armed runs) — not meaningful outside a running instance. |
| `soar/backups/`, `soar/e2e_soc_orchestrator.py.bak-*` | Superseded snapshots of the orchestrator, kept locally as a rollback reference. The current file is what's tracked. |

## Review-process working state (drafts; only the locked outputs are tracked)

| Path | Why local |
|---|---|
| `soar/review_overlays/reviewer-a.jsonl`, `reviewer-b.jsonl`, `adjudication.jsonl`, `ASSIGNMENTS.json`, `ASSIGNMENTS_v2.json`, `ADJUDICATION-PROPOSALS.json`, `reviewer-b-PROPOSALS.json` | In-progress dual-review and adjudication working files for Dataset B labeling. Superseded by the two tracked, locked outputs: `FINAL_LABELS_v1.json` and `DATASET_B_LOCK_v1.json`, whose content hashes cover several of these files as evidence of what fed into the lock — see `DATASET_B_LOCK_v1.json`'s own `content_hashes_sha256` block. |

## Real historical case data (sanitized but not yet formally cleared)

| Path | Why local |
|---|---|
| `ai/testset/dataset_b_candidates/`, `ai/testset/dataset_b_candidates_v2/` | Pseudonymized/redacted exports derived from real historical TheHive cases (see `soar/export_dataset_b_candidates*.py` for the sanitization pipeline). "Sanitized" and "cleared for commit" are treated as distinct here — these directories stay local until a dataset is formally reviewed, approved, and locked in the manner Dataset B v2 already was. The **locked, aggregate outputs** for the already-approved dataset (`FINAL_LABELS_v1.json`, `DATASET_B_LOCK_v1.json`) are tracked; the underlying per-case candidate records are not. |
| `ai/testset/**/raw_export/`, `**/*.raw.json`, `**/dataset_b_raw/` | Pre-sanitization raw exports. Must never be committed under any circumstance — this is a hard rule in `soar/sanitization.py`'s own design, not just a `.gitignore` convenience. |

## Large / regenerable results

| Path | Size (approx.) | Why local |
|---|---|---|
| `ai/results/raw/`, `ai/results/raw-ec2/`, `ai/results/raw-gpu/`, `ai/results/raw-gpu-all/`, `ai/results/raw-gpu-exp3/` | ~230K–310K each | Raw per-case, per-model, per-prompt-version benchmark output. Regenerable via `ai/benchmark.py` against the same prompts/testset. The aggregate summaries (`ai/results/*.md`, `ai/results/results*.csv`) that these feed into ARE tracked. |
| `redteam-mcp/burp-proxy/mcp-proxy-all.jar` | ~15 MB | Third-party binary (Burp Suite MCP proxy), not project source. Not meaningfully version-controllable; re-obtain from its original source if needed. |
| `graphify-out/cache/` | — | AST/semantic caches for the codebase knowledge graph, regenerated automatically on the next `/graphify` run. |

## Backups / temp files

| Path | Why local |
|---|---|
| `*.bak`, `*.bak-*`, `*.bak.*` | Ad hoc file backups made during editing sessions. |
| `.DS_Store`, `Thumbs.db`, `*.swp`, `*.swo`, `*~` | Editor/OS artifacts. |

## Not yet decided (flagged, not excluded)

- `graphify-out/graph.html`, `graph.json`, `cost.json`, `manifest.json`,
  `GRAPH_REPORT.md`, and the dotfiles alongside them are currently tracked
  (only `graphify-out/cache/` is excluded, per this pass's explicit scope).
  They are themselves a regenerable artifact of running `/graphify` — see
  `REPO-CLEANUP-REPORT.md` for a recommendation to reconsider this in a
  future pass.
