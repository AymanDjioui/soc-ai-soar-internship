# Setup

This covers getting the offline pieces of this project running (tests,
dataset tooling, AI benchmark replay). It does **not** cover standing up the
live pfSense/ELK/TheHive/Cortex/GPU infrastructure — that's a full lab build
described narratively in `PROJECT-STATE.md` and `notes/`, not a scripted
install.

## Prerequisites

- Python 3.12 (the committed venv metadata in `soar/.venv/pyvenv.cfg` targets
  3.12; other 3.x versions likely work but are untested)
- `pip`
- For live integration only (not required for offline tests): SSH access to
  the pfSense box, a TheHive instance + API key, an Elasticsearch endpoint,
  and Docker (for the ELK stack in `configs/elk/`)

## Offline setup (tests, dataset tooling)

```bash
cd soar
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt   # if present; otherwise see
                                                # imports at the top of soar/*.py
```

> The repo's own `soar/.venv/` (if present locally) already has a working
> environment — `soar/.venv/bin/python3` — used throughout this project's own
> test runs rather than a system Python. See
> `LOCAL-ARTIFACTS-MANIFEST.md` for why the venv itself is not committed.

## Running the test suite

There is no shared pytest runner — each `soar/test_*.py` is a standalone
script with its own PASS/FAIL counter and process exit code:

```bash
cd soar
for f in test_*.py; do
  echo "=== $f ==="
  ./.venv/bin/python3 "$f"
done
```

Expected result (verified 2026-08-22, see `REPO-CLEANUP-REPORT.md`):
**632 checks passed, 0 failed**, across 12 files. None of these tests touch
live infrastructure — they exercise the L1/L2 policy gate, idempotency
store, sanitization, and dataset/review pipeline against synthetic and
locked fixture data only.

## Environment variables

Copy `.env.example` to `.env` (or export the variables directly) and fill in
real values. **Never commit a filled-in `.env`.** See `docs/SECURITY.md` for
which values are currently live/rotated and `.env.example` itself for the
full variable list with inline documentation of what each one controls.

```bash
cp .env.example .env
# edit .env with real values
set -a; source .env; set +a
```

## ELK stack (Docker)

```bash
cd configs/elk
cp .env.example .env                                    # fill in real values
cp docker-compose.yml.example docker-compose.yml         # fill in real values
cp elastalert/config.yaml.example elastalert/config.yaml # fill in real values
docker compose up -d
```

The real `.env`, `docker-compose.yml`, and `elastalert/config.yaml` are
gitignored (see `docs/SECURITY.md` for why) — the `.example` files are the
tracked source of truth for what settings are required.

## pfSense

`configs/pfsense/` is a **read-only reference mirror** (config.xml export +
two scripts) pulled from the live box for documentation purposes, kept
unredacted locally per a standing project decision and never pushed (the
whole directory is gitignored). There is no scripted pfSense install here —
consult `PROJECT-STATE.md` and `notes/` for the actual lab network layout
(WAN/LAN/DMZ, Suricata interface placement, the Redis-based EVE delivery
pipeline).

## Shadow-mode / dry-run deployment

Before any orchestrator run that could touch the firewall, confirm dry-run
is active:

```bash
SOAR_DRY_RUN=1 SOAR_ALERT_ID="~<alert-id>" ./.venv/bin/python3 e2e_soc_orchestrator.py
```

`SOAR_DRY_RUN` / `SOAR_AGENT_DRY_RUN` default to armed-off behavior only if
explicitly set — see `soar/README.md` and `docs/SECURITY.md` §1 for the full
L1/L2 gating model, the kill switch, and why "the script printed success"
is never sufficient verification in this project (always check pfSense
tables / Elasticsearch counts / Cortex job status directly).

## Red-team MCP server (offensive tooling, lab-scoped)

```bash
cd redteam-mcp
pip install -r requirements.txt
```

Requires `KALI_HOST` / `KALI_USER` / `KALI_PASS` (see `.env.example`) and
only operates against the lab's own IP ranges — see `redteam-mcp/README.md`
for the scope guard.
