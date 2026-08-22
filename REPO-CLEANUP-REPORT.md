# Repository Cleanup Report — private-GitHub preparation pass

**Date:** 2026-08-22 (3 passes)
**Scope:** Repository hygiene and private-GitHub readiness. Files are now
**staged** (third pass) — see the addendum immediately below. Nothing
committed, no remote created, no live infrastructure accessed, no
credentials used for authentication or created, Dataset B locked
contents/hashes untouched, Phase 8 not started.

---

## Addendum — third pass (same day): remaining TheHive keys resolved, staged for commit

The user manually revoked the two remaining TheHive API key values (the
`configs/elk/elastalert/config.yaml` key and the `notes/6.md` key) — all
**three** TheHive key exposures found in this repository are now revoked.
Work done in this pass:

1. **Documentation updated, no values recorded.** `docs/SECURITY.md` and
   this report's §2 were restructured: all three TheHive key incidents now
   appear under "Resolved incidents" (date, file, remediation, verification
   only — no key values, old or new). Both documents now state explicitly
   that **new, dedicated service credentials will be created only during
   deployment (Phase 8)**, not as part of repository preparation.
2. **Secret scan re-run against exactly the 235 files `git add .` would
   stage** (verified via `git add --dry-run .`, matched 1:1 against the
   established tracked-file list). Decisive patterns (`password=`,
   `api_key=`, `Bearer `, JWT, AWS keys, private-key blocks) plus a
   dedicated check for the specific known-revoked key values.
3. **A real finding**: the known-value check turned up `notes/12.md`,
   containing plaintext copies of **two already-known, already-revoked**
   TheHive key values (the one originally in the root orchestrator script,
   and the one originally in `configs/elk/elastalert/config.yaml` /
   `notes/6.md`) — quoted in prose describing a 2026 incident where a stale
   per-rule `hive_apikey` override caused silent `401` failures. This file
   had been missed by **three prior scanning passes** because the text used
   a parenthetical prose style (`` key (`VALUE`) ``) rather than a
   `key=value`/`key: value` pattern, which is what the decisive regexes
   look for. It was caught this time only because task 2 additionally
   required checking the literal, specific known-revoked values (not just
   generic patterns) against the exact staged file set. **Redacted
   immediately** (values replaced with `${THEHIVE_API_KEY}` /
   `${THEHIVE_API_KEY_STALE}` placeholders + a dated note, same convention
   used elsewhere), re-staged, and the full staged snapshot re-verified
   clean. No other tracked/staged file contains either value (confirmed
   with a whole-tree, not just staged-set, search). Both values correspond
   to already-revoked keys — this was not a new, unrevoked exposure.
4. **Repository staged**: `git add .` run (not `git add -A`, no `--force`)
   after the fix above. **235 files, 57,286 insertions, ~5.41 MB.** Nothing
   committed.
5. **Full re-verification after staging**: the actual staged blobs were
   extracted via `git checkout-index` into a clean directory (bypassing the
   working tree entirely, so this checks exactly what would be committed)
   and re-scanned — clean. Every staged path independently confirmed
   *not* ignored via `git check-ignore`. Dataset B's 8 referenced files
   plus the lock file itself re-hashed — byte-identical. Test suites
   **not** re-run this pass: no executable or test file changed (only
   `notes/12.md`, `docs/SECURITY.md`, `REPO-CLEANUP-REPORT.md`) — last
   verified 632/632 passing in the prior pass, and that result stands
   since no test-relevant file changed since.

**Note on methodology**: this environment's `grep` is an alias for `ugrep`,
which appears to apply `.gitignore`-aware filtering automatically during
plain recursive scans of the repository (`grep -r . --exclude-dir=.git`
from the repo root), silently skipping gitignored paths. This has no
bearing on the staged-file scans in this report (which either enumerate
files explicitly or scan an extracted, `.gitignore`-free snapshot), but is
worth knowing if reproducing these commands manually.

---

## Addendum — second pass (same day): root orchestrator key resolved

The user manually revoked the TheHive API key that had been hardcoded in
`/e2e_soc_orchestrator.py` (repo root) — hard blocker #1 in the original
version of this report, below. Follow-up work done in this pass:

1. **`e2e_soc_orchestrator.py` sanitized.** The hardcoded key is gone from
   source; the file now reads `THEHIVE_API_KEY` from the environment only
   (no default, no fallback) and fails closed with a clear `sys.exit` if
   the variable is unset. Verified: no literal key-shaped string remains in
   the file; the fail-closed path was exercised directly (raises
   `SystemExit` with the variable unset, proceeds past the check with it
   set). See `docs/SECURITY.md` "Resolved incidents."
2. **Consolidation evaluated, not performed.** `soar/e2e_soc_orchestrator.py`
   (1,234 lines — hardened production orchestrator: deterministic policy
   gate, idempotency, kill switch, dry-run) and the root file (395 lines —
   an earlier mock-LLM prototype with none of those safety mechanisms) are
   different generations of the tool, not a config/secrets-only diff.
   Merging them would be a substantial behavioral rewrite, which conflicts
   with this task's "preserve the script's existing behavior otherwise."
   Instead, the root file now carries a header note identifying it as a
   superseded, historical-reference prototype and pointing to the `soar/`
   copy as the maintained implementation — this addresses "avoid
   maintaining two inconsistent implementations" without changing behavior.
3. **`.gitignore` updated**: `/e2e_soc_orchestrator.py` is no longer
   excluded — it is sanitized and now proposed for tracking like any other
   source file. Tracked-file count is now **235 files, ~5.51 MB** (was 228
   / ~5.4 MB).
4. **`docs/SECURITY.md`, `docs/REPOSITORY-MAP.md`,
   `LOCAL-ARTIFACTS-MANIFEST.md` updated** to move this item from "hard
   blocker" to "resolved incident" and record the root file's new tracked
   status. No key value — old or new — appears anywhere in this repository
   or in this report.
5. **Full re-verification performed**: secret scan re-run against every
   currently-proposed-tracked file (235 files, including the newly-tracked
   root script and `graphify-out/`, checked separately since its minified
   JSON/HTML content produces noisy — and confirmed false-positive —
   base64-shaped matches); all 12 `soar/test_*.py` suites re-run (**632
   passed, 0 failed**); all 8 files referenced by
   `DATASET_B_LOCK_v1.json`'s `content_hashes_sha256` block, plus that lock
   file itself, re-hashed and confirmed byte-identical to their recorded
   values.

**Two TheHive API key incidents remained open after this pass** — see the
third-pass addendum below, where both were resolved.

---

## 1. Executive summary

- Repo was **not previously a git repository**. It now is (`git init -b
  main` run; **nothing staged or committed**).
- A broad secret scan found **8 categories of real, plaintext credentials**
  across tracked documentation and real operational config files — 3 of
  them (a hardcoded API key in a root-level script, a stale note claiming a
  key was "exposed in `notes/8.md`" that turned out not to be there anymore,
  and a full plaintext credentials table in `PROJECT-STATE.md`) were **not
  previously documented anywhere in this repo's own incident history**
  (`soar/L1-L2-SAFETY-AUDIT.md`). See §2.
- 6 plaintext secrets in **tracked documentation** were redacted in place
  this pass (value removed, replaced with an env-var placeholder + a dated
  note), per the task's explicit authorization to sanitize documentation.
  **No credential was rotated** — that requires live access this pass does
  not have and was not authorized to use.
- `.gitignore` was extended so that every remaining real credential-bearing
  file (`configs/elk/*`, `configs/pfsense/`, `.mcp.json`,
  `.claude/settings.local.json`, etc.) is excluded from tracking, with
  sanitized `.example` templates added where useful. (The root
  `/e2e_soc_orchestrator.py` was originally on this list too; it has since
  been sanitized and removed from it — see the Addendum.)
- **632/632 offline tests pass, 0 failures**, across the 12 `soar/test_*.py`
  suites — matches the count already recorded in
  `soar/review_overlays/DATASET_B_LOCK_v1.json`.
- Estimated tracked size: **~5.51 MB** of ~45 MB total working tree (235
  files tracked as of the second pass, ~2,100 excluded — mostly
  `soar/.venv/`, `ai/results/raw*/`, and `graphify-out/cache/`).
- **Second-pass update**: the root `/e2e_soc_orchestrator.py` hardcoded-key
  incident (originally hard blocker #1) is **resolved** — key manually
  revoked by the project owner, file sanitized to read `THEHIVE_API_KEY`
  from the environment only with a fail-closed check, no longer gitignored.
  See the Addendum above and `docs/SECURITY.md` "Resolved incidents."
- **Third-pass update**: the remaining two TheHive API key incidents are
  **also now resolved** — both manually revoked by the project owner. All
  three TheHive key exposures found in this repository are now revoked; see
  the third-pass addendum below and `docs/SECURITY.md` §2. A handful of
  unrelated, non-TheHive credentials (SSH/Elasticsearch/Kibana passwords)
  remain unrotated — see §2.2 and §2.5 for the current checklist.

---

## 2. Secret scan — summary (all values redacted)

Method: `grep -rniI` across the full tree (excluding `.venv`, `__pycache__`,
`.git`, `graphify-out` generated caches, and binary/media files) for
password/API-key/token/Bearer/JWT/AWS/private-key/Gmail-app-password shapes,
followed by manual review of every hit and a targeted second pass for
prose-style `label` / `password` patterns that the first pass's regexes
missed (this is how the `PROJECT-STATE.md` credentials table and the
demo-account password were found — see below).

### 2.1 Resolved incidents — all 3 TheHive API key exposures

| Date | File(s) | Credential type | Remediation | Verification |
|---|---|---|---|---|
| 2026-08-22 | `e2e_soc_orchestrator.py` (repo root) | TheHive API key, previously hardcoded in source | Key manually revoked by the project owner. Source sanitized: reads `THEHIVE_API_KEY` from the environment only, no default/fallback, fails closed via `sys.exit` if unset. | No literal key-shaped string remains in the file (confirmed by pattern scan); fail-closed path exercised directly; file no longer excluded in `.gitignore`. See `docs/SECURITY.md`. |
| 2026-08-22 | `configs/elk/elastalert/config.yaml` (line 22, `hive_apikey`); duplicated in `PROJECT-STATE.md` (pre-redaction, was line 589) | A second, distinct TheHive API key — the "open, unresolved blocker" from `soar/L1-L2-SAFETY-AUDIT.md` §21 | Key manually revoked by the project owner. Documentation copy was already redacted to `${THEHIVE_API_KEY}` in an earlier pass; the real config file stays gitignored per standing project policy (unrelated to the revocation). | Documentation copy confirmed to contain no literal value; real config file confirmed still excluded via `git check-ignore`. |
| 2026-08-22 | `notes/6.md` (pre-redaction, was line 156) | A third, distinct TheHive API key value, quoted in incident-history prose | Key manually revoked by the project owner. Documentation was already redacted to `${THEHIVE_API_KEY}` in an earlier pass. | Documentation copy confirmed to contain no literal value. |

**No key value — old or new — is recorded anywhere in this repository or
in this report.** All three revocations were performed by the project
owner outside of this tooling; this tooling did not access TheHive or any
other live system, and did not request or create a replacement credential
at any point. **New, dedicated service credentials (a fresh TheHive API
key, and any other service accounts this project needs) will be created
only during deployment (Phase 8)** — not as part of repository preparation.
Every config file that references one of these three keys
(`configs/elk/elastalert/config.yaml`, any local `.env`) is expected to be
non-functional against live TheHive until then; that is intended, not a
defect.

### 2.2 Hard blockers still open — unrelated to TheHive, not addressed this turn

| # | File | Line(s) | Credential type | Remediated? |
|---|---|---|---|---|
| 1 | `PROJECT-STATE.md` (pre-redaction) | was 96–98 | ELK SSH password, Elasticsearch password, pfSense admin password — a 3-row plaintext credentials table | Documentation redacted, replaced with `${ELK_SSH_PASSWORD}` / `${ELASTIC_PASSWORD}` / `${PFSENSE_PASSWORD}`. Underlying credentials not rotated. |
| 2 | `PROJECT-STATE.md` (pre-redaction) | was 66 | Kali attacker-box SSH password | Documentation redacted, replaced with `${KALI_PASSWORD}`. Underlying credential not rotated. |
| 3 | `PROJECT-STATE.md`, `TOMORROW-TODO.md`, `AGENT-ROADMAP.md` (pre-redaction) | was 28 / 64 / 224 | TheHive demo-account **password** (`soc-l2@thehive.local`) — 3 occurrences. (The demo account's password, not an API key — grouped here since it's not one of the 3 resolved key incidents.) | All three redacted, replaced with `${SOC_L2_DEMO_PASSWORD}`. Underlying password not rotated. |
| 4 | `RUNBOOK-2026-08-11.md` (pre-redaction) | was 42, 47, 67 | Elasticsearch password, inlined in 3 example `curl` commands | Replaced with `"$ELASTIC_PASSWORD"` shell-variable references. Underlying credential not rotated. |
| 5 | `configs/elk/docker-compose.yml` | 42–44 | 3 hardcoded Kibana encryption keys (`XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY`, `XPACK_SECURITY_ENCRYPTIONKEY`, `XPACK_REPORTING_ENCRYPTIONKEY`) | File deliberately kept real+local (see §2.4); already documented as exposed since `notes/6.md`'s original session. Not rotated. |
| 6 | `configs/elk/.env` | — | Elasticsearch/Kibana stack passwords | Kept real+local; sanitized `.env.example` added. Not rotated. |
| 7 | `configs/pfsense/config.xml` | 30 | pfSense admin password as a **bcrypt hash** (not reversible plaintext, lower severity) | Kept real+local; whole directory gitignored per standing project decision. |
| 8 | `.claude/settings.local.json` | 4, 9 | SSH passwords (pfSense admin, Kali box) embedded in Bash permission allow-list strings | Gitignored. Not rotated. |

**Nothing in this table was rotated by this tooling.** These are separate,
non-TheHive credentials outside the scope of this turn's revocation. See
`docs/SECURITY.md` §3 for the current rotation checklist before any push.

### 2.3 Reviewed and confirmed clean (false positives)

- `soar/sanitization.py`, `soar/test_sanitization.py`,
  `soar/test_notifications.py`, `soar/test_replay_harness.py` — contain
  strings like `password: hunter2`, `api_key=sk-live-...`,
  `SuperSecret123!`, and a syntactically-valid-but-fake JWT. These are the
  project's **own** secret-redaction test fixtures (the code under test
  strips exactly these patterns), not leaked credentials.
- `soar/review_overlays/FINAL_LABELS_v1.json`,
  `soar/review_overlays/DATASET_B_LOCK_v1.json` — scanned in full; contain
  only case UIDs, SHA-256 content hashes, rubric metadata, and test counts.
  No raw case text, no IPs, no secrets.
- `ai/results/raw*/`, `ai/testset/dataset_b_candidates*/` — "password"
  matches are all LLM-generated summaries or raw log lines (e.g.
  `"Accepted password for root from <ip>"`) describing attacker behavior,
  not credentials.
- `soar/L1-L2-SAFETY-AUDIT.md`'s documented "12 Gmail-app-password-shaped
  matches" — reviewed at the time by the audit's own author, confirmed
  ordinary prose, not credentials.
- `.mcp.json` — local MCP server wiring only (script paths, a local port).
  No credential present; still gitignored as instructed.
- `TASK-SPLIT.md`'s claim that "TheHive API keys ... are exposed in
  `notes/8.md`" — checked; **no key-shaped value currently exists in
  `notes/8.md`**. Either already cleaned up at some point and the
  cross-reference in `TASK-SPLIT.md` never updated, or the reference was
  always imprecise. Documentation drift, not a live credential — no action
  taken beyond noting it here.

### 2.4 Standing, pre-existing exception (not new, not touched)

Per `CLAUDE.md`, `configs/elk/` and `configs/pfsense/` were pulled from live
infrastructure and kept **unredacted on disk deliberately**, with an
explicit prior decision never to publish them externally. This pass honors
that decision by excluding every real file in those directories from git
(rather than editing or deleting them) and adds sanitized `.example`
templates alongside each one so the required configuration shape is still
documented for a reader. Nothing in `configs/` was edited.

### 2.5 Checklist before this repo is pushed anywhere (even private)

1. ~~Rotate/revoke the root `/e2e_soc_orchestrator.py` TheHive API key.~~
   **Done 2026-08-22** — see §2.1.
2. ~~Rotate/revoke the two remaining TheHive API key values.~~
   **Done 2026-08-22** — see §2.1. New TheHive credentials are deliberately
   not created here; that happens only during deployment (Phase 8).
3. Rotate the ELK SSH, Elasticsearch, pfSense admin, and Kali SSH passwords
   found in the (now-redacted-in-docs, but still-live) credentials table
   (§2.2, items 1, 2, 4), plus the Kibana encryption keys (§2.2 item 5) —
   still open, unrelated to the TheHive incidents.
4. Re-run the secret scan commands in this report after rotation to confirm
   zero remaining plaintext values in tracked files.
5. Only then `git add` / `git commit`.

Full detail and reasoning: `docs/SECURITY.md`.

---

## 3. Proposed tracked-file list

**235 files, ~5.51 MB**, by top-level location:

| Location | Tracked files | Notes |
|---|---|---|
| `ai/` | 65 | prompts, benchmark harness, results summaries, Dataset A fixtures |
| `soar/` | 48 | orchestrator source, policy/idempotency/sanitization modules, 12 test files, `L1-L2-SAFETY-AUDIT.md`, `README.md`, and the 2 locked Dataset B outputs |
| `configs/` | 35 | `elk/logstash/` (no secrets, uses `${ELASTIC_PASSWORD}`), `elk/elastalert/patches/`, `elk/elastalert/rules/`, and the 3 `.example` templates |
| `screenshots/` | 21 | detection evidence, no secrets found |
| `notes/` | 21 | session log (2 files sanitized) |
| `graphify-out/` | 12 | generated knowledge-graph artifacts, excluding `cache/`; re-verified clean this pass with a dedicated scan (see §2.3) |
| `report/` | 4 | LaTeX source + compiled PDF |
| `docs/` | 4 | `REPOSITORY-MAP.md`, `SETUP.md`, `SECURITY.md` — README lives at root |
| `redteam-mcp/` | 3 | `server.py`, `README.md`, `requirements.txt` (jar excluded) |
| `demo/` | 1 | `attack-scenarios.md` |
| Root-level `.md`/config/source files | ~21 | roadmaps, plans, `README.md`, `.gitignore`, `.env.example`, `LOCAL-ARTIFACTS-MANIFEST.md`, `REPO-CLEANUP-REPORT.md`, `CLAUDE.md`/`AGENTS.md`, `Architecture.jpeg`, and (as of this pass) the sanitized `e2e_soc_orchestrator.py` |

Full per-file breakdown: `docs/REPOSITORY-MAP.md`. Exact list: `git status
--porcelain --untracked-files=all | grep '^??'` from the repo root (nothing
is staged, so this is equivalent to "would be tracked if added").

## 4. Proposed ignored-file list

**~2,100 files excluded**, overwhelmingly:

| Location | Ignored files | What |
|---|---|---|
| `soar/` | 1,373 | almost entirely `soar/.venv/` (Python virtual environment — thousands of installed-package files), plus `__pycache__/`, `backups/`, `LIVE_CHECKPOINT_*/`, `review_overlays/*` (except the 2 locked files), `idempotency_store/`, `soar_audit.jsonl` |
| `ai/` | 633 | `ai/results/raw*/` (regenerable benchmark output) and `ai/testset/dataset_b_candidates*/` (real historical case data, not yet formally locked) |
| `graphify-out/` | 83 | `graphify-out/cache/` (AST/semantic caches) |
| `configs/` | 6 | the 3 real credential-bearing files + `configs/pfsense/`'s 3 files |
| Root | 3 | `.mcp.json`, `.codex/`, `.claude/settings.local.json` (`/e2e_soc_orchestrator.py` is no longer excluded — see Addendum) |
| `redteam-mcp/` | 2 | `burp-proxy/mcp-proxy-all.jar` (15 MB third-party binary), `__pycache__/` |

Full reasoning per category: `LOCAL-ARTIFACTS-MANIFEST.md`. Exact list:
`git status --ignored --porcelain --untracked-files=all | grep '^!!'` from
the repo root.

---

## 5. Repository size

| | Size |
|---|---|
| Total working tree (excl. `.git`) | 45 MB |
| Estimated tracked (proposed) | **~5.51 MB** (235 files) |
| `soar/.venv/` (excluded) | 20 MB |
| `redteam-mcp/burp-proxy/mcp-proxy-all.jar` (excluded) | 15 MB |
| `ai/results/raw*/` combined (excluded) | ~0.8 MB |
| `.git/` (after `git init`, nothing committed) | 120 KB |

---

## 6. `git status --short`

```
?? .env.example
?? .gitignore
?? AGENT-ROADMAP.md
?? AGENTS.md
?? AI-LAYER-PLAN.md
?? Architecture.jpeg
?? CLAUDE.md
?? FINAL-ROADMAP.md
?? LOCAL-ARTIFACTS-MANIFEST.md
?? MY-NOTES.md
?? PENTEST-PLAN.md
?? PROJECT-STATE.md
?? README.md
?? REPORT-PLAN.md
?? ROADMAP.md
?? RUNBOOK-2026-08-11.md
?? TASK-SPLIT.md
?? TOMORROW-TODO.md
?? ai/
?? configs/
?? demo/
?? docs/
?? e2e_soc_orchestrator.py
?? graphify-out/
?? notes/
?? redteam-mcp/
?? report/
?? screenshots/
?? soar/
```

Nothing is staged (`??` = untracked, no `A`/`M` entries). `git init -b main`
was run; no commit exists. (`e2e_soc_orchestrator.py` now appears as its
own untracked entry rather than being gitignored, since it is sanitized —
see Addendum.)

---

## 7. Top-level tree

```
.
├── ai/                 prompts, benchmark, results, testset
├── .claude/             (settings.local.json — gitignored)
├── .codex/               (gitignored)
├── configs/             elk/, pfsense/  (real files gitignored, .example tracked)
├── demo/                attack-scenarios.md
├── docs/                REPOSITORY-MAP.md, SETUP.md, SECURITY.md   [new]
├── graphify-out/         cache/ gitignored, rest tracked
├── notes/                1.md..20.md, archive-roadmap, badr_phase1_report (1)/(2)
├── redteam-mcp/          server.py, README.md, requirements.txt, burp-proxy/ (jar gitignored)
├── report/               benchmark-report.tex, ch9-autonomous-l1.md, coverage-matrix.md, PDF
├── screenshots/          detected-by-firewall-ids/, detected-by-juiceshop-app/, e4-scenario1-*
├── soar/                 orchestrator, policy, tests (632 checks), review_overlays/ (2 of 9 files tracked)
├── AGENT-ROADMAP.md
├── AGENTS.md             (identical to CLAUDE.md — dual AI-tool convention)
├── AI-LAYER-PLAN.md
├── Architecture.jpeg
├── CLAUDE.md
├── e2e_soc_orchestrator.py   [tracked — sanitized this pass, see Addendum]
├── .env.example          [new]
├── FINAL-ROADMAP.md
├── .gitignore            [extended this pass]
├── LOCAL-ARTIFACTS-MANIFEST.md   [new]
├── .mcp.json             (gitignored)
├── MY-NOTES.md
├── PENTEST-PLAN.md
├── PROJECT-STATE.md      (sanitized this pass — see §2.2)
├── README.md             [new]
├── REPO-CLEANUP-REPORT.md   [new, this file]
├── REPORT-PLAN.md
├── ROADMAP.md
├── RUNBOOK-2026-08-11.md (sanitized this pass — see §2.2)
├── TASK-SPLIT.md
└── TOMORROW-TODO.md
```

---

## 8. Test suite

```
CONTAINMENT VERIFICATION TESTS:      50 passed, 0 failed
CORTEX METADATA TESTS:               26 passed, 0 failed
IDEMPOTENCY TESTS:                   34 passed, 0 failed
PHASE 1 TESTS:                       57 passed, 0 failed
L2 ASSIGNMENT TESTS:                 87 passed, 0 failed
NOTIFICATION TESTS:                  96 passed, 0 failed
PFSENSE VERIFY TESTS:                23 passed, 0 failed
PHASE 7D TESTS:                      49 passed, 0 failed
REPLAY HARNESS TESTS:                66 passed, 0 failed
REVIEW DATASET TESTS:                32 passed, 0 failed
SANITIZATION TESTS:                  38 passed, 0 failed
TRUEPOSITIVE CLOSURE TESTS:          74 passed, 0 failed
------------------------------------------------------------
GRAND TOTAL:                        632 passed, 0 failed
```

Run via `cd soar && for f in test_*.py; do ./.venv/bin/python3 "$f"; done`
(no shared pytest runner exists — each file has its own counter/exit code,
consistent with `soar/L1-L2-SAFETY-AUDIT.md`'s documented convention). All
12 exit codes were 0; no tracebacks. Matches the count already recorded in
`soar/review_overlays/DATASET_B_LOCK_v1.json`'s `test_suite` block exactly
— **calculated independently in this pass, not assumed.**

---

## 9. Duplicate / obsolete file findings (recommendations only — nothing moved or deleted)

| Finding | Detail | Recommendation |
|---|---|---|
| `CLAUDE.md` / `AGENTS.md` | Byte-identical (verified with `diff`). Appears intentional — Claude Code reads `CLAUDE.md`, other tools follow the `AGENTS.md` convention. | Keep both; document the "edit one, edit both" requirement (done in `docs/REPOSITORY-MAP.md`). Not a cleanup target. |
| `notes/badr_phase1_report (1).md` vs `(2).md` | `(1)` (284 lines) is a strict content prefix of `(2)` (619 lines) — classic duplicate-download naming, not two distinct documents. | Rename `(2)` to a clean name (e.g. `badr_phase1_report.md`) and either delete or clearly mark `(1)` as a superseded draft. Not done in this pass (no deletions authorized). |
| Roadmap chain: `notes/archive-roadmap-2026-07-20.md` → `ROADMAP.md` → `FINAL-ROADMAP.md` → `AGENT-ROADMAP.md` | Each of the latter three explicitly says it supersedes the previous one *for task planning* while the earlier ones remain valid for background rationale — this is self-documenting, not accidental sprawl, but a new reader has to read all 4 to find the "current" one. | Consider adding one line to the top of `README.md` or `PROJECT-STATE.md` pointing directly at `AGENT-ROADMAP.md` as the current plan (partially done — `README.md`'s "Current phase status" section links there). No files touched. |
| Orchestrator: 4 copies exist — `/e2e_soc_orchestrator.py` (root), `soar/e2e_soc_orchestrator.py` (current), `soar/e2e_soc_orchestrator.py.bak-20260815-113408-pre-mailer-sync`, `soar/backups/e2e_soc_orchestrator.2026-08-20.py` | The root copy's hardcoded key has been resolved this pass (see §2.1) — it now reads `THEHIVE_API_KEY` from the environment, same as the other three copies, which already used the env-var pattern and contained no secrets. It remains a distinct, less-featured prototype (see the Addendum) — not merged, per "preserve existing behavior." | The two `soar/` backups are reasonable rollback references and are already gitignored (`soar/backups/`, `*.bak-*`) — no action needed. The root copy is now tracked as a documented historical/reference artifact — no further action needed unless the project owner wants it archived or removed. |
| `configs/elk/docker-compose.yml` (and its new `.example`) still expose ports `5515`(udp)/`5516`(tcp) for "Suricata EVE JSON input" | `CLAUDE.md`/`PROJECT-STATE.md` document that Suricata EVE delivery moved to native Redis output on 2026-07-16 and that these Logstash inputs were "removed as dead code" — but the *compose file* was never updated to match. | Documentation/config drift, not a secret issue. Noted inline in the new `.example` file; recommend updating the real `docker-compose.yml` to drop those ports next time the ELK stack is touched. Not changed in this pass (real file is gitignored and out of scope for functional edits). |
| `graphify-out/` (12 tracked files besides `cache/`) | Itself a fully regenerable artifact of running `/graphify` locally, similar in spirit to `ai/results/raw*/`. | Task instructions scoped exclusion to `graphify-out/cache/` only, so the rest stays tracked as directed. Flagged here as a candidate for a future, explicitly-authorized pass if repo size becomes a concern. |
| `TASK-SPLIT.md` references a key "exposed in `notes/8.md`" | No such value currently exists in `notes/8.md` (checked in this pass). | Stale cross-reference; low priority documentation cleanup, not touched. |

---

## 10. Full list of edits made across both passes

**First pass — documentation sanitization** (value removed, placeholder + dated note added):
- `PROJECT-STATE.md` — 4 separate edits (line ~589 second TheHive key, the
  3-row credentials table, the Kali SSH password, the demo-account password)
- `notes/6.md` — 1 edit (TheHive key in incident-history prose)
- `TOMORROW-TODO.md` — 1 edit (demo-account password)
- `AGENT-ROADMAP.md` — 1 edit (demo-account password)
- `RUNBOOK-2026-08-11.md` — 1 edit (3 inlined Elasticsearch-password curl commands → shell variable)

**First pass — new files:**
- `.gitignore` (rewritten/extended)
- `.env.example`
- `configs/elk/.env.example`
- `configs/elk/docker-compose.yml.example`
- `configs/elk/elastalert/config.yaml.example`
- `README.md`
- `docs/REPOSITORY-MAP.md`
- `docs/SETUP.md`
- `docs/SECURITY.md`
- `LOCAL-ARTIFACTS-MANIFEST.md`
- `REPO-CLEANUP-REPORT.md` (this file)

**Second pass — code sanitization** (root orchestrator key incident):
- `e2e_soc_orchestrator.py` (repo root) — hardcoded key line replaced with
  `os.environ.get('THEHIVE_API_KEY')`, no default; fail-closed `sys.exit`
  check added to `main()`; header comment added documenting the incident and
  the file's status as a superseded prototype. No other logic changed.

**Second pass — documentation updates** (status changes only, no values):
- `docs/SECURITY.md` — resolved-incident record added; hard-blocker table
  renumbered (2 items remain open); pre-push checklist updated.
- `docs/REPOSITORY-MAP.md` — root orchestrator row added, marked tracked.
- `LOCAL-ARTIFACTS-MANIFEST.md` — root orchestrator entry moved from
  "excluded" to "resolved and no longer excluded."
- `REPO-CLEANUP-REPORT.md` (this file) — Addendum added; §1, §2, §3, §5,
  §6, §7, §9 updated for consistency with the current, post-revocation state.

**Second pass — `.gitignore`:**
- `/e2e_soc_orchestrator.py` exclusion rule removed (replaced with an
  explanatory comment) — the file is sanitized and now proposed for tracking.

**Repository state:**
- `git init -b main` (first pass). **No files staged. No commit created.**
  Still true after the second pass.

No file was deleted. No file under `soar/` or `ai/` had its code changed —
only documentation (`.md`) files and the `.gitignore`/`.example`/`docs/`
additions above. Dataset B locked contents/hashes
(`FINAL_LABELS_v1.json`, `DATASET_B_LOCK_v1.json`) were not touched. No
live infrastructure was accessed and no credential was used for
authentication at any point in this pass.
