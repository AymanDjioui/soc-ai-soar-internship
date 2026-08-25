# Security model & known limitations

This document covers two different things: (1) the SOAR safety model (L1 vs
L2 autonomy), which is a design property of the code, and (2) the current
credential-hygiene status of this repository, which is an operational
concern for anyone about to push this project anywhere. Read section 2
before pushing to GitHub, even a private one.

> Some incident entries below cite files (`PROJECT-STATE.md`,
> `REPO-CLEANUP-REPORT.md`, `notes/*.md`, etc.) that were later consolidated
> into `PROJECT-ARCHIVE-LOCAL.md` during the 2026-08-25 scope cut and are no
> longer tracked in this repo. Left as-is — these are historical incident
> records, not live pointers. The archive is gitignored (local only); ask
> the project owner if you need to see it.

## 1. L1 vs L2 safety model

The orchestrator (`soar/agent_orchestrator.py`, `soar/e2e_soc_orchestrator.py`)
never lets the LLM decide whether to act. The model produces an assessment
(verdict, severity, confidence, MITRE technique); `l1_policy.py`'s
deterministic, code-side policy gate decides whether that assessment is
*allowed* to result in a containment action. The gate is veto-only — it can
refuse, never authorize on its own initiative.

- **L1 (autonomous)**: high-confidence, rule-eligible, protected-asset-free
  cases may be auto-contained (pfSense block) and auto-closed, gated by
  `SOAR_L1_CONTAIN_MIN_CONF` / `SOAR_L1_CLOSE_MIN_CONF` and a same-key
  idempotency claim (`soar/idempotency.py`) so no action ever double-fires.
- **L2 (human-in-the-loop)**: everything else — ambiguous targets, protected
  assets (RFC1918/CGNAT/Tailscale ranges, the SOC's own infrastructure),
  missing evidence, rule-ineligible techniques — is assigned to a human
  analyst (`SOAR_L2_LOGIN`) and/or emailed, never auto-contained.
- A `SOAR_KILL_SWITCH` file and `SOAR_DRY_RUN` / `SOAR_AGENT_DRY_RUN` env
  vars gate whether any run can touch the firewall at all. See
  `soar/L1-L2-SAFETY-AUDIT.md` for the full design history and every
  verification pass, including the credential incidents below.
- 632/632 offline unit/integration checks pass across the 12 `soar/test_*.py`
  suites (verified during this repo-hygiene pass — see
  `REPO-CLEANUP-REPORT.md`). None of them touch live infrastructure.

## 2. Credential hygiene status (as of 2026-08-22)

A broad secret scan was run across the full repository as part of preparing
this project for a private GitHub push (see `REPO-CLEANUP-REPORT.md` for
the complete, redacted finding list). Summary:

### Resolved incidents

| Date | Affected file(s) | Remediation | Verification |
|---|---|---|---|
| 2026-08-22 | `/e2e_soc_orchestrator.py` (repo root) | Hardcoded TheHive API key removed from source. The key is now read exclusively from the `THEHIVE_API_KEY` environment variable, with no default and no fallback value; `main()` fails closed with a clear `sys.exit` error if the variable is unset. The key itself has been **manually revoked by the project owner**. | Confirmed the script no longer contains any literal key value (`py_compile` + a manual read of the diff). Confirmed the fail-closed path actually raises `SystemExit` when `THEHIVE_API_KEY` is unset, and that the script proceeds past the check once the variable is set. File is no longer excluded from git in `.gitignore` — it is sanitized and eligible for tracking like any other source file. |
| 2026-08-22 | `configs/elk/elastalert/config.yaml` (`hive_apikey`); duplicated in `PROJECT-STATE.md` (pre-redaction) | A second, distinct TheHive API key, first flagged as an open blocker in `soar/L1-L2-SAFETY-AUDIT.md` §21. **Manually revoked by the project owner.** The documentation copy was already redacted to `${THEHIVE_API_KEY}` in an earlier pass; the real config file remains gitignored (kept real+local per standing project policy — see §2's "Standing, pre-existing exception" below), consistent with how a rotated key will be supplied going forward. | Documentation copy confirmed to contain no literal value. Revocation performed and confirmed by the project owner outside this tooling. |
| 2026-08-22 | `notes/6.md` (pre-redaction) | A third, distinct TheHive API key value, quoted in prose describing an earlier exposure-during-troubleshooting incident. **Manually revoked by the project owner.** Documentation was already redacted to `${THEHIVE_API_KEY}` in an earlier pass. | Documentation copy confirmed to contain no literal value. Revocation performed and confirmed by the project owner outside this tooling. |

**No key value — old or new — is recorded anywhere in this repository or in any of this project's documentation.** Revocation of all three credentials was performed by the project owner outside of this tooling; at no point did this tooling access TheHive or any other live system, request a replacement credential, or generate one. **New, dedicated service credentials (a fresh TheHive API key, and any other service accounts this project needs) will be created only during deployment (Phase 8), not as part of repository preparation.** Until then, every config file that references one of these keys (`configs/elk/elastalert/config.yaml`, and any local `.env`) is expected to be non-functional against live TheHive — that is the intended state, not a defect.

### Hard blockers — must be resolved before any push, even private

All three TheHive API key incidents are now resolved (see above). The
remaining items are unrelated, non-TheHive credentials:

| # | Location | What | Status |
|---|---|---|---|
| 1 | `.claude/settings.local.json` | Hardcoded SSH passwords inside Bash permission allow-list strings (pfSense admin SSH password, a lab Kali box password). | File is gitignored. Values not rotated. |
| 2 | `configs/elk/docker-compose.yml` | Three hardcoded Kibana encryption keys (`XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY`, `XPACK_SECURITY_ENCRYPTIONKEY`, `XPACK_REPORTING_ENCRYPTIONKEY`), plaintext. | File is gitignored; a sanitized `.example` template exists. Not rotated — rotating `XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY` invalidates existing Kibana connectors, so do this deliberately, not as a side effect. |
| 3 | `configs/elk/.env` | Plaintext Elasticsearch/Kibana stack passwords. | File is gitignored; sanitized `.env.example` exists. |
| 4 | `PROJECT-STATE.md` credentials table (pre-redaction) | ELK SSH password, Elasticsearch password, pfSense admin password, Kali SSH password, TheHive demo-account password. | Values redacted from documentation in an earlier pass (placeholders only). Underlying credentials not rotated. |
| 5 | `configs/pfsense/config.xml` | pfSense admin password as a **bcrypt hash** (not plaintext), plus full firewall/NAT/interface configuration. Lower severity (hashed, not reversible in practice) but still an administrative artifact CLAUDE.md says not to publish. | Directory is gitignored in full. |

None of the items above were rotated by this pass. No live infrastructure
was accessed and no credential was used for authentication, requested, or
created at any point.

### Reviewed and found clean (false positives / already safe)

- `soar/review_overlays/FINAL_LABELS_v1.json` and `DATASET_B_LOCK_v1.json` —
  scanned for credential- and PII-shaped content; contain only case UIDs,
  content hashes, review-rubric metadata, and test-suite counts. No raw case
  text, no IPs, no secrets. Safe to track (see `REPO-CLEANUP-REPORT.md`).
- `ai/results/raw*/` and `ai/testset/dataset_b_candidates*/` — matches for
  the word "password" are all LLM-generated summaries or raw Suricata/SSH
  log lines describing attacker behavior (e.g. `"Accepted password for root
  from <ip>"`), not credentials. These directories are gitignored anyway
  (large/regenerable, or real historical case data respectively) so the
  distinction is moot for tracking purposes, but it matters for triage: they
  are not part of the "hard blocker" list above.
- `soar/sanitization.py`, `soar/test_sanitization.py`,
  `soar/test_notifications.py`, `soar/test_replay_harness.py` — contain
  strings like `password: hunter2`, `api_key=sk-live-...`, and a syntactically
  valid but non-functional example JWT. These are the project's **own**
  redaction-regex test fixtures (`soar/sanitization.py` is the code that
  strips secrets from case data before it's ever written to disk/exported),
  not leaked credentials.
- `soar/L1-L2-SAFETY-AUDIT.md` §20's "12 Gmail-app-password-shaped matches"
  were reviewed by the audit's own author at the time and are ordinary
  English prose that coincidentally matches a 4x4-lowercase-letter shape —
  confirmed false positives, not credentials.
- `.mcp.json` — local MCP server wiring (script paths, a local proxy port).
  No credentials present. Still gitignored per this pass's own instructions
  (MCP config commonly carries credentials in other projects, and doing so
  here is zero-cost).

### Standing, pre-existing exception (not new)

Per `CLAUDE.md`, `configs/elk/` and `configs/pfsense/` were deliberately
pulled and kept **unredacted on disk** as an operational mirror, with an
explicit decision to never publish or share them externally. This pass
respects that decision by keeping every real file in those two directories
out of git (see the `.gitignore` rules) rather than editing or deleting them,
and adds sanitized `.example` templates so a reader can still see the
required shape of the configuration.

## 3. Before this repo is pushed anywhere — even a private remote

1. ~~Rotate/revoke the root-level `/e2e_soc_orchestrator.py` TheHive API
   key.~~ **Done 2026-08-22** — see "Resolved incidents" above.
2. ~~Rotate/revoke the two remaining TheHive API key values.~~
   **Done 2026-08-22** — all three TheHive key incidents are now revoked.
   **New TheHive credentials are deliberately not created here** — that
   happens only during deployment (Phase 8), so the pipeline remains
   non-functional against live TheHive until then by design.
3. Rotate the ELK SSH, Elasticsearch, pfSense admin, and Kali SSH passwords
   (hard blocker #4) and the Kibana encryption keys (hard blocker #2) —
   still open, unrelated to the TheHive incidents.
4. Re-run the secret scan (`REPO-CLEANUP-REPORT.md` documents the exact
   commands used) after rotation, to confirm zero remaining plaintext
   credential values in any tracked file.
5. Only then run `git add` / `git commit`.
