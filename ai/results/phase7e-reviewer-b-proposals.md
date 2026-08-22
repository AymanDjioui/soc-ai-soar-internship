# Phase 7E — reviewer-b independent review — PROPOSALS (not yet saved), 2026-08-22

**Status: proposals only, awaiting human approval.** Nothing in this turn was written to
`soar/review_overlays/reviewer-b.jsonl` (the actual append-only decision overlay) —
`review_rubric.validate_decision()` was used to *validate* each proposed decision, not
`review_dataset.record_decision()` to save one. This document and
`soar/review_overlays/reviewer-b-PROPOSALS.json` are the only outputs.

Performed entirely offline, inside `replay_harness.network_guard()`. No TheHive/Cortex/
pfSense/Ollama access, no credentials touched, no live infrastructure contacted.

## Contamination disclosure (read first)

While looking up what `review_status: "excluded"` means for this rubric, I read
`soar/L1-L2-SAFETY-AUDIT.md` §22, which turned out to contain reviewer-a's actual decision
(`excluded`, with full rationale) on two specific cases — `dsb-c-11b8b89478` and
`dsb-c-23ed74f43f`. Both are also in reviewer-b's assigned queue (they're in the static
dual-review set: every historical `Other`-disposition case gets both reviewers). That
directly violates the independence this dual-review design exists for.

Per your direction, **both cases are excluded from this batch entirely** rather than
included with a taint flag. They are not counted below and no proposal was generated for
them. They need a clean review session (or your explicit sign-off accepting the
contamination) before a reviewer-b decision is recorded for either.

## Verification (before any analysis)

- Dataset B v2 candidate population: `ai/testset/dataset_b_candidates_v2/` — **226 cases**,
  `load_and_verify_candidates()` independently re-hashed and structurally re-verified every
  candidate against `MANIFEST.json` — **0 errors**.
- `REVIEW_SAMPLE_MANIFEST.json` (60-case stratified review sample) verified against the
  loaded candidates via `verify_sample_against_candidates()` — **0 errors**.
- Reviewer-b's queue loaded from the **authoritative static assignment file**
  (`soar/review_overlays/ASSIGNMENTS_v2.json`, `queues.reviewer-b`) — **42 cases**, matching
  the expected count (calculated, not assumed).
- All 42 assigned UIDs exist in the verified candidate pool — 0 missing.
- 42 − 2 contaminated = **40 cases analyzed this turn**.

## Why no L1 proposals

Every one of the 40 analyzed cases has `fixture_provenance == "missing"`
(`has_any_investigation_fixture == false`). Both `review_rubric.validate_decision()` and
`review_dataset.record_decision()`'s Dataset-B-specific gate refuse to approve L1 with no
investigation fixture — so no case in this batch could honestly be proposed L1 today. This
matches the known Phase 7D finding that Dataset B currently has zero populated fixtures
project-wide. Every proposal below is `approved`+L2, `disputed`+L2, or `excluded`.

## Result counts

| Category | Count |
|---|---|
| Assigned to reviewer-b (authoritative) | 42 |
| Removed — contaminated, not analyzed | 2 |
| **Analyzed this turn** | **40** |
| → Approved (L2) | 14 |
| → Disputed (L2) | 8 |
| → Excluded | 18 |

All 40 proposed decisions passed `review_rubric.validate_decision()` with **zero rubric
violations**.

## Excluded (18) — self-declared test artifacts or unusable/corrupted records

| case_uid | title | reason |
|---|---|---|
| dsb-c-20c442286a | TEST INJECTED - Botnet C2 Contact Detected (C-1 demo) | self-declared synthetic ("SYNTHETIC ALERT injected for controlled C-1 testing") |
| dsb-c-2c6d78d773 | LAB TEST - Two Recipients | self-declared synthetic notification test |
| dsb-c-428d2c127a | run_analyzer wiring test | developer wiring/integration smoke test |
| dsb-c-73e2e9a412 | Cortex Responder API Test | manual responder-integration test |
| dsb-c-74a2ea79ba | Cortex Responder API Test | manual responder test + ambiguous target (2 unlabeled IPs) |
| dsb-c-b51a9c206d | LAB TEST - Malicious IP Detection (cachebust) | self-declared synthetic cachebust test |
| dsb-c-bacc20009d | LAB TEST - Observable Check | pipeline/observable-attachment smoke test |
| dsb-c-c2f63b996e | Malicious IP Detected - LAB TEST | self-declared "controlled test event for TheHive/Cortex email automation" |
| dsb-c-cd0f1e6772 | Cortex Responder API Test | manual responder test |
| dsb-c-e1b19a2be7 | Cortex Responder API Test | manual responder test |
| dsb-c-e86059c1ff | LAB TEST - Malicious IP Detection | self-declared "Synthetic malicious IP alert for SOAR Mailer responder testing" |
| dsb-c-319505ab29 | Port Scan Detected by PfSense | unresolved `{0}..{4}` template; "ip" observable data = `"547"` (a port number, not an IP) |
| dsb-c-56d1ec67db | Port Scan Detected by PfSense | same corruption; observable data = `"3702"` |
| dsb-c-61b09ad6b3 | Port Scan Detected by PfSense | same corruption; observable data = `"5355"` |
| dsb-c-725c3db03e | Windows Brute Force Detected | source-IP field never populated — observable data literally `"-"` |
| dsb-c-86340f135f | Suricata: {rule[name]} - {match[alert][signature]} | title AND description entirely unresolved template, no observables |
| dsb-c-ce88041225 | Brute Force from {match[winlog.event_data.IpAddress]} | unresolved template title/description, no observables |
| dsb-c-dc1b7c7233 | New Service on {match[host.name]} | unresolved template title/description, no observables |

These 18 broaden the same "synthetic/test-case exclusion filter gap" pattern already noted
for reviewer-a's queue (title/tag doesn't match `_is_excluded_test_case()`'s exact-prefix
check), plus a second, distinct defect class not previously documented: several `dsb-c-*`
records where the alert **description or observable data is an unresolved format-string
template or a leaked non-IP value** (port numbers or a bare `"-"` sitting in the `ip`
observable field). Recommend flagging this second pattern to the export-pipeline owner
separately from the title-matching gap — it's a different bug (upstream template
substitution failing before Cortex/TheHive ingestion), not a classification-filter miss.

## Disputed (8) — genuine uncertainty, not a rubber stamp

| case_uid | title | disposition | why disputed |
|---|---|---|---|
| dsb-c-ec8679e908 | New Local/Domain Account Created | TruePositive | unresolved description template + account name `h4x0r` (test-persona-like), can't tell genuine-but-broken from undeclared lab test |
| dsb-c-4bbcdcf864 | GPL ATTACK_RESPONSE id check returned root | TruePositive | description is a bare timestamp, zero real content, no observables |
| dsb-c-548455316f | GPL ATTACK_RESPONSE id check returned root | TruePositive | same defect as above — likely a shared export bug across all 3 near-duplicates |
| dsb-c-6bde7943a8 | GPL ATTACK_RESPONSE id check returned root | TruePositive | same defect as above |
| dsb-c-c851a89a34 | PfSense Perimeter Block | TruePositive | target 172.16.0.10 is our **own** Juice Shop DMZ host (per CLAUDE.md) — TP-blocking our own asset is internally inconsistent |
| dsb-c-e31b0af6b4 | Path Traversal / LFI Attempt on Juice Shop | TruePositive | one observable IP is our **own** ELK server's Tailscale address (100.99.54.59) — likely an attribution/relay artifact, not the real attacker |
| dsb-c-4a309f2549 | New Malicious Windows Service | TruePositive | "Service Name: Sysmon64" is Microsoft's own legitimate monitoring agent — plausibly mislabeled, no observables to disambiguate |
| dsb-c-8d06d04a08 | PfSense Perimeter Block | TruePositive | blocks 192.168.84.1 (TP) on the same /24 where two sibling cases (.134) were marked FalsePositive for similar SSDP/multicast noise — plausible disposition inconsistency |

## Approved — L2 (14)

| case_uid | title | disposition | primary reason |
|---|---|---|---|
| dsb-c-122c595cdf | Linux Root SSH Login | TruePositive | MISSING_EVIDENCE (IP in text, no observable attached) |
| dsb-c-22c9abd9e7 | XSS Attempt on Juice Shop | TruePositive | MISSING_EVIDENCE (matches documented SID 2009714 chain — high confidence) |
| dsb-c-57c0b4c518 | Suspicious outbound connection detected | TruePositive | MISSING_EVIDENCE (185.220.101.45, known Tor exit range) |
| dsb-c-5c4b6efe80 | Outbound contact to known Cobalt Strike C2 | TruePositive | MISSING_EVIDENCE |
| dsb-c-6b7b55b5df | Port Scan Detected by PfSense | FalsePositive | AMBIGUOUS_TARGET (2 unlabeled real IPs incl. SSDP multicast) |
| dsb-c-75eb479702 | Suricata alert (SSDP amplification) | FalsePositive | MISSING_EVIDENCE (documented UPnP FP scenario, cleanly tagged) |
| dsb-c-7d6f4e8e17 | Suricata alert (XSS script tag) | TruePositive | MISSING_EVIDENCE (matches documented SID 2009714 chain) |
| dsb-c-8137463674 | Linux SSH Brute Force | TruePositive | MISSING_EVIDENCE (IP in text, no observable attached) |
| dsb-c-8b5d1c41d0 | Linux SSH Brute Force | TruePositive | MISSING_EVIDENCE (IP in text, no observable attached) |
| dsb-c-c131c7b865 | JuiceShop XSS Attack | TruePositive | MISSING_EVIDENCE |
| dsb-c-da2da23b77 | PfSense Perimeter Block | FalsePositive | MISSING_EVIDENCE (consistent SSDP FP pattern) |
| dsb-c-dfdc99686e | SSDP Amplification Scan (internal) | FalsePositive | MISSING_EVIDENCE ("Normal UPnP discovery" — matches README's documented FP scenario) |
| dsb-c-a4fa0f8905 | ET SCAN Nmap Scripting Engine User-Agent Detected | Other | RAG_INSUFFICIENT_HISTORY (description itself says "no prior history") |
| dsb-c-cf8a3c59c3 | Linux Root SSH Login | TruePositive | MISSING_EVIDENCE (IP in text, no observable attached) |

Full per-case rationale, checklist snapshots, and content hashes are in
`soar/review_overlays/reviewer-b-PROPOSALS.json`.

## Not done this turn (as instructed)

- No decision was saved to `soar/review_overlays/reviewer-b.jsonl`.
- No adjudication of the 8 disputed cases.
- No dataset locking, no Phase 8 work.
- `dsb-c-11b8b89478` / `dsb-c-23ed74f43f` left unaddressed pending your direction.

**Stopping here for human approval.**
