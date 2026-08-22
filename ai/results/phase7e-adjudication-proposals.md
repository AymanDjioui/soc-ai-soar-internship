# Phase 7E — finalization and adjudication — PROPOSALS (not yet saved), 2026-08-22

**Status: proposals only, awaiting human approval.** Nothing was written to
`soar/review_overlays/reviewer-a.jsonl` or `reviewer-b.jsonl`. `soar/review_overlays/
ADJUDICATION-PROPOSALS.json` and this document are the only outputs. No dataset lock, no
Phase 8 work, no live infrastructure (TheHive/Cortex/pfSense/Ollama) contacted.

Performed entirely offline, inside `replay_harness.network_guard()`.

## Protocol deviation (accepted per your direction)

`dsb-c-11b8b89478` and `dsb-c-23ed74f43f` are excluded from dual review entirely. A prior
session's independent reviewer-b pass was contaminated for exactly these two cases (it read
reviewer-a's actual decision + rationale in `soar/L1-L2-SAFETY-AUDIT.md` §22 before
reviewer-b's own read). No reviewer-b decision has been created or copied for either —
reviewer-a's existing decision (already saved in `reviewer-a.jsonl`) stands as the sole,
authoritative primary decision for both. Both are excluded from every inter-reviewer
agreement statistic below.

Effect: 20 statically-assigned dual-review cases − 2 excluded = **18 clean dual-reviewed
cases**.

## 1–2. Verification

| Check | Result |
|---|---|
| Dataset B v2 candidate population (`ai/testset/dataset_b_candidates_v2/`) | **226 cases**, re-hashed + structurally re-verified against `MANIFEST.json` — 0 errors |
| Review sample manifest (`REVIEW_SAMPLE_MANIFEST.json`) | **60 cases**, re-verified against loaded candidates — 0 errors |
| Assignments (`ASSIGNMENTS_v2.json`) | total_cases=60, primary_counts={reviewer-a: 30, reviewer-b: 30}, dual_review_count=20 |
| reviewer-a.jsonl | 38 decisions (30 primary + 8 secondary dual-review) |
| reviewer-b.jsonl | 40 decisions (30 primary + 10 of 12 secondary dual-review — missing exactly the 2 excluded cases) |
| **All 60 sample cases have ≥1 clean primary decision** | **YES** — 0 missing |

## 3–4. Comparing the 18 clean dual-reviewed cases

| # | case_uid | reviewer-a | reviewer-b | agree? |
|---|---|---|---|---|
| 1 | dsb-c-428d2c127a | excluded | excluded | yes |
| 2 | dsb-c-4a309f2549 | disputed / L2 | disputed / L2 | yes |
| 3 | dsb-c-548455316f | approved / L2 | disputed / L2 | **no** |
| 4 | dsb-c-6b7b55b5df | approved / L2 | approved / L2 | yes |
| 5 | dsb-c-73e2e9a412 | excluded | excluded | yes |
| 6 | dsb-c-74a2ea79ba | excluded | excluded | yes |
| 7 | dsb-c-75eb479702 | approved / L2 | approved / L2 | yes |
| 8 | dsb-c-8137463674 | approved / L2 | approved / L2 | yes |
| 9 | dsb-c-a4fa0f8905 | disputed / L2 | approved / L2 | **no** |
| 10 | dsb-c-c131c7b865 | approved / L2 | approved / L2 | yes |
| 11 | dsb-c-c2f63b996e | excluded | excluded | yes |
| 12 | dsb-c-cd0f1e6772 | excluded | excluded | yes |
| 13 | dsb-c-ce88041225 | approved / L2 | excluded | **no** |
| 14 | dsb-c-cf8a3c59c3 | approved / L2 | approved / L2 | yes |
| 15 | dsb-c-da2da23b77 | approved / L2 | approved / L2 | yes |
| 16 | dsb-c-dc1b7c7233 | approved / L2 | excluded | **no** |
| 17 | dsb-c-dfdc99686e | approved / L2 | approved / L2 | yes |
| 18 | dsb-c-e1b19a2be7 | excluded | excluded | yes |

**Agreements: 14/18. Disagreements: 4/18** (status-pair breakdown: excluded/excluded ×6,
approved/approved ×7, disputed/disputed ×1, approved/disputed ×1, disputed/approved ×1,
approved/excluded ×2).

### Preliminary reviewer-agreement statistics (18 clean dual cases only)

- **Exact agreement rate: 14/18 = 77.8%**
- Scope is strictly the 18 clean cases — the 2 excluded contaminated cases are not counted
  anywhere in this figure.
- Caveat: n=18 is small; this is a preliminary percent-agreement figure, not a full
  inter-rater reliability analysis (e.g. Cohen's κ) — worth redoing once a larger
  dual-reviewed set or Dataset B fixtures exist.

### Every case still marked disputed (whole 60-sample, not just the 18)

12 cases carry `review_status: "disputed"` from at least one reviewer: `dsb-c-09974c4f4b`,
`dsb-c-419b09d1f8`, `dsb-c-4a309f2549`, `dsb-c-4bbcdcf864`, `dsb-c-548455316f`,
`dsb-c-6bde7943a8`, `dsb-c-8d06d04a08`, `dsb-c-a4fa0f8905`, `dsb-c-a7435e639c`,
`dsb-c-c851a89a34`, `dsb-c-e31b0af6b4`, `dsb-c-ec8679e908`. Of these, only 2
(`dsb-c-4a309f2549`, `dsb-c-548455316f`) fall inside the 18 clean dual cases; the other 9 were
disputed by only ONE reviewer and never received the second opinion the dynamic-escalation
design (`review_dataset.effective_queue()`) intends for a disputed case — worth flagging as a
process gap separately from this adjudication.

**Unresolved cases needing adjudication = (4 dual-review disagreements) ∪ (12 disputed-status
cases), deduplicated = 14 cases.**

## 5–7. Adjudication proposals (14 cases, all rubric-valid)

All 14 proposed decisions passed `review_rubric.validate_decision()` — **14/14 PASS, 0
failures**.

### A. Resolved toward "approved" (8)

| case_uid | proposed | primary reason | confidence | why |
|---|---|---|---|---|
| dsb-c-548455316f | approved / L2 | MISSING_EVIDENCE | medium | Bare-timestamp description + zero observables is a *definite* evidentiary gap, not an open question — aligns with reviewer-a's own resolution. |
| dsb-c-4bbcdcf864 | approved / L2 | MISSING_EVIDENCE | medium | Same shared-defect group as above (identical signature name, identical bare-timestamp pattern across 3 near-duplicates). Never had a 2nd reviewer. |
| dsb-c-6bde7943a8 | approved / L2 | MISSING_EVIDENCE | medium | Same shared-defect group. Never had a 2nd reviewer. |
| dsb-c-a4fa0f8905 | approved / L2 | RAG_INSUFFICIENT_HISTORY | medium | Target is unambiguous; the historical "Other" disposition is directly supported by the record's own text ("no prior history... before assessing severity"), not a rubber stamp. Reviewer-a's dispute was a hunch without a counter-fact. |
| dsb-c-09974c4f4b | approved / L2 | CONFLICTING_EVIDENCE | medium | Signature says LFI/traversal, captured request is XSS-shaped; target is the protected ELK host. The conflict is concretely documented — the L2 outcome isn't actually in doubt. Never had a 2nd reviewer. |
| dsb-c-419b09d1f8 | approved / L2 | CONFLICTING_EVIDENCE | medium | Target group reads as ordinary "Users" (not evidently privileged); member-added value missing. Never had a 2nd reviewer. |
| dsb-c-a7435e639c | approved / L2 | CONFLICTING_EVIDENCE | medium | Only log line is a CLOSED, [preauth] single connection from the internal LAN gateway — doesn't support "brute force" on its face. Never had a 2nd reviewer. |
| dsb-c-e31b0af6b4 | approved / L2 | PROTECTED_ASSET | medium | Direct precedent: `dsb-c-cddbaedc91` (already approved) targets the *same* IP (100.99.54.59, project's own ELK host) under identical reasoning. Never had a 2nd reviewer. |

### B. Resolved toward "excluded" (3)

| case_uid | proposed | confidence | why |
|---|---|---|---|
| dsb-c-ce88041225 | excluded | high | Title AND description both entirely unrendered template placeholders, zero observables — no security content survived export. Consistent with the uncontested exclusion of `dsb-c-86340f135f` (identical defect shape). |
| dsb-c-dc1b7c7233 | excluded | high | Same defect class as above. |
| dsb-c-ec8679e908 | excluded | medium | Weaker than the self-declared "LAB TEST" group (no explicit self-declaration), but two independent signals align: unrendered description template + account name `h4x0r` (stereotypical test persona). Lowest-confidence exclusion in this batch. |

**Flagged consistency note (not itself adjudicated):** reviewer-a approved
`dsb-c-1a1e45f08c` — same defect shape as ce88041225/dc1b7c7233 (unresolved `{match[...]}`
title, zero observables) — as L2 rather than excluding it. That decision was made solo
(never dual-reviewed) and is untouched here, but is worth a broader consistency sweep later.

### C. No change proposed — genuinely unresolved (3)

| case_uid | status | why no resolution is proposed |
|---|---|---|
| dsb-c-4a309f2549 | disputed / L2 (unchanged) | Both reviewers independently reached "disputed" for the same reason (Sysmon64 is a legitimate MS tool, no observables to disambiguate). A real, well-supported dispute — not a gap in review effort. Recommend leaving disputed until Dataset B fixtures exist. |
| dsb-c-8d06d04a08 | disputed / L2 (unchanged) | Reviewer-b's subnet-reuse concern rests on an unverified fact (is 192.168.84.1 *also* a protected gateway address, the way .134 was established to be elsewhere?) this analysis cannot confirm from the record. Recommend a human fact-check before resolving. |
| dsb-c-c851a89a34 | disputed / L2 (unchanged) | "TruePositive block against our own DMZ asset" is also readable as pfSense blocking *outbound* traffic from a possibly-compromised Juice Shop host — a legitimate TruePositive, not an inconsistency. Both readings are plausible from the record alone; recommend checking the underlying case/log before resolving. |

## Result counts

| Category | Count |
|---|---|
| Total sample cases | 60 |
| Cases with ≥1 primary decision | 60 / 60 |
| Statically dual-assigned cases | 20 |
| Excluded per protocol deviation | 2 |
| Clean dual-reviewed cases | 18 |
| Agreements (18 clean) | 14 |
| Disagreements (18 clean) | 4 |
| Preliminary agreement rate | 77.8% |
| Disputed-status cases (whole 60-sample) | 12 |
| **Unresolved cases requiring adjudication** | **14** |
| → proposed "approved" | 8 |
| → proposed "excluded" | 3 |
| → no change (stays "disputed") | 3 |
| Adjudication proposals passing rubric validation | 14 / 14 |

Full per-case detail (both reviewers' original decisions, proposed decision, rationale,
rubric-validation result) is in `soar/review_overlays/ADJUDICATION-PROPOSALS.json`.

## Not done this turn (as instructed)

- No decision saved to `reviewer-a.jsonl` or `reviewer-b.jsonl`.
- No reviewer-b decision created for `dsb-c-11b8b89478` / `dsb-c-23ed74f43f`.
- No `ADJUDICATION_QUEUE.json` write, no dataset lock, no Phase 8 work.
- No live infrastructure contacted.
- 9 of the 12 disputed-status cases never received the second-reviewer look the
  dynamic-escalation design intends for a disputed case — flagged as a process gap, not
  fixed here.

**Stopping here for human approval.**
