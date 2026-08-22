# Dataset A — human review worksheet (Phase 7A draft)

Status: **DRAFT — no case in this directory has been reviewed or locked.**
This directory (`ai/testset/dataset_a_draft/`) holds the 7 golden cases
migrated from `ai/testset/*.json` into the Phase 7 schema
(`soar/dataset_schema.py`, `schema_version: "phase7-v1"`). Migration script:
`soar/migrate_golden_seven.py`.

Nothing here contributes to a safety-gate metric until `review_status`
becomes `"approved"` (see `soar/replay_harness.py::_score_case()` — only
approved cases count toward `false_auto_containment_count` and the other
pass/fail metrics). A `"pending"` case is fully visible in a report for
review purposes, but never fails or passes the run.

## Review states

| `review_status` | Meaning | Contributes to safety gate? |
|---|---|---|
| `pending` | Not yet reviewed, or review incomplete | No |
| `approved` | A named human reviewer confirmed every required field | **Yes** |
| `disputed` | A reviewer disagrees with the candidate label, or evidence is ambiguous | Yes, but **`expected_tier` is forced to `L2` or null — never `L1`** (enforced by `dataset_schema.validate_case()`) |
| `excluded` | Reviewed and determined unsuitable for evaluation (e.g. content issue, true duplicate) | No |

**A historical or hand-authored label is a CANDIDATE, never automatic ground
truth.** This is true even for these 7 cases, despite each already carrying
a human-authored `rationale` in its legacy `ground_truth` block — that
`rationale` was written for the OLD, narrower schema (verdict +
`must_not_auto_block` only). It does not by itself establish the NEW
required fields (`expected_tier`, `expected_primary_reason`,
`required_reason_codes`, `event_time`), which is exactly why every migrated
record here is `pending`, not `approved`.

## To approve a case, a reviewer must

1. Read the case's `alert`, legacy `ground_truth`, and `label_notes` (the
   migration script's own notes on what it could/couldn't establish).
2. Confirm or correct `expected_tier` (`"L1"` or `"L2"`) — **never derive
   this by reading `l1_policy.py`'s current gate logic and predicting its
   output; derive it from the SCENARIO itself** (is this genuinely a
   narrow, corroborated, external, allowlisted-technique attack that SHOULD
   be eligible for autonomous L1 containment, independent of whether
   today's code happens to agree?). Using the policy under test to label
   its own ground truth is circular and is rejected by the schema's
   `label_source` allowlist if attempted directly — but a reviewer can
   still commit this error informally by "peeking" at the code first, which
   no validator can catch. Don't.
3. Set `event_time` — an ISO8601 timestamp. For these 7 cases (originally
   undated), use the date the underlying scenario was documented (see each
   case's `source` field, e.g. `notes/12.md`) unless a more precise time is
   recoverable.
4. Decide `required_reason_codes` / `forbidden_reason_codes` if the scenario
   clearly implies specific ones (e.g. a case with `must_not_auto_block:
   true` already gets `L1_TRUE_POSITIVE_CONTAINED` auto-added to
   `forbidden_reason_codes` by the migration script — extend this if other
   codes are similarly implied by the scenario, not by the code).
5. Set `label_confidence` (`high`/`medium`/`low`) reflecting how certain the
   reviewer is, independent of the original migration's guess.
6. Fill `reviewed_by` (a name or handle) and `reviewed_at` (ISO8601, the
   review date) — both are REQUIRED by the schema for `approved`.
7. Set `review_status: "approved"`. Run `dataset_schema.validate_case()` on
   the result — it must return `[]` before the case can be locked.

## Adjudication (disagreement between reviewers)

If two reviewers reach different `expected_tier` conclusions for the same
case:
1. Do not average or split the difference — pick the SAFER of the two
   conclusions as the interim state (`L2` is always safer than `L1`, since
   L2 never auto-contains).
2. Set `review_status: "disputed"` (which the schema already forces to
   `expected_tier: "L2"` or `null` — consistent with step 1 by
   construction) and record both reviewers' reasoning in `label_notes`.
3. A disputed case stays disputed until a third reviewer (or the original
   two, after discussion) reaches consensus — at which point it becomes
   `approved` with the AGREED `expected_tier`, `reviewed_by` naming
   whoever made the final call, and `label_notes` preserving the dispute
   history for audit purposes (never overwritten, only appended to).

## Per-case status (this migration)

| case_uid | must_not_auto_contain | expected_tier (draft) | Needs before approval |
|---|---|---|---|
| `01-testmyids-wan` | False | `null` | event_time; whether this specific case clears the L1 rule-allowlist/corroboration gates — **not derivable from `must_not_auto_block` alone** |
| `02-ssdp-false-positive` | True | `L2` | event_time only (tier already safely implied) |
| `03-attack-response-lan` | False | `null` | event_time; same open question as case 01 |
| `04-powershell-ua` | True | `L2` | event_time only |
| `05-sqli-auth-bypass` | True | `L2` | event_time only |
| `06-cred-dump-sam` | True | `L2` | event_time only |
| `07-nmap-scan-dmz` | True | `L2` | event_time only |

**None of the 7 cases has `fixtures` populated** (no frozen verdict/trace/
tool-call recording exists for them yet) — every one of them is a schema-
valid DRAFT but **not replay-ready** until fixtures are captured. Capturing
fixtures requires either a recorded live session (out of scope for Phase
7A) or hand-construction of a plausible fixture set for review — a Phase 7B
decision, not made here.

## What locking Dataset A actually requires (not done in Phase 7A)

1. Every case `review_status: "approved"` (or a deliberate, documented
   `"excluded"`), signed off by a named reviewer.
2. `fixtures` populated for every case that will be replayed.
3. `soar/rag_snapshot.py::write_manifest()` run over the final case set,
   producing a checksummed manifest — the manifest, not the loose JSON
   files, is what "locked" formally means.
4. `soar/replay_harness.py::build_reason_code_coverage_manifest()` run and
   reviewed — 7 cases will not cover every `policy_decision` reason code
   (54 total codes exist; only a fraction are `policy_decision`-classified,
   and 7 cases is still a small sample against even that subset) —
   additional hand-authored cases are expected before lock, not just these
   7 migrated ones.
