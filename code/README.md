# Ghost Data Still Exists: deletion-audit agent

For each privacy request, this agent decides whether deletion was actually requested. It
rebuilds the subject's current and historical identities and reads every evidence format: SQL
replicas, JSON bundles, five log dialects, handover text, and screenshots/PDFs via a vision
model. It then reconstructs each record's state as of `audit_at`, applies `deletion_rules.csv`,
and emits ordered FINDING / REMEDIATION / VERIFICATION steps.

## Setup and run

```bash
# from the repository root (the folder that contains dataset/ and code/)
python3 -m venv .venv && source .venv/bin/activate
pip install -r code/requirements.txt
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env        # optional, see "Models" below

python3 code/main.py                               # -> ./output.csv (518 rows)
python3 code/evaluation/validate_output.py         # contract checks on output.csv
python3 code/evaluation/main.py                    # scores on samples + custom cases
python3 code/evaluation/usage_report.py            # regenerates evaluation/usage_report.md
python3 code/main.py --inspect case_11             # identities, matched evidence, decision trace
python3 -m unittest discover -s code/tests -v      # 15 unit + end-to-end tests (stdlib only)
```

Python 3.10+ is required (tested on 3.11 and 3.13; output is byte-identical across both). The deterministic pipeline uses only the standard library
(`sqlite3`, `csv`, `json`, `re`); `anthropic` and `pymupdf` are needed only for live model calls.
A full run takes about 1 s.

## Architecture

```
code/
  main.py              entry point, Auditor (per-case pipeline), --inspect debug view
  ingest/              one parser per format -> Observation rows (file_id, captured_at, observed_at,
    sql.py               system, resource, category, exists / exposed / active, identifiers, links)
    json_records.py      SQL: in-memory sqlite per snapshot, one row per table copy (replica drift)
    logs.py              JSON: one recursive walker for bundles, exports, manifests
    text.py              logs: 5 dialects, trace-merged (lookup key + completion state)
    media.py             PNG/PDF -> Claude vision (prompts/media_extraction.md), cached JSON
    common.py            Observation model + per-system state interpretation
  identity.py          current + historical emails, phones, sha256 email hashes, user ids
  intent.py            deletion vs not: claude-haiku-5-5 + cache + multilingual rule fallback
  state.py             ownership links, episode scoping, latest state as of audit_at
  policy.py            deletion_rules.csv -> finding / remediation / verification operations
  planner.py           phase -> operation -> system -> resource ordering, JSON serialisation
  accounts.py          narrow, single-candidate account inference from deletion batches
  ledger.py            per-call token ledger (feeds usage_report.md)
  prompts/*.md         every model prompt
  docs/DATA_NOTES.md   data reconnaissance and rules derived from the samples
  evaluation/          main.py (metrics), validate_output.py, usage_report.py, custom_cases/, reports
  tests/               unittest suite: parsers, identity, policy, ordering, samples floor, determinism
  cache/media/         vision extractions of the 15 PNG/PDF files (re-used by every run)
```

Per case:

1. **Intent.** NOT_APPLICABLE with `[]` for access, export, correction, opt-out and login requests.
2. **Identity.** The request email (any case, current or historical) resolves to `user_id` and
   then to every email, phone and email hash the user ever had.
3. **Ownership.** A resource belongs to the subject only through grounded identifiers on its
   record, a link from an owned record (search document → source account), or a data-catalog
   link (`LINK_RESOURCE_IDENTITY`). Names and activity claims never link anything.
4. **As-of state.** Only files with `captured_at <= audit_at` set state and can be cited. The
   latest observation wins, and every surviving replica copy counts.
5. **Policy.** DELETE / REDACT (including tombstones) / ANONYMIZE / RETAIN. A backup whose
   restore is allowed and an enabled data flow are recreation risks.
6. **Plan.** Findings cite evidence. INCOMPLETE remediation and verification use `""`. COMPLETE
   cases emit only evidence-backed checks.

## Models

| Where | Model | Why |
|---|---|---|
| intent classification | `claude-haiku-5-5` (effort low) | 518 short multilingual texts; one cached call per distinct text |
| PNG / PDF extraction | `claude-sonnet-5-5` vision (effort medium) | 15 files, extracted once, cached in `cache/media/` |

Everything else is deterministic code. Without `ANTHROPIC_API_KEY` the run uses the cached
media extractions and the rule-based classifier. The submitted `output.csv` was produced this
way: the build environment had no key, and `evaluation/usage_report.md` states that plainly.
The media cache was transcribed in the development session by Claude (vision) using the same
JSON schema as `prompts/media_extraction.md`. Delete a file in `cache/media/` to have
`media.py` re-extract it through the API.

## Reports

* `evaluation/evaluation_report.md`: metrics, custom cases, failures and fixes
* `evaluation/usage_report.md`: model calls, tokens and cost of the final full run
