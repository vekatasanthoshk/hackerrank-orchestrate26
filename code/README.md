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
python3 code/evaluation/main.py --ablation         # samples, custom cases, synthetic fixtures, intent probes
python3 code/evaluation/usage_report.py            # regenerates evaluation/usage_report.md
python3 code/main.py --inspect case_11             # identities, matched evidence, decision trace
python3 -m unittest discover -s code/tests -v      # 49 unit, robustness, security, offline-SDK and end-to-end tests
python3 code/package_submission.py                 # validate + rebuild submission/ (code.zip, output.csv, log.txt)
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
  intent.py            deletion vs not: claude-haiku-5-5 + cache + multilingual rule layer + injection guard
  state.py             ownership links, episode scoping, latest state as of audit_at
  policy.py            deletion_rules.csv -> finding / remediation / verification operations
  planner.py           phase -> operation -> system -> resource ordering, JSON serialisation
  accounts.py          narrow, single-candidate account inference from deletion batches
  ledger.py            per-call token ledger (feeds usage_report.md)
  prompts/*.md         every model prompt
  docs/DATA_NOTES.md   data reconnaissance and rules derived from the samples
  evaluation/          main.py (metrics, --ablation), validate_output.py, usage_report.py, custom_cases/,
                       fixtures/ (synthetic dataset + cases), intent probes (dev + held-out), reports
  tests/               unittest suites: pipeline (parsers, identity, policy, ordering, samples floor,
                       determinism) and robustness (hostile SQL / paths / model output, edge-case requests)
  docs/SECURITY.md     threat model, findings and fixes
  cache/media/         vision extractions of the 15 PNG/PDF files (re-used by every run)
```

Per case:

1. **Intent.** NOT_APPLICABLE with `[]` for access, export, correction, opt-out, login and
   billing requests. Instruction-like segments in the request text are cut out first.
2. **Identity.** The request email (any case, current or historical) resolves to `user_id` and
   then to every email, phone and email hash the user ever had.
3. **Ownership.** A resource belongs to the subject only through grounded identifiers on its
   record (including the key a read-back was made with), a link from an owned record (search
   document → source account), or a data-catalog link (`LINK_RESOURCE_IDENTITY`) that the
   record's own identifiers do not contradict. Names never link anything; a deletion-batch
   claim can only schedule a check (`accounts.py`).
4. **As-of state.** Only files with `captured_at <= audit_at` set state and can be cited. The
   latest observation wins, every surviving replica copy counts, and conflicts (same instant,
   different result; replica copies a later read does not cover) are reported, not hidden.
5. **Policy.** DELETE / REDACT (including tombstones) / ANONYMIZE / RETAIN. A backup whose
   restore is allowed and an enabled data flow are recreation risks.
6. **Plan.** Findings cite evidence. INCOMPLETE remediation and verification use `""`. COMPLETE
   cases emit only evidence-backed checks.

## Models

| Where | Model | Why |
|---|---|---|
| intent classification | `claude-haiku-5-5` (effort low, JSON-schema answer) | 518 short multilingual texts; one cached call per distinct text |
| PNG / PDF extraction | `claude-sonnet-5-5` vision (effort medium, server-side refusal fallback) | 15 files (PDFs as native documents), extracted once, cached in `cache/media/` |

Everything else is deterministic code. Without `ANTHROPIC_API_KEY` the run uses the cached
media extractions and the rule-based classifier, and `evaluation/usage_report.md` says so.
**So far every submitted number comes from such a run**: no key has been available, so the
model stages have only been exercised offline (real SDK, fake API). The cache was transcribed
during development with the schema in `prompts/media_extraction.md` and re-checked against
every image on 2026-10-25.
With a key, `python3 code/main.py --refresh-media` re-extracts all 15 artifacts with the
vision model and keeps the transcription in `cache/media_manual/`. Then
`evaluation/compare_media.py` diffs the two extractions field by field (a model-comparison
report). Step-by-step instructions, including **where to store the key safely**, are in
`docs/LIVE_RUN.md`. Never put the key in the repo, in chat, or in `log.txt`.

## Robustness and security

* **Untrusted evidence.** SQL runs in a sandboxed in-memory SQLite: no ATTACH, PRAGMA or
  extensions. Manifest paths must stay inside `dataset/evidence/`. Corrupt or oversized
  files are skipped with a warning instead of aborting the run.
* **Untrusted text.** Instruction-like segments ("SYSTEM:", "ignore previous instructions",
  "answer DELETION", in nine languages) are cut out of request text before classification;
  when present, the model cannot override the rule layer. Request and artifact text are
  delimited and treated as data, and model answers must match a strict schema. A model
  "delete" is vetoed when the request explicitly says to keep the account (six languages).
* **Edge-case requests.** All of these are handled:
  * timestamps in any ISO form are normalised to UTC;
  * a missing `audit_at` falls back to `reported_at`;
  * unknown emails are matched only on the exact address and its hash;
  * a reused email prefers its current owner;
  * duplicate or blank case ids are skipped;
  * empty request text is not a deletion.
* **Unknown states.** An unknown restore status, PII exposure or a missing retained record is
  never cited as proof in a COMPLETE answer.
* Details: `docs/SECURITY.md`. Warnings print to stderr. On this dataset the run prints two:
  the one restore-risk finding that rests on an unstated restore status (case_55), and the one
  catalog link whose screenshot shows a person outside the identity table (case_63).

## Reports

* `evaluation/evaluation_report.md`: metrics, custom cases, failures and fixes
* `evaluation/usage_report.md`: model calls, tokens and cost of the final full run
