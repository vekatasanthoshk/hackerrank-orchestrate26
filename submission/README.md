# Submission files

Upload at https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists

| File | Upload slot | How it was produced |
|---|---|---|
| `code.zip` | Code zip | `python3 code/package_submission.py` (the `code/` folder only: no `dataset/`, venv, caches of secrets or ledger) |
| `output.csv` | Predictions CSV | `python3 code/main.py` (518 rows; `python3 code/evaluation/validate_output.py` -> 0 problems) |
| `log.txt` | Chat transcript | appended by Claude Code per AGENTS.md |

`output.csv` and `log.txt` here are copies of the root files at packaging time.

The agent trace (session transcripts) is **not** kept in this repository: it contains the
account email. Build `agent-trace.zip` outside the repo and upload it directly
(`code/docs/LIVE_RUN.md`, section 4).

Before the final upload, check `code/evaluation/usage_report.md`: until the live run in
`code/docs/LIVE_RUN.md` has been done with an API key, it reports 0 model calls and every
answer comes from the rule layer and the cached transcriptions.
