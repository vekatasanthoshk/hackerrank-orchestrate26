# Live run with real model calls

The submitted pipeline works without a key: the rule-based intent classifier runs, and the
media extractions come from the cache. This runbook makes the two model stages run for real.
Haiku classifies request intent. Sonnet vision re-extracts the 15 PNG/PDF artifacts. Every
API `usage` block lands in the ledger behind `usage_report.md`.

## 1. Store the key safely (never in the repo, chat, or log)

* **Claude Code cloud session:** open the cloud environment menu in the session's title bar,
  choose **Edit**, and add the key under **Network secrets** (or as an environment variable)
  named **`ANTHROPIC_API_KEY`**. A *new* session picks it up. Start one with
  `vekatasanthoshk/hackerrank-orchestrate26` selected.
* **Your own machine:** create `.env` in the repository root with the line
  `ANTHROPIC_API_KEY=sk-ant-...`. `.env` and `.env.*` are git-ignored, and `main.py` loads
  the file automatically.

Do not paste the key into a chat or commit message: `log.txt` records prompts verbatim and is
submitted.

## 2. Run (from the repository root)

```bash
pip install -r code/requirements.txt                 # anthropic + pymupdf
python3 code/main.py --refresh-media                 # vision re-extraction + LLM intent -> output.csv
python3 code/evaluation/compare_media.py             # model vs earlier transcription -> media_comparison.md
python3 code/evaluation/main.py --ablation --write-report  # samples, custom, fixtures, both intent probes
python3 code/evaluation/usage_report.py              # real calls / tokens / cost of the final run
python3 -m unittest discover -s code/tests           # 49 tests (incl. offline real-SDK checks)
python3 code/package_submission.py                   # validates output.csv, rebuilds submission/
git add -A && git commit -m "Live model run" && git push
```

`--refresh-media` moves each earlier transcription to `code/cache/media_manual/` (once) and
caches the model's answer in `code/cache/media/`. Each later run re-uses the cache at zero cost.
The real run makes about 375 Haiku calls (one per distinct request text) and 15 Sonnet vision
calls. The projected total cost is a few US cents; `usage_report.md` shows the measured figure.

## 3. Check before submitting

* Read the console warnings (stderr) and `media_comparison.md`. If the model extracted a fact
  differently from the transcription, decide which is right before submitting.
* There must be no `intent model calls failed` or `vision extraction failed` warning. Those
  mean the run fell back to the rules or the earlier transcription for some inputs, so it is
  not a full model run.
* `usage_report.md` must show non-zero calls for `claude-haiku-5-5` and `claude-sonnet-5-5`.
* `python3 code/evaluation/validate_output.py` must report 0 problems.

## 4. Agent trace

Session transcripts contain the whole conversation (including your email) and are **not**
committed. Build `agent-trace.zip` outside the repo (copy the session JSONL files from
`~/.claude/projects/`, or use the session's export), and upload it directly to HackerRank.
