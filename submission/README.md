# Submission files

Upload at https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists

| File | Upload slot | How it was produced |
|---|---|---|
| `code.zip` | Code zip | `zip -qr code.zip code -x "*/__pycache__/*" "*.pyc"` (no dataset/, no venv) |
| `output.csv` | Predictions CSV | `python3 code/main.py` (518 rows; `python3 code/evaluation/validate_output.py` -> 0 problems) |
| `log.txt` | Chat transcript | appended by Claude Code per AGENTS.md |
| `agent-trace.zip` | Agent trace (if a slot exists) | Claude Code session JSONL snapshot, see `agent-trace/claude-code/README.txt` |

`output.csv` and `log.txt` here are copies of the root files at commit time.
