"""Run ledger: every model call appends its token usage here (code/cache/usage_ledger.jsonl).

usage_report.md is generated from this file, so the reported numbers are the
real ``usage`` blocks returned by the API rather than estimates.
"""
import json
import os
import time

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache", "usage_ledger.jsonl")
RUN_ID = os.environ.get("RUN_ID") or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def record(purpose, model, usage, ref="", cached=False):
    os.makedirs(os.path.dirname(PATH), exist_ok=True)
    row = {
        "run_id": RUN_ID, "purpose": purpose, "model": model, "ref": ref, "cached": cached,
        "input_tokens": getattr(usage, "input_tokens", 0) if usage else 0,
        "output_tokens": getattr(usage, "output_tokens", 0) if usage else 0,
    }
    with open(PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")


def load(run_id=None):
    if not os.path.exists(PATH):
        return []
    with open(PATH, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]
    return [r for r in rows if run_id is None or r["run_id"] == run_id]
