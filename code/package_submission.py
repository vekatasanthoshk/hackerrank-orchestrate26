"""Build the HackerRank upload files into ./submission/ (run from anywhere).

    python3 code/package_submission.py

* submission/code.zip   - the code/ directory only (no dataset, caches of secrets,
                          bytecode, temp files, or the usage ledger)
* submission/output.csv - copy of ./output.csv after it passes validate_output.py
* submission/log.txt    - copy of ./log.txt (chat transcript) after check_log() passes

The agent trace is deliberately not built here: session transcripts contain the whole
conversation and must not be committed. Upload it separately (see code/docs/LIVE_RUN.md).
"""
import os
import re
import shutil
import subprocess
import sys
import zipfile

CODE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(CODE)
OUT = os.path.join(ROOT, "submission")
EXCLUDE_DIRS = {"__pycache__", ".venv", "venv", "node_modules", ".git"}
EXCLUDE_FILES = {"usage_ledger.jsonl", ".env"}
EXCLUDE_SUFFIX = (".pyc", ".tmp", ".zip")


def check_log(path):
    """Problems in the transcript that a merge of two sessions' appends can introduce:
    conflict markers, entries out of time order, duplicated entries, and entries without
    exactly one tool= and one model= line (AGENTS.md section 5)."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    problems = []
    if re.search(r"^(<<<<<<<|=======|>>>>>>>)", text, re.M):
        problems.append("merge conflict markers")
    entries = [e for e in re.split(r"(?=^## \[)", text, flags=re.M) if e.startswith("## [")]
    heads = [e.split("\n", 1)[0] for e in entries]
    stamps = [h[4:h.index("]")] for h in heads]
    problems += [f"out of order: {b}" for a, b in zip(heads, heads[1:]) if b[4:b.index("]")] < a[4:a.index("]")]]
    problems += [f"duplicate entry: {h}" for h in sorted({h for h in heads if heads.count(h) > 1 and "SESSION START" not in h})]
    for head, entry in zip(heads, entries):
        if len(re.findall(r"^tool=\S", entry, re.M)) != 1 or len(re.findall(r"^model=\S", entry, re.M)) != 1:
            problems.append(f"needs exactly one tool= and one model= line: {head}")
    return problems if stamps else ["no entries"]


def build_zip(path):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for base, dirs, files in os.walk(CODE):
            dirs[:] = sorted(d for d in dirs if d not in EXCLUDE_DIRS)
            for name in sorted(files):
                if name in EXCLUDE_FILES or name.endswith(EXCLUDE_SUFFIX) or name.startswith(".env"):
                    continue
                full = os.path.join(base, name)
                zf.write(full, os.path.relpath(full, ROOT))


def main():
    check = subprocess.run([sys.executable, os.path.join(CODE, "evaluation", "validate_output.py")],
                           capture_output=True, text=True)
    print(check.stdout.strip())
    if check.returncode != 0:
        sys.exit("output.csv failed validation; not packaging")
    log_problems = check_log(os.path.join(ROOT, "log.txt"))
    if log_problems:
        sys.exit("log.txt failed its checks; not packaging:\n  " + "\n  ".join(log_problems))
    os.makedirs(OUT, exist_ok=True)
    build_zip(os.path.join(OUT, "code.zip"))
    shutil.copy(os.path.join(ROOT, "output.csv"), OUT)
    shutil.copy(os.path.join(ROOT, "log.txt"), OUT)
    with zipfile.ZipFile(os.path.join(OUT, "code.zip")) as zf:
        names = zf.namelist()
    bad = [n for n in names if n.startswith("dataset/") or "/." in n or n.endswith(".zip")]
    if bad:
        sys.exit(f"unexpected files in code.zip: {bad[:5]}")
    print(f"submission/code.zip: {len(names)} files; submission/output.csv and log.txt copied")


if __name__ == "__main__":
    main()
