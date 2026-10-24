"""Score predictions against sample_output.csv and the hand-built custom cases.

    python3 code/evaluation/main.py                 # samples + custom cases, summary + per-case diffs
    python3 code/evaluation/main.py --quiet         # summary only
    python3 code/evaluation/main.py --write-report  # also regenerate the metrics block of evaluation_report.md

Metrics
  status accuracy      deletion_status exact match per case
  step P / R / F1      multiset match on (phase, system_id, resource_id, operation, state)
  field accuracy       per field, over gold steps aligned to a predicted step with the
                       same (system_id, resource_id, operation): phase, state, evidence_id
  evidence accuracy    evidence_id correct among aligned steps
  sequence exact       predicted step list identical to gold (all 7 fields, in order)
  sequence LCS         longest common subsequence of step keys / max(len)
"""
import argparse
import csv
import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
CODE = os.path.dirname(HERE)
ROOT = os.path.dirname(CODE)
sys.path.insert(0, CODE)

KEY = ("phase", "system_id", "resource_id", "operation", "state")


def step_key(s):
    return tuple(s[k] for k in KEY)


def lcs(a, b):
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a)):
        for j in range(len(b)):
            dp[i + 1][j + 1] = dp[i][j] + 1 if a[i] == b[j] else max(dp[i][j + 1], dp[i + 1][j])
    return dp[-1][-1]


def score(pred, gold):
    """pred/gold: {case_id: (status, steps)}"""
    m = Counter()
    per_case = []
    for cid, (gst, gsteps) in sorted(gold.items()):
        pst, psteps = pred.get(cid, ("MISSING", []))
        m["cases"] += 1
        m["status_ok"] += pst == gst
        gk, pk = Counter(map(step_key, gsteps)), Counter(map(step_key, psteps))
        tp = sum((gk & pk).values())
        m["tp"] += tp
        m["gold_steps"] += sum(gk.values())
        m["pred_steps"] += sum(pk.values())
        pidx = {(s["system_id"], s["resource_id"], s["operation"]): s for s in psteps}
        for g in gsteps:
            p = pidx.get((g["system_id"], g["resource_id"], g["operation"]))
            if p is None:
                continue
            m["aligned"] += 1
            for f in ("phase", "state", "evidence_id", "step_no"):
                m[f"field_{f}"] += p[f] == g[f]
        full = [tuple(s[k] for k in KEY + ("evidence_id", "step_no")) for s in psteps]
        gfull = [tuple(s[k] for k in KEY + ("evidence_id", "step_no")) for s in gsteps]
        exact = pst == gst and full == gfull
        m["seq_exact"] += exact
        denom = max(len(gsteps), len(psteps))
        m["seq_lcs"] += 1.0 if denom == 0 else lcs(list(map(step_key, psteps)), list(map(step_key, gsteps))) / denom
        per_case.append({
            "case_id": cid, "gold_status": gst, "pred_status": pst, "exact": exact,
            "missing": sorted(set(gk) - set(pk)), "extra": sorted(set(pk) - set(gk)),
            "evidence_diffs": [(g["resource_id"], g["operation"], g["evidence_id"], pidx[(g["system_id"], g["resource_id"], g["operation"])]["evidence_id"])
                               for g in gsteps if (g["system_id"], g["resource_id"], g["operation"]) in pidx
                               and pidx[(g["system_id"], g["resource_id"], g["operation"])]["evidence_id"] != g["evidence_id"]],
        })
    n = max(m["cases"], 1)
    prec = m["tp"] / max(m["pred_steps"], 1)
    rec = m["tp"] / max(m["gold_steps"], 1)
    al = max(m["aligned"], 1)
    summary = {
        "cases": m["cases"],
        "status_accuracy": m["status_ok"] / n,
        "step_precision": prec, "step_recall": rec,
        "step_f1": 0 if prec + rec == 0 else 2 * prec * rec / (prec + rec),
        "aligned_steps": m["aligned"],
        "field_phase_acc": m["field_phase"] / al, "field_state_acc": m["field_state"] / al,
        "field_step_no_acc": m["field_step_no"] / al,
        "evidence_id_acc": m["field_evidence_id"] / al,
        "sequence_exact": m["seq_exact"] / n, "sequence_lcs": m["seq_lcs"] / n,
    }
    return summary, per_case


def load_csv_outputs(path):
    out = {}
    with open(path, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            out[r["case_id"]] = (r["deletion_status"], json.loads(r["steps_json"]))
    return out


def load_custom_cases():
    cases = []
    folder = os.path.join(HERE, "custom_cases")
    for name in sorted(os.listdir(folder)):
        if name.endswith(".json"):
            cases.append(json.load(open(os.path.join(folder, name), encoding="utf-8")))
    return cases


def predict(auditor, requests):
    from planner import serialize  # noqa: F401  (serialisation is exercised in main.run)

    out = {}
    for req in requests:
        st, steps, _ = auditor.audit(req)
        out[req["case_id"]] = (st, steps)
    return out


def print_summary(title, s):
    print(f"\n### {title}")
    for k, v in s.items():
        print(f"  {k:<20} {v:.3f}" if isinstance(v, float) else f"  {k:<20} {v}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--write-report", action="store_true")
    args = ap.parse_args()
    from main import Auditor, DATASET, _load_env

    _load_env()
    auditor = Auditor(use_llm=False if args.no_llm else None)
    auditor.prepare()
    with open(os.path.join(DATASET, "sample_deletion_requests.csv"), encoding="utf-8") as fh:
        sample_reqs = list(csv.DictReader(fh))
    gold = load_csv_outputs(os.path.join(DATASET, "sample_output.csv"))
    pred = predict(auditor, sample_reqs)
    s_summary, s_cases = score(pred, gold)
    print_summary("Public samples (32)", s_summary)
    if not args.quiet:
        for c in s_cases:
            if c["exact"]:
                continue
            print(f"  {c['case_id']}: status {c['pred_status']} (gold {c['gold_status']})")
            for k in c["missing"]:
                print("      - missing", k)
            for k in c["extra"]:
                print("      + extra  ", k)
            for d in c["evidence_diffs"]:
                print("      ~ evidence", d)
    custom = load_custom_cases()
    c_summary, c_cases = None, []
    if custom:
        cgold = {c["request"]["case_id"]: (c["expected"]["deletion_status"], c["expected"]["steps"]) for c in custom}
        cpred = {}
        for c in custom:
            st, steps, _ = auditor.audit(c["request"])
            if c["expected"].get("check") == "status_only":
                steps = c["expected"]["steps"] if st == c["expected"]["deletion_status"] else steps
            cpred[c["request"]["case_id"]] = (st, steps)
        c_summary, c_cases = score(cpred, cgold)
        print_summary(f"Custom cases ({len(custom)})", c_summary)
        for c in c_cases:
            flag = "PASS" if c["exact"] else "FAIL"
            print(f"  {flag} {c['case_id']}: {c['pred_status']} (expected {c['gold_status']})")
            if not c["exact"] and not args.quiet:
                for k in c["missing"]:
                    print("      - missing", k)
                for k in c["extra"]:
                    print("      + extra  ", k)
    if args.write_report:
        write_metrics(s_summary, s_cases, c_summary, c_cases)


def write_metrics(s_summary, s_cases, c_summary, c_cases):
    path = os.path.join(HERE, "evaluation_report.md")
    lines = ["<!-- METRICS:START (generated by code/evaluation/main.py --write-report) -->", "",
             "| Metric | Public samples (32) | Custom cases |", "|---|---|---|"]
    for k, v in s_summary.items():
        cv = c_summary.get(k, "") if c_summary else ""
        fmt = (lambda x: f"{x:.3f}" if isinstance(x, float) else str(x))
        lines.append(f"| {k} | {fmt(v)} | {fmt(cv) if cv != '' else ''} |")
    lines += ["", "Per-case sample results:", "", "| case | gold | pred | exact | missing steps | extra steps |",
              "|---|---|---|---|---|---|"]
    for c in s_cases:
        lines.append(f"| {c['case_id']} | {c['gold_status']} | {c['pred_status']} | {'yes' if c['exact'] else 'no'} | "
                     f"{len(c['missing'])} | {len(c['extra'])} |")
    if c_cases:
        lines += ["", "Custom cases:", "", "| case | expected | predicted | pass |", "|---|---|---|---|"]
        for c in c_cases:
            lines.append(f"| {c['case_id']} | {c['gold_status']} | {c['pred_status']} | {'yes' if c['exact'] else 'no'} |")
    lines += ["", "<!-- METRICS:END -->"]
    block = "\n".join(lines)
    text = open(path, encoding="utf-8").read() if os.path.exists(path) else "<!-- METRICS:START --><!-- METRICS:END -->"
    start, end = text.find("<!-- METRICS:START"), text.find("<!-- METRICS:END -->")
    text = text[:start] + block + text[end + len("<!-- METRICS:END -->"):]
    open(path, "w", encoding="utf-8").write(text)
    print(f"\nupdated {path}")


if __name__ == "__main__":
    main()
