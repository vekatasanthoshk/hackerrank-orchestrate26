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
            with open(os.path.join(folder, name), encoding="utf-8") as fh:
                cases.append(json.load(fh))
    return cases


def predict(auditor, requests):
    from planner import serialize  # noqa: F401  (serialisation is exercised in main.run)

    out = {}
    for req in requests:
        st, steps, _ = auditor.audit(req)
        out[req["case_id"]] = (st, steps)
    return out


# Intent probes, oldest first. Each was written before the rule change it measured and scored once
# as held-out (that first score is recorded in evaluation_report.md); every one except the last was
# then used to fix the rules, so it now counts as a dev set. Only the last one is still held out.
PROBES = (("dev-1", "intent_probe.json"), ("dev-2", "intent_probe_heldout.json"),
          ("dev-3", "intent_probe_heldout_v3.json"), ("dev-4", "intent_probe_heldout_v4.json"),
          ("dev-5", "intent_probe_heldout_v5.json"), ("held-out", "intent_probe_heldout_v6.json"))


def score_intent_probes(auditor):
    """Score the rule layer on every probe, and the configured classifier (the LLM when a key
    is set). Reports misses and false deletions (non-deletion text treated as deletion)."""
    from intent import rule_intent, sanitize

    out = []
    for name, fname in PROBES:
        path = os.path.join(HERE, fname)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            probe = json.load(fh)
        probe = probe["cases"] if isinstance(probe, dict) else probe
        rules = sum(rule_intent(sanitize(p["text"])[0])[0] == p["expected"] for p in probe)
        labels = ["DELETION" if auditor.intent.classify(p["text"])[0] else "NOT_DELETION" for p in probe]
        active = sum(lab == p["expected"] for lab, p in zip(labels, probe))
        unsafe = sum(lab == "DELETION" and p["expected"] == "NOT_DELETION" for lab, p in zip(labels, probe))
        misses = [p["text"] for lab, p in zip(labels, probe) if lab != p["expected"]]
        out.append({"name": name, "file": fname, "n": len(probe), "rules_correct": rules, "active_correct": active,
                    "active_source": "llm" if auditor.intent.use_llm else "rules", "false_deletions": unsafe,
                    "misses": misses})
    return out


def ablation(sample_reqs, gold):
    """Effect of the two sample-derived heuristics: on the samples (score) and on the 518 requests
    (how many answers change). Both are evidence-free inferences, so this is reported, not hidden."""
    from main import Auditor, DATASET

    with open(os.path.join(DATASET, "deletion_requests.csv"), encoding="utf-8") as fh:
        eval_reqs = list(csv.DictReader(fh))
    variants = {"full pipeline": {}, "without batch account inference": {"batch_inference": False},
                "without episode scoping": {"episode_scoping": False}}
    rows, base_eval = [], None
    for label, kw in variants.items():
        a = Auditor(use_llm=False, **kw)
        a.prepare()
        s, _ = score(predict(a, sample_reqs), gold)
        ev = predict(a, eval_reqs)
        base_eval = base_eval or ev
        changed = sum(ev[c] != base_eval[c] for c in ev)
        status = sum(ev[c][0] != base_eval[c][0] for c in ev)
        rows.append((label, s, changed, status))
    return rows


def print_summary(title, s):
    print(f"\n### {title}")
    for k, v in s.items():
        print(f"  {k:<20} {v:.3f}" if isinstance(v, float) else f"  {k:<20} {v}")


FIXTURES = os.path.join(HERE, "fixtures")


def run_fixtures():
    """Synthetic fixture cases: fixtures/cases.json against the hand-built fixture dataset (plus the
    challenge's deletion_rules.csv). Expected answers follow from how the fixture was built."""
    import shutil
    import tempfile

    from main import Auditor, DATASET

    path = os.path.join(FIXTURES, "cases.json")
    if not os.path.exists(path):
        return None, []
    with open(path, encoding="utf-8") as fh:
        cases = json.load(fh)["cases"]
    with tempfile.TemporaryDirectory() as tmp:
        ds = os.path.join(tmp, "dataset")
        shutil.copytree(os.path.join(FIXTURES, "dataset"), ds)
        shutil.copy(os.path.join(DATASET, "deletion_rules.csv"), ds)
        auditor = Auditor(dataset=ds, use_llm=False)
        auditor.prepare()
        with open(os.path.join(ds, "deletion_requests.csv"), encoding="utf-8") as fh:
            reqs = {r["case_id"]: r for r in csv.DictReader(fh)}
        pred = {c["case_id"]: auditor.audit(reqs[c["case_id"]])[:2] for c in cases}
    gold = {c["case_id"]: (c["expected"]["deletion_status"], c["expected"]["steps"]) for c in cases}
    return score(pred, gold)


def print_suite(title, summary, cases, quiet):
    print_summary(title, summary)
    for c in cases:
        print(f"  {'PASS' if c['exact'] else 'FAIL'} {c['case_id']}: {c['pred_status']} (expected {c['gold_status']})")
        if not c["exact"] and not quiet:
            for k in c["missing"]:
                print("      - missing", k)
            for k in c["extra"]:
                print("      + extra  ", k)
            for d in c["evidence_diffs"]:
                print("      ~ evidence", d)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--ablation", action="store_true", help="also measure the two sample-derived heuristics")
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
        cpred = {c["request"]["case_id"]: auditor.audit(c["request"])[:2] for c in custom}
        c_summary, c_cases = score(cpred, cgold)
        print_suite(f"Custom cases on the challenge evidence ({len(custom)})", c_summary, c_cases, args.quiet)
    f_summary, f_cases = run_fixtures()
    if f_summary:
        print_suite(f"Synthetic fixture cases ({len(f_cases)})", f_summary, f_cases, args.quiet)
    probes = score_intent_probes(auditor)
    for p in probes:
        print(f"\n### Intent probe, {p['name']} ({p['n']} texts, {p['file']})\n  rules {p['rules_correct']}/{p['n']}, "
              f"active classifier ({p['active_source']}) {p['active_correct']}/{p['n']}, "
              f"false deletions {p['false_deletions']}")
        for t in p["misses"]:
            print("      miss:", t)
    abl = None
    if args.ablation:
        abl = ablation(sample_reqs, gold)
        print("\n### Ablation of the sample-derived heuristics")
        for label, s, changed, status in abl:
            print(f"  {label:<36} samples recall {s['step_recall']:.3f} precision {s['step_precision']:.3f} "
                  f"status {s['status_accuracy']:.3f}; evaluation answers changed {changed} (status {status})")
    if args.write_report:
        write_metrics(s_summary, s_cases, c_summary, c_cases, f_summary, f_cases, probes, abl)


def write_metrics(s_summary, s_cases, c_summary, c_cases, f_summary=None, f_cases=(), probes=(), abl=None):
    path = os.path.join(HERE, "evaluation_report.md")
    fmt = (lambda x: f"{x:.3f}" if isinstance(x, float) else str(x))  # noqa: E731
    lines = ["<!-- METRICS:START (generated by code/evaluation/main.py --write-report) -->", "",
             "| Metric | Public samples (32) | Custom cases | Synthetic fixtures |", "|---|---|---|---|"]
    for k, v in s_summary.items():
        cv = fmt(c_summary[k]) if c_summary else ""
        fv = fmt(f_summary[k]) if f_summary else ""
        lines.append(f"| {k} | {fmt(v)} | {cv} | {fv} |")
    lines += ["", "Per-case sample results:", "", "| case | gold | pred | exact | missing steps | extra steps |",
              "|---|---|---|---|---|---|"]
    for c in s_cases:
        lines.append(f"| {c['case_id']} | {c['gold_status']} | {c['pred_status']} | {'yes' if c['exact'] else 'no'} | "
                     f"{len(c['missing'])} | {len(c['extra'])} |")
    for title, cases in (("Custom cases (challenge evidence)", c_cases), ("Synthetic fixture cases", f_cases)):
        if cases:
            lines += ["", f"{title}:", "", "| case | expected | predicted | pass |", "|---|---|---|---|"]
            for c in cases:
                lines.append(f"| {c['case_id']} | {c['gold_status']} | {c['pred_status']} | "
                             f"{'yes' if c['exact'] else 'no'} |")
    if probes:
        lines += ["", "Intent probes:", "", "| probe | texts | rule layer | classifier used in this run | false deletions |",
                  "|---|---|---|---|---|"]
        for p in probes:
            lines.append(f"| {p['name']} (`evaluation/{p['file']}`) | {p['n']} | {p['rules_correct']}/{p['n']} | "
                         f"{p['active_source']}: {p['active_correct']}/{p['n']} | {p['false_deletions']} |")
    if abl:
        lines += ["", "Ablation of the sample-derived heuristics (rule intent, no model):", "",
                  "| variant | sample recall | sample precision | sample status | evaluation answers changed |",
                  "|---|---|---|---|---|"]
        for label, s, changed, status in abl:
            lines.append(f"| {label} | {s['step_recall']:.3f} | {s['step_precision']:.3f} | "
                         f"{s['status_accuracy']:.3f} | {changed} ({status} status) |")
    lines += ["", "<!-- METRICS:END -->"]
    block = "\n".join(lines)
    text = "<!-- METRICS:START --><!-- METRICS:END -->"
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    start, end = text.find("<!-- METRICS:START"), text.find("<!-- METRICS:END -->")
    text = text[:start] + block + text[end + len("<!-- METRICS:END -->"):]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"\nupdated {path}")


if __name__ == "__main__":
    main()
