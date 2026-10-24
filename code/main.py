"""Ghost Data Still Exists - deletion-audit agent.

Usage (from the repository root):
    python3 code/main.py                       # audit dataset/deletion_requests.csv -> ./output.csv
    python3 code/main.py --inspect case_11     # print identities, evidence and decision for one case
    python3 code/main.py --requests dataset/sample_deletion_requests.csv --out /tmp/sample_pred.csv

Pipeline per case:
    intent (LLM + cache + rules) -> identity resolution -> evidence visible at audit_at
    -> ownership of resources -> latest state per resource -> deletion_rules policy
    -> ordered FINDING / REMEDIATION / VERIFICATION steps.
"""
import argparse
import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from identity import Identities  # noqa: E402
from ingest import load_activity, load_observations  # noqa: E402
from intent import IntentClassifier  # noqa: E402
from planner import order_steps, serialize  # noqa: E402
from policy import Policy  # noqa: E402
from state import EvidenceIndex  # noqa: E402
import accounts  # noqa: E402

ROOT = os.path.dirname(HERE)
DATASET = os.path.join(ROOT, "dataset")


def _load_env():
    path = os.path.join(ROOT, ".env")
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.strip().split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"'))


class Auditor:
    def __init__(self, dataset=DATASET, use_llm=None):
        self.dataset = dataset
        self.ids = Identities(dataset)
        self.observations = load_observations(dataset)
        self.activity, self.links = load_activity(dataset)
        self.index = EvidenceIndex(self.observations, self.links, self.ids)
        self.policy = Policy(dataset)
        self.intent = IntentClassifier(use_llm=use_llm)
        self.inferred_accounts = {}
        self.requests_by_user = {}

    def prepare(self):
        """Cross-case pass over every participant-visible request (evaluation + sample files):
        infer otherwise-unlinked primary accounts from deletion-worker batches."""
        requests = []
        for name in ("deletion_requests.csv", "sample_deletion_requests.csv"):
            path = os.path.join(self.dataset, name)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    requests += list(csv.DictReader(fh))
        self.inferred_accounts = accounts.infer_batch_accounts(requests, self.activity, self.index, self.ids)
        self.requests_by_user = {}
        for r in requests:
            for uid in self.ids.users_for_email(r["email"]):
                self.requests_by_user.setdefault(uid, []).append(r)

    def _in_scope(self, rid, req, earlier):
        """Episode scoping for one request.

        A resource is in scope when some observation of it describes the world at or
        before audit_at (its observed_at, even if the file was exported later). If every
        such observation is already covered by an earlier, closed request of the same
        subject (observed before that request's audit_at), it belongs to that episode.
        """
        times = [o.observed_at for o in self.index.by_resource.get(rid, []) if o.observed_at <= req["audit_at"]]
        if not times:
            return False
        if earlier and all(any(t <= e["audit_at"] for e in earlier) for t in times):
            return False
        return True

    def audit(self, req, debug=False):
        dbg = {"case_id": req["case_id"]}
        is_del, src, reason = self.intent.classify(req["request_text"])
        dbg["intent"] = (is_del, src, reason)
        if not is_del:
            return "NOT_APPLICABLE", [], dbg
        users = self.ids.users_for_email(req["email"])
        dbg["users"] = users
        audit_at = req["audit_at"]
        owned = {}
        for uid in users:
            owned.update(self.index.owned_resources(uid, audit_at))
        inferred = self.inferred_accounts.get(req["case_id"])
        if inferred and not any(r.startswith("account_") for r in owned):
            owned[inferred] = "inferred:deletion-batch"
        dbg["owned"] = owned
        states = []
        earlier = [r for uid in users for r in self.requests_by_user.get(uid, [])
                   if r["audit_at"] < req["requested_at"]]
        for rid in sorted(owned):
            if not owned[rid].startswith("inferred:") and not self._in_scope(rid, req, earlier):
                continue
            rs = self.index.state(rid, audit_at)
            if rs is None:
                # Linked, but no read-back visible at audit_at: only a future check is possible.
                states.append(_Unobserved(rid, self.index))
                continue
            states.append(rs)
        dbg["states"] = states
        findings, fixes, checks = [], [], []
        for rs in states:
            f, r, v = self.policy.evaluate(rs)
            if f:
                findings.append(_step("FINDING", rs, f, rs.evidence_id))
                fixes.append(_step("REMEDIATION", rs, r, ""))
            if v:
                checks.append((rs, v))
        status = "INCOMPLETE" if findings else "COMPLETE"
        verification = []
        for rs, v in checks:
            ev = "" if status == "INCOMPLETE" else (rs.evidence_id or "")
            if status == "COMPLETE" and not ev:
                continue  # a COMPLETE case may only contain evidence-backed checks
            verification.append(_step("VERIFICATION", rs, v, ev))
        steps = order_steps(findings + fixes + verification)
        return status, steps, dbg


class _Unobserved:
    """A linked resource with no read-back visible at audit_at (verification only, no evidence)."""

    def __init__(self, rid, index):
        from ingest.common import SYSTEM_CATEGORY, system_for

        obs = index.by_resource.get(rid, [])
        self.system_id = obs[0].system_id if obs else system_for(rid)
        self.resource_id = rid
        self.category = obs[0].category if obs else SYSTEM_CATEGORY.get(self.system_id, "UNKNOWN")
        # assume the required final state already holds; this can only add a check, never a finding
        self.exists = self.category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD")
        self.exposed, self.active = False, False
        self.evidence_id, self.observed_at, self.history = "", "", []

    def __repr__(self):
        return f"<{self.system_id}/{self.resource_id} (no read-back at audit_at; verify only)>"


def _step(phase, rs, op_state, evidence_id):
    op, state = op_state
    return {"phase": phase, "system_id": rs.system_id, "resource_id": rs.resource_id,
            "operation": op, "state": state, "evidence_id": evidence_id or ""}


def case_sort_key(case_id):
    """Natural order (case_33 < case_100), matching the order of deletion_requests.csv."""
    prefix, _, num = case_id.rpartition("_")
    return (prefix, int(num)) if num.isdigit() else (case_id, 0)


def run(requests_path, out_path, use_llm=None):
    with open(requests_path, encoding="utf-8") as fh:
        requests = list(csv.DictReader(fh))
    auditor = Auditor(use_llm=use_llm)
    auditor.prepare()
    rows = []
    for req in sorted(requests, key=lambda r: case_sort_key(r["case_id"])):
        status, steps, _ = auditor.audit(req)
        rows.append((req["case_id"], status, serialize(steps)))
    rows.sort(key=lambda r: case_sort_key(r[0]))
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "deletion_status", "steps_json"])
        w.writerows(rows)
    _write_run_summary(auditor, rows, requests_path, out_path)
    return auditor, rows


def _write_run_summary(auditor, rows, requests_path, out_path):
    """Record what this run did so usage_report.md is generated from facts, not estimates."""
    import json
    import time

    import ledger
    from ingest.media import CACHE_DIR

    media_files = [o for o in auditor.observations if o.source == "media"]
    statuses = {}
    for _, st, _ in rows:
        statuses[st] = statuses.get(st, 0) + 1
    summary = {
        "run_id": ledger.RUN_ID,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "requests_file": os.path.relpath(requests_path, ROOT),
        "output_file": os.path.relpath(out_path, ROOT),
        "requests": len(rows),
        "statuses": statuses,
        "intent": {k: v for k, v in auditor.intent.stats.items() if k != "disagreements"},
        "intent_disagreements": len(auditor.intent.stats["disagreements"]),
        "intent_model": __import__("intent").MODEL,
        "media_cache_files": len([f for f in os.listdir(CACHE_DIR) if f.endswith(".json")]),
        "media_observations": len(media_files),
        "llm_enabled": auditor.intent.use_llm,
    }
    path = os.path.join(HERE, "cache", "last_run.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump(summary, open(path, "w", encoding="utf-8"), indent=2)


def inspect(case_id):
    requests = []
    for name in ("deletion_requests.csv", "sample_deletion_requests.csv"):
        with open(os.path.join(DATASET, name), encoding="utf-8") as fh:
            requests += list(csv.DictReader(fh))
    req = next((r for r in requests if r["case_id"] == case_id), None)
    if req is None:
        sys.exit(f"unknown case {case_id}")
    auditor = Auditor()
    auditor.prepare()
    status, steps, dbg = auditor.audit(req, debug=True)
    print(f"== {case_id}  email={req['email']}  audit_at={req['audit_at']}  reported={req['reported_status']}")
    print("request:", req["request_text"])
    print("intent:", dbg["intent"])
    for uid in dbg.get("users", []):
        print("identity:", auditor.ids.describe(uid))
    for rid, how in sorted(dbg.get("owned", {}).items()):
        print(f"  owned {rid:<22} via {how}")
    for rs in dbg.get("states", []):
        print("  state", rs)
        for o in getattr(rs, "history", []):
            vis = "" if o.captured_at <= req["audit_at"] else "  (after audit_at)"
            print(f"      {o.file_id:<12} {o.observed_at} exists={o.exists} exposed={o.exposed} "
                  f"active={o.active} cat={o.category} {o.source}{vis}")
    print("status:", status)
    for s in steps:
        print("  ", s)


def main():
    _load_env()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--requests", default=os.path.join(DATASET, "deletion_requests.csv"))
    ap.add_argument("--out", default=os.path.join(ROOT, "output.csv"))
    ap.add_argument("--inspect", metavar="CASE_ID")
    ap.add_argument("--no-llm", action="store_true", help="use only the rule-based intent classifier")
    args = ap.parse_args()
    if args.inspect:
        inspect(args.inspect)
        return
    auditor, rows = run(args.requests, args.out, use_llm=False if args.no_llm else None)
    counts = {}
    for _, st, _ in rows:
        counts[st] = counts.get(st, 0) + 1
    print(f"wrote {len(rows)} rows to {args.out}: {counts}; intent stats: "
          f"{ {k: v for k, v in auditor.intent.stats.items() if k != 'disagreements'} }")


if __name__ == "__main__":
    main()
