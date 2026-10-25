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
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from identity import Identities, norm  # noqa: E402
import ingest  # noqa: E402
from ingest import load_activity, load_observations  # noqa: E402
from ingest.common import ts_norm  # noqa: E402
from intent import IntentClassifier  # noqa: E402
from planner import order_steps, serialize  # noqa: E402
from policy import Policy  # noqa: E402
from state import EvidenceIndex  # noqa: E402
import accounts  # noqa: E402
import intent as intent_module  # noqa: E402

ROOT = os.path.dirname(HERE)
DATASET = os.path.join(ROOT, "dataset")


def _load_env():
    path = os.path.join(ROOT, ".env")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.strip().split("=", 1)
                    os.environ.setdefault(k.strip().removeprefix("export ").strip(), v.strip().strip('"').strip("'"))


REQUIRED_FIELDS = ("case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at",
                   "request_text")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def normalize_request(raw):
    """Clean one request row; returns (request, problems).

    Timestamps are normalised to UTC ``...Z`` so the audit cut-off compares correctly.
    A missing / unparseable ``audit_at`` falls back to ``reported_at`` (the moment the
    claim was made); if neither is usable the case is audited against all evidence and
    the problem is reported."""
    req = {k: (raw.get(k) or "").strip() if isinstance(raw.get(k), str) else raw.get(k) for k in REQUIRED_FIELDS}
    req["request_text"] = raw.get("request_text") or ""
    problems = []
    for k in ("requested_at", "reported_at", "audit_at"):
        req[k] = ts_norm(req.get(k) or "")
    if not TS_RE.match(req["audit_at"] or ""):
        problems.append(f"invalid audit_at {raw.get('audit_at')!r}")
        req["audit_at"] = req["reported_at"] if TS_RE.match(req["reported_at"] or "") else "9999-12-31T23:59:59Z"
    if not TS_RE.match(req["requested_at"] or ""):
        problems.append(f"invalid requested_at {raw.get('requested_at')!r}")
        req["requested_at"] = "0000-01-01T00:00:00Z"
    if not req["email"]:
        problems.append("missing email")
    return req, problems


class Auditor:
    def __init__(self, dataset=DATASET, use_llm=None, batch_inference=True, episode_scoping=True):
        self.dataset = dataset
        # both heuristics were derived from a handful of samples; the flags exist so their
        # effect can be measured (evaluation/main.py --ablation)
        self.batch_inference = batch_inference
        self.episode_scoping = episode_scoping
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
        requests = [normalize_request(r)[0] for r in requests]
        if self.batch_inference:
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

    def _catalog_conflict(self, rid, users):
        """Compare a catalog-linked record with the identifiers printed on the record itself.

        Returns None when they agree (or the record prints none), "other" when the printed
        emails / phones / hashes belong to a different known user, and "unknown" when they
        belong to nobody in user_identities.csv."""
        keys = set().union(*(self.ids.keys(u) for u in users)) if users else set()
        printed = {norm(i) for o in self.index.by_resource.get(rid, []) for i in o.idents}
        printed = {k for k in printed if k and not k.startswith("user_")}
        if not printed or printed & keys:
            return None
        return "other" if self.ids.owners(printed) - set(users) else "unknown"

    def audit(self, raw_req, debug=False):
        req, problems = normalize_request(raw_req)
        dbg = {"case_id": req["case_id"], "problems": problems}
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
        if not users:
            # unknown address: only records carrying this exact email or its hash
            owned.update(self.index.owned_by_keys(self.ids.keys_for_unknown_email(req["email"])))
            problems.append("request email not found in user_identities.csv")
        for rid, how in sorted(owned.items()):
            conflict = self._catalog_conflict(rid, users) if how.startswith("catalog:") else None
            if conflict == "other":
                # the record's own content outweighs the catalog's claim: it is another person's
                del owned[rid]
                problems.append(f"{rid}: data-catalog link dropped; the record itself names another known user")
            elif conflict == "unknown":
                problems.append(f"{rid}: data-catalog link kept; the record prints identifiers of a person "
                                f"who is not in user_identities.csv, so no other owner can be shown")
        inferred = self.inferred_accounts.get(req["case_id"])
        if inferred and not any(r.startswith("account_") for r in owned):
            owned[inferred] = "inferred:deletion-batch"
        dbg["owned"] = owned
        states = []
        # earlier, already-audited deletion requests of the same subject (episode scoping)
        earlier = [r for uid in users for r in self.requests_by_user.get(uid, [])
                   if r["audit_at"] < req["requested_at"] and self.intent.classify(r["request_text"])[0]
                   ] if self.episode_scoping else []
        for rid in sorted(owned):
            if not owned[rid].startswith("inferred:") and not self._in_scope(rid, req, earlier):
                continue
            rs = self.index.state(rid, audit_at)
            if rs is None:
                # Linked, but no read-back visible at audit_at: only a future check is possible.
                states.append(_Unobserved(rid, self.index))
                continue
            problems.extend(rs.notes)
            states.append(rs)
        dbg["states"] = states
        findings, fixes, checks = [], [], []
        for rs in states:
            f, r, v, proven = self.policy.evaluate(rs)
            if f is None and v is None:
                problems.append(f"no deletion rule for category {rs.category} ({rs.resource_id})")
                continue
            if f and owned.get(rs.resource_id, "").startswith("inferred:"):
                # linked only through a deletion-batch claim: it may schedule a check, never a finding
                problems.append(f"{rs.resource_id}: linked only by a deletion-batch claim and read back present; "
                                f"left to verification instead of a finding")
                f, proven = None, False
            if f:
                if f[1] == "ACTIVE" and rs.active is None:
                    # rule_14 / COMPLETE definition: a path counts until evidence shows it closed
                    problems.append(f"{rs.resource_id}: {'restore' if f[0] == 'REPORT_RESTORE_RISK' else 'sync'} "
                                    f"status never stated (last read-back {rs.evidence_id}); reported as a "
                                    f"recreation path until evidence shows it blocked / disabled")
                findings.append(_step("FINDING", rs, f, rs.evidence_id))
                fixes.append(_step("REMEDIATION", rs, r, ""))
            if v:
                checks.append((rs, v, proven))
        status = "INCOMPLETE" if findings else "COMPLETE"
        verification = []
        for rs, v, proven in checks:
            if status == "COMPLETE":
                if not (proven and rs.evidence_id):
                    continue  # a COMPLETE case may only contain evidence-backed, proving checks
                verification.append(_step("VERIFICATION", rs, v, rs.evidence_id))
            else:
                verification.append(_step("VERIFICATION", rs, v, ""))
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
    return (prefix, int(num), "") if num.isdigit() else (case_id, 0, case_id)


def run(requests_path, out_path, use_llm=None, dataset=None):
    with open(requests_path, encoding="utf-8-sig") as fh:
        requests = list(csv.DictReader(fh))
    auditor = Auditor(dataset=dataset or DATASET, use_llm=use_llm)
    auditor.prepare()
    rows, seen, warnings = [], set(), list(ingest.WARNINGS)
    for req in sorted(requests, key=lambda r: case_sort_key((r.get("case_id") or "").strip())):
        cid = (req.get("case_id") or "").strip()
        if not cid or cid in seen:
            warnings.append(f"skipped request with empty or duplicate case_id {cid!r}")
            continue
        seen.add(cid)
        status, steps, dbg = auditor.audit(req)
        warnings += [f"{cid}: {p}" for p in dbg.get("problems", [])]
        rows.append((cid, status, serialize(steps)))
    rows.sort(key=lambda r: case_sort_key(r[0]))
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "deletion_status", "steps_json"])
        w.writerows(rows)
    os.replace(tmp, out_path)  # never leave a half-written output.csv behind
    for msg in warnings:
        print("warning:", msg, file=sys.stderr)
    if os.path.abspath(requests_path) == os.path.abspath(os.path.join(DATASET, "deletion_requests.csv")) \
            and os.path.abspath(out_path) == os.path.abspath(os.path.join(ROOT, "output.csv")):
        _write_run_summary(auditor, rows, requests_path, out_path)  # only the submission run feeds usage_report.md
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
        "intent_model": intent_module.MODEL,
        "media_cache_files": len([f for f in os.listdir(CACHE_DIR) if f.endswith(".json")]),
        "media_observations": len(media_files),
        "llm_enabled": auditor.intent.use_llm,
    }
    path = os.path.join(HERE, "cache", "last_run.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)


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
    ap.add_argument("--dataset", default=DATASET, help="dataset folder (default: ./dataset)")
    ap.add_argument("--refresh-media", action="store_true",
                    help="re-extract every PNG/PDF with the vision model (needs ANTHROPIC_API_KEY)")
    args = ap.parse_args()
    if args.refresh_media:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            sys.exit("--refresh-media needs ANTHROPIC_API_KEY in the environment")
        import ingest.media

        ingest.media.REFRESH = True
    if args.inspect:
        inspect(args.inspect)
        return
    auditor, rows = run(args.requests, args.out, use_llm=False if args.no_llm else None, dataset=args.dataset)
    counts = {}
    for _, st, _ in rows:
        counts[st] = counts.get(st, 0) + 1
    print(f"wrote {len(rows)} rows to {args.out}: {counts}; intent stats: "
          f"{ {k: v for k, v in auditor.intent.stats.items() if k != 'disagreements'} }")


if __name__ == "__main__":
    main()
