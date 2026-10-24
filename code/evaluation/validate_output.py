"""Contract checks for the submission file (default: ./output.csv).

    python3 code/evaluation/validate_output.py [path]

Checks: exact header, one row per case in dataset/deletion_requests.csv, sorted by
case_id (natural order, as in deletion_requests.csv), allowed statuses, parseable JSON arrays, exactly the seven step fields,
allowed phase/operation/state triples, consecutive step_no from 1, phase order,
NOT_APPLICABLE -> [], COMPLETE -> verification steps with evidence only,
INCOMPLETE -> findings cite evidence and remediation/verification use "",
every cited id exists (file_id / activity_id / audit_id) and no cited file was
captured after the case's audit_at.
"""
import csv
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DS = os.path.join(ROOT, "dataset")
ALLOWED = {
    "FINDING": {"REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
                "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE"},
    "REMEDIATION": {"DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED", "DELETE_RECORD": "ABSENT",
                    "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED"},
    "VERIFICATION": {"VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT",
                     "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
                     "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED"},
}
FIELDS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
PHASE_RANK = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}


def main(path):
    errors, warnings = [], []
    with open(os.path.join(DS, "deletion_requests.csv"), encoding="utf-8") as fh:
        reqs = {r["case_id"]: r for r in csv.DictReader(fh)}
    with open(os.path.join(DS, "evidence_files.csv"), encoding="utf-8") as fh:
        files = {r["file_id"]: r["captured_at"] for r in csv.DictReader(fh)}
    with open(os.path.join(DS, "system_activity.csv"), encoding="utf-8") as fh:
        acts = {r["activity_id"]: r["event_time"] for r in csv.DictReader(fh)}
    with open(os.path.join(DS, "user_audit_log.csv"), encoding="utf-8") as fh:
        audits = {r["audit_id"]: r["event_time"] for r in csv.DictReader(fh)}
    with open(path, encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        rows = list(reader)
    if header != ["case_id", "deletion_status", "steps_json"]:
        errors.append(f"bad header {header}")
    ids = [r[0] for r in rows]

    def natural(c):
        prefix, _, num = c.rpartition("_")
        return (prefix, int(num)) if num.isdigit() else (c, 0)

    if ids != sorted(ids, key=natural):
        errors.append("rows not sorted by case_id")
    if set(ids) != set(reqs) or len(ids) != len(reqs):
        errors.append(f"row/case mismatch: {len(ids)} rows vs {len(reqs)} cases")
    for cid, status, sj in rows:
        try:
            steps = json.loads(sj)
        except ValueError:
            errors.append(f"{cid}: invalid JSON")
            continue
        if not isinstance(steps, list):
            errors.append(f"{cid}: steps_json is not an array")
            continue
        if status not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            errors.append(f"{cid}: bad status {status}")
        if status == "NOT_APPLICABLE" and steps:
            errors.append(f"{cid}: NOT_APPLICABLE must have []")
        if status == "INCOMPLETE" and not steps:
            errors.append(f"{cid}: INCOMPLETE with no steps")
        if status == "COMPLETE" and not steps:
            warnings.append(f"{cid}: COMPLETE with no evidence-backed check (no records found for the subject)")
        audit_at = reqs.get(cid, {}).get("audit_at", "")
        last_phase = -1
        for i, s in enumerate(steps, 1):
            if set(s) != FIELDS:
                errors.append(f"{cid}: step {i} fields {sorted(s)}")
                continue
            if s["step_no"] != i:
                errors.append(f"{cid}: step_no {s['step_no']} at position {i}")
            if ALLOWED.get(s["phase"], {}).get(s["operation"]) != s["state"]:
                errors.append(f"{cid}: illegal {s['phase']}/{s['operation']}/{s['state']}")
            rank = PHASE_RANK.get(s["phase"], 9)
            if rank < last_phase:
                errors.append(f"{cid}: phase order violated at step {i}")
            last_phase = rank
            ev = s["evidence_id"]
            if status == "COMPLETE" and s["phase"] != "VERIFICATION":
                errors.append(f"{cid}: COMPLETE case contains {s['phase']}")
            if status == "COMPLETE" and not ev:
                errors.append(f"{cid}: COMPLETE verification step {i} without evidence")
            if status == "INCOMPLETE" and s["phase"] == "FINDING" and not ev:
                errors.append(f"{cid}: finding {i} without evidence")
            if status == "INCOMPLETE" and s["phase"] != "FINDING" and ev:
                errors.append(f"{cid}: INCOMPLETE {s['phase']} step {i} must use empty evidence_id")
            if ev:
                when = files.get(ev) or acts.get(ev) or audits.get(ev)
                if when is None:
                    errors.append(f"{cid}: unknown evidence id {ev}")
                elif when > audit_at:
                    errors.append(f"{cid}: cites {ev} captured {when} after audit_at {audit_at}")
    print(f"{path}: {len(rows)} rows, {len(errors)} problems, {len(warnings)} warnings")
    for e in errors[:50]:
        print("  -", e)
    for w in warnings[:20]:
        print("  ~", w)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "output.csv")))
