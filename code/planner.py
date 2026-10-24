"""Step ordering, numbering and deterministic JSON serialisation.

Order (problem_statement.md, confirmed by sample case_11):
  phase:        FINDING -> REMEDIATION -> VERIFICATION
  within phase: operation order of the allowed-operations table,
                then system_id, then resource_id (ascending).
Remediation therefore disables flows and blocks restores before touching records.
"""
import json

OP_ORDER = [
    "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
    "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD",
    "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
]
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
RANK = {op: i for i, op in enumerate(OP_ORDER)}


def order_steps(steps):
    steps = sorted(steps, key=lambda s: (PHASE_ORDER[s["phase"]], RANK[s["operation"]],
                                         s["system_id"], s["resource_id"]))
    out = []
    for i, s in enumerate(steps, 1):
        out.append({"step_no": i, "phase": s["phase"], "system_id": s["system_id"],
                    "resource_id": s["resource_id"], "operation": s["operation"],
                    "state": s["state"], "evidence_id": s["evidence_id"]})
    return out


def serialize(steps):
    return json.dumps(steps, ensure_ascii=False, separators=(",", ":"))
