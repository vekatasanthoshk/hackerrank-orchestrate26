"""deletion_rules.csv -> finding / remediation / verification operations per resource.

Each rule's required_action maps to a treatment:

  DELETE     record must be gone          present  -> REPORT_REMAINING_RECORD / DELETE_RECORD
  REDACT     keep record, strip PII       exposed  -> REPORT_EXPOSED_PII / REDACT_RECORD
             (incl. ACCOUNT_TOMBSTONE: keep stable user_id, remove name/email/phone/hash)
  ANONYMIZE  keep record, unlink user     exposed  -> REPORT_EXPOSED_PII / ANONYMIZE_RECORD
  RETAIN     security audit / legal hold  must stay present -> VERIFY_RECORD_PRESENT
  RETAIN     BACKUP_ARCHIVE (restore access can be blocked)
             restore allowed -> REPORT_RESTORE_RISK / BLOCK_RESTORE
Data flows are recreation paths: enabled -> REPORT_ACTIVE_DATA_FLOW / DISABLE_DATA_FLOW.

Every relevant resource gets a verification step for its required final state,
including resources that were already compliant.
"""
import csv
import os

FIND = {
    "DELETE": ("REPORT_REMAINING_RECORD", "PRESENT"),
    "REDACT": ("REPORT_EXPOSED_PII", "PRESENT"),
    "ANONYMIZE": ("REPORT_EXPOSED_PII", "PRESENT"),
    "BLOCK": ("REPORT_RESTORE_RISK", "ACTIVE"),
    "DISABLE": ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
}
FIX = {
    "DELETE": ("DELETE_RECORD", "ABSENT"),
    "REDACT": ("REDACT_RECORD", "REDACTED"),
    "ANONYMIZE": ("ANONYMIZE_RECORD", "ANONYMIZED"),
    "BLOCK": ("BLOCK_RESTORE", "BLOCKED"),
    "DISABLE": ("DISABLE_DATA_FLOW", "DISABLED"),
}
VERIFY = {
    "DELETE": ("VERIFY_RECORD_ABSENT", "ABSENT"),
    "REDACT": ("VERIFY_RECORD_REDACTED", "REDACTED"),
    "ANONYMIZE": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    "RETAIN": ("VERIFY_RECORD_PRESENT", "PRESENT"),
    "BLOCK": ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
    "DISABLE": ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
}


def load_rules(dataset):
    with open(os.path.join(dataset, "deletion_rules.csv"), encoding="utf-8") as fh:
        return {r["data_category"]: r for r in csv.DictReader(fh)}


class Policy:
    def __init__(self, dataset):
        self.rules = load_rules(dataset)

    def treatment(self, category):
        if category == "DATA_FLOW":
            return "DISABLE"
        rule = self.rules.get(category)
        if not rule:
            return None
        action = rule["required_action"]
        if action == "RETAIN" and category == "BACKUP_ARCHIVE":
            return "BLOCK"
        return action

    def evaluate(self, rs):
        """Return (finding, remediation, verification) tuples (op, state) or None for one resource."""
        t = self.treatment(rs.category)
        if t is None:
            return None, None, None
        violation = False
        if t == "DELETE":
            violation = bool(rs.exists)
        elif t in ("REDACT", "ANONYMIZE"):
            violation = bool(rs.exists) and bool(rs.exposed)
            if not rs.exists:
                # the record is already gone entirely: verify its absence instead
                return None, None, VERIFY["DELETE"]
        elif t in ("BLOCK", "DISABLE"):
            violation = bool(rs.exists) and rs.active is True
        elif t == "RETAIN":
            if not rs.exists:
                return None, None, None  # nothing to verify as retained
            return None, None, VERIFY["RETAIN"]
        if violation:
            return FIND[t], FIX[t], VERIFY[t]
        return None, None, VERIFY[t]
