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
        """Return (finding, remediation, verification, proven) for one resource.

        finding / remediation / verification are (operation, state) tuples or None.
        ``proven`` says whether the cited evidence actually establishes the compliant
        state; an unproven check is still part of a remediation plan but can never be
        cited as proof in a COMPLETE case (unknown restore status, unknown exposure,
        or a retained record that is missing).
        """
        t = self.treatment(rs.category)
        if t is None:
            return None, None, None, False
        if t == "DELETE":
            if rs.exists:
                return FIND[t], FIX[t], VERIFY[t], True
            return None, None, VERIFY[t], True
        if t in ("REDACT", "ANONYMIZE"):
            if not rs.exists:
                return None, None, VERIFY["DELETE"], True  # gone entirely: verify absence
            if rs.exposed:
                return FIND[t], FIX[t], VERIFY[t], True
            return None, None, VERIFY[t], rs.exposed is False
        if t in ("BLOCK", "DISABLE"):
            if rs.exists and rs.active is True:
                return FIND[t], FIX[t], VERIFY[t], True
            # gone, or explicitly disabled / blocked; unknown flags are not proof
            return None, None, VERIFY[t], (not rs.exists) or rs.active is False
        if t == "RETAIN":
            # required final state is "present"; a missing retained record cannot be proven
            return None, None, VERIFY["RETAIN"], bool(rs.exists)
        return None, None, None, False
