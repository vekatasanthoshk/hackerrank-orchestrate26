"""Automated tests (standard library only).

    python3 -m unittest discover -s code/tests -v        # from the repository root

Unit tests pin down the parsing / identity / policy / ordering rules documented in
docs/DATA_NOTES.md; the end-to-end tests run the real dataset and assert the
submission contract and the sample-score floor so regressions are caught.
"""
import csv
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

CODE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(CODE)
sys.path.insert(0, CODE)

from identity import Identities, norm  # noqa: E402
from ingest.common import interpret, text_identifiers  # noqa: E402
from ingest.logs import parse_line  # noqa: E402
from intent import rule_intent  # noqa: E402
from planner import order_steps  # noqa: E402
from policy import Policy  # noqa: E402

DATASET = os.path.join(ROOT, "dataset")


class LogParsing(unittest.TestCase):
    def test_all_dialects(self):
        cases = {
            'logfmt': '2026-09-26T07:49:50Z level=INFO service=account_service trace_id=rb-1 '
                      'event=profile_lookup_completed resource_id=account_2064 rows=0 http_status=404',
            'bracketed': '2026-07-28T05:51:21Z [INFO] [account_service] [tr-6074163] profile_lookup_completed: '
                         'instance="account-5" resource_id="account_7947" rows="0" http_status="404"',
            'pipe': '2026-07-03T07:51:32Z | DEBUG | security_service | tr-5156005 | audit_record_read_completed | '
                    'resource_id="audit_record_4413" rows="1" correlation_key="user_211"',
            'json': '2026-04-19T06:51:13Z {"severity":"DEBUG","service":"search_service","trace_id":"tr-77",'
                    '"event":"index_query_started","match_key":"dubois.ines94@icloud.com"}',
            'syslog': '2026-03-25T08:51:23Z <12>1 node-1 support_platform tr-7458912 - - level=WARN '
                      'resource_id="support_9464" event="message_pii_scan" matched_value="silva.mariana@icloud.com"',
            'cloud': '2026-09-30T11:51:03Z requestId=tr-2263120 level=DEBUG function=profile_service '
                     'message="resource_id=\\"account_66777\\" event=\\"profile_lookup_completed\\" rows=\\"1\\""',
        }
        for name, line in cases.items():
            rec = parse_line(line)
            self.assertIsNotNone(rec, name)
            self.assertTrue(rec.get("service"), name)
            self.assertTrue(rec.get("event") or rec.get("resource_id"), name)
        self.assertEqual(parse_line(cases["cloud"])["resource_id"], "account_66777")
        self.assertEqual(parse_line(cases["pipe"])["correlation_key"], "user_211")


class Identity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ids = Identities(DATASET)

    def test_hash_rule_holds_for_every_user(self):
        for u in self.ids.users.values():
            for e in u["emails"]:
                self.assertIn(hashlib.sha256(e.encode()).hexdigest(), u["hashes"])

    def test_normalisation(self):
        self.assertEqual(norm("CHOI.JIHOON94@GMAIL.COM"), "choi.jihoon94@gmail.com")
        self.assertEqual(norm("+55 41 90257-9346"), norm("+55 (41) 902579346"))
        self.assertEqual(norm("USER_12"), "user_12")
        self.assertIsNone(norm("Gabriel Silva"))  # names never link records

    def test_historical_email_resolves(self):
        self.assertEqual(self.ids.users_for_email("minjun.kim90@gmail.com"), ["user_12"])
        self.assertEqual(self.ids.users_for_email("BCARVALHO6517@GMAIL.COM"), ["user_52"])

    def test_decoy_email_does_not_resolve(self):
        self.assertEqual(self.ids.users_for_email("g.silva76.jr@gmail.com"), [])


class Interpretation(unittest.TestCase):
    def test_states(self):
        self.assertFalse(interpret("account_service", {"rows": "0", "http_status": "404"})[0])
        self.assertTrue(interpret("search_service", {"result": "hit"})[0])
        self.assertTrue(interpret("analytics_platform", {"email": "a@b.co"})[1])
        self.assertFalse(interpret("analytics_platform", {"email": None, "user_id": None})[1])
        self.assertTrue(interpret("integration_service", {"enabled": "true"})[2])
        self.assertFalse(interpret("backup_service", {"decision": "deny"})[2])
        self.assertTrue(interpret("backup_service", {"eligible": "true", "deletion_block": "false"})[2])

    def test_support_free_text_and_redaction(self):
        exposed = interpret("support_platform", {"message_text": "Send it to noah.f438085@outlook.com."})[1]
        self.assertTrue(exposed)
        self.assertFalse(interpret("support_platform", {"message_text": "[REDACTED]"})[1])
        self.assertEqual(text_identifiers({"message_text": "call +81 90 6156 0005"}), {"+81 90 6156 0005"})

    def test_categories(self):
        self.assertEqual(interpret("support_platform", {"events": ["attachment_pii_scan"]})[3], "SUPPORT_ATTACHMENT")
        self.assertEqual(interpret("analytics_platform", {"events": ["contact_lookup_completed"]})[3],
                         "SECONDARY_IDENTIFIER")


class Intent(unittest.TestCase):
    def test_deletion_in_many_languages(self):
        for t in ["Please erase the account linked to this email address.",
                  "Solicito a exclusão permanente da conta associada a este e-mail.",
                  "Je demande la suppression définitive du compte.",
                  "このメールアドレスに関連するアカウントの完全な削除を依頼します。",
                  "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다.",
                  "My account page is gone, but my old profile still appears. Can you remove that search result too?"]:
            self.assertEqual(rule_intent(t)[0], "DELETION", t)

    def test_non_deletion(self):
        for t in ["Please remove me from marketing lists only. I still want receipts.",
                  "I'd like to download my account information in a portable format.",
                  "Could you send me a copy of the information held on my account?",
                  "Quisiera descargar una copia de mis datos. Por favor, no cierren mi cuenta.",
                  "Merci de me retirer uniquement des listes marketing. Je souhaite conserver mon compte."]:
            self.assertEqual(rule_intent(t)[0], "NOT_DELETION", t)


class PolicyAndPlanner(unittest.TestCase):
    def test_policy(self):
        p = Policy(DATASET)
        self.assertEqual(p.treatment("ACCOUNT_TOMBSTONE"), "REDACT")
        self.assertEqual(p.treatment("BACKUP_ARCHIVE"), "BLOCK")
        self.assertEqual(p.treatment("SECURITY_AUDIT_LOG"), "RETAIN")
        self.assertEqual(p.treatment("DATA_FLOW"), "DISABLE")

    def test_case_11_order(self):
        def s(phase, sys_, rid, op, st):
            return {"phase": phase, "system_id": sys_, "resource_id": rid, "operation": op, "state": st,
                    "evidence_id": ""}
        steps = [s("VERIFICATION", "integration_service", "data_flow_9522", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
                 s("REMEDIATION", "analytics_platform", "analytics_2034", "ANONYMIZE_RECORD", "ANONYMIZED"),
                 s("FINDING", "support_platform", "support_864", "REPORT_EXPOSED_PII", "PRESENT"),
                 s("REMEDIATION", "integration_service", "data_flow_9522", "DISABLE_DATA_FLOW", "DISABLED"),
                 s("FINDING", "search_service", "search_052", "REPORT_REMAINING_RECORD", "PRESENT"),
                 s("FINDING", "analytics_platform", "analytics_2034", "REPORT_EXPOSED_PII", "PRESENT"),
                 s("VERIFICATION", "account_service", "account_4248", "VERIFY_RECORD_ABSENT", "ABSENT")]
        got = [(x["step_no"], x["resource_id"], x["operation"]) for x in order_steps(steps)]
        self.assertEqual([g[1] for g in got], ["search_052", "analytics_2034", "support_864", "data_flow_9522",
                                               "analytics_2034", "account_4248", "data_flow_9522"])
        self.assertEqual([g[0] for g in got], list(range(1, 8)))


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from main import Auditor

        cls.auditor = Auditor(use_llm=False)
        cls.auditor.prepare()

    def test_samples_score(self):
        gold, reqs = {}, []
        with open(os.path.join(DATASET, "sample_output.csv"), encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                gold[r["case_id"]] = (r["deletion_status"], json.loads(r["steps_json"]))
        with open(os.path.join(DATASET, "sample_deletion_requests.csv"), encoding="utf-8") as fh:
            reqs = list(csv.DictReader(fh))
        status_ok, tp, pred_n, gold_n = 0, 0, 0, 0
        key = lambda s: (s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"])  # noqa: E731
        for r in reqs:
            st, steps, _ = self.auditor.audit(r)
            gst, gsteps = gold[r["case_id"]]
            status_ok += st == gst
            tp += len(set(map(key, steps)) & set(map(key, gsteps)))
            pred_n += len(steps)
            gold_n += len(gsteps)
        self.assertEqual(status_ok, len(reqs))       # status accuracy 1.000
        self.assertEqual(tp, pred_n)                  # precision 1.000: never an unsupported step
        self.assertGreaterEqual(tp / gold_n, 0.86)    # recall floor

    def test_custom_cases(self):
        folder = os.path.join(CODE, "evaluation", "custom_cases")
        for name in sorted(os.listdir(folder)):
            case = json.load(open(os.path.join(folder, name), encoding="utf-8"))
            st, steps, _ = self.auditor.audit(case["request"])
            self.assertEqual(st, case["expected"]["deletion_status"], name)
            self.assertEqual(steps, case["expected"]["steps"], name)

    def test_full_run_contract_and_determinism(self):
        with tempfile.TemporaryDirectory() as tmp:
            outs = []
            for i in range(2):
                out = os.path.join(tmp, f"out{i}.csv")
                subprocess.run([sys.executable, os.path.join(CODE, "main.py"), "--no-llm", "--out", out],
                               check=True, capture_output=True)
                with open(out, "rb") as fh:
                    outs.append(fh.read())
            self.assertEqual(outs[0], outs[1])
            res = subprocess.run([sys.executable, os.path.join(CODE, "evaluation", "validate_output.py"),
                                  os.path.join(tmp, "out0.csv")], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stdout)
            self.assertIn("518 rows, 0 problems", res.stdout)


if __name__ == "__main__":
    unittest.main()
