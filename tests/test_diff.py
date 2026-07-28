import unittest

from wechat_ipa_audit.diffing import diff_reports


class DiffReportTests(unittest.TestCase):
    def test_accounts_for_added_removed_and_modified_executables(self) -> None:
        baseline = {
            "executables": [
                {"path": "Payload/App.app/App", "sha256": "aaa"},
                {"path": "Payload/App.app/Frameworks/Old", "sha256": "old"},
            ]
        }
        candidate = {
            "executables": [
                {"path": "Payload/App.app/App", "sha256": "bbb"},
                {"path": "Payload/App.app/Frameworks/New", "sha256": "new"},
            ]
        }

        result = diff_reports(baseline, candidate)

        self.assertEqual(result["added"], ["Payload/App.app/Frameworks/New"])
        self.assertEqual(result["removed"], ["Payload/App.app/Frameworks/Old"])
        self.assertEqual(result["modified"], ["Payload/App.app/App"])

