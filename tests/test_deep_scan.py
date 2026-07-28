from __future__ import annotations

import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from wechat_ipa_audit.deep_scan import scan_binary, scan_ipa_members


class DeepScanTests(unittest.TestCase):
    def test_extracts_domains_and_risk_markers_without_echoing_tokens(self) -> None:
        report = scan_binary(
            b"\0".join(
                [
                    b"https://config.example.test/v1",
                    b"SecItemCopyMatching",
                    b"UIPasteboard",
                    b"ptrace",
                    b"Bearer abcdefghijklmnopqrstuvwxyz",
                ]
            )
        )

        self.assertEqual(report["domains"], ["config.example.test"])
        self.assertEqual(
            report["risk_markers"],
            ["anti_debug", "clipboard", "credential_store", "hardcoded_secret"],
        )
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", str(report))

    def test_ignores_a_malformed_url_string(self) -> None:
        report = scan_binary(
            b"http://[ malformed http://%s http://aweme "
            b"https://valid.example.test/path"
        )

        self.assertEqual(report["domains"], ["valid.example.test"])

    def test_scans_and_extracts_only_named_archive_members(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            ipa = root / "sample.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/App.app/Frameworks/test.dylib", b"dlopen")
                archive.writestr("Payload/App.app/secret.txt", b"not selected")

            report = scan_ipa_members(
                ipa,
                ["Payload/App.app/Frameworks/test.dylib"],
                extract_directory=root / "components",
            )

            self.assertEqual(len(report), 1)
            self.assertEqual(report[0]["risk_markers"], ["dynamic_loading"])
            self.assertTrue(Path(report[0]["extracted_to"]).is_file())
            self.assertFalse((root / "components" / "secret.txt").exists())


if __name__ == "__main__":
    unittest.main()
