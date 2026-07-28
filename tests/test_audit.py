import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from wechat_ipa_audit.audit import audit_ipa


def make_ipa(path: Path, *, bundle_id: str = "com.example.fixture") -> None:
    info = {
        "CFBundleIdentifier": bundle_id,
        "CFBundleShortVersionString": "8.0.75",
        "CFBundleVersion": "1",
        "CFBundleExecutable": "Fixture",
        "CFBundleURLTypes": [
            {"CFBundleURLSchemes": ["fixture", "fixture-share"]}
        ],
        "NSCameraUsageDescription": "camera",
    }
    # Minimal arm64 Mach-O header, filetype MH_EXECUTE, zero load commands.
    macho = bytes.fromhex(
        "cffaedfe"  # MH_MAGIC_64 little endian
        "0c000001"  # CPU_TYPE_ARM64
        "00000000"  # subtype
        "02000000"  # MH_EXECUTE
        "00000000"  # ncmds
        "00000000"  # sizeofcmds
        "00000000"  # flags
        "00000000"  # reserved
    )
    profile = plistlib.dumps(
        {
            "Name": "Fixture Profile",
            "TeamIdentifier": ["TEAMFIXTURE"],
            "Entitlements": {
                "application-identifier": "TEAMFIXTURE.com.example.fixture",
                "com.apple.security.application-groups": ["group.fixture"],
                "keychain-access-groups": ["TEAMFIXTURE.*"],
                "get-task-allow": False,
            },
        }
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("Payload/Fixture.app/Info.plist", plistlib.dumps(info))
        archive.writestr("Payload/Fixture.app/Fixture", macho)
        archive.writestr(
            "Payload/Fixture.app/embedded.mobileprovision",
            b"CMS-PREFIX" + profile + b"CMS-SUFFIX",
        )
        archive.writestr("Payload/Fixture.app/_CodeSignature/CodeResources", b"plist")
        archive.writestr(
            "Payload/Fixture.app/Frameworks/Injected.framework/Injected",
            macho,
        )


class AuditIpaTests(unittest.TestCase):
    def test_reports_bundle_urls_permissions_and_macho_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ipa = Path(directory) / "fixture.ipa"
            make_ipa(ipa)

            report = audit_ipa(ipa)

        self.assertEqual(report["bundle"]["identifier"], "com.example.fixture")
        self.assertEqual(report["bundle"]["version"], "8.0.75")
        self.assertEqual(
            report["bundle"]["url_schemes"], ["fixture", "fixture-share"]
        )
        self.assertEqual(
            report["bundle"]["usage_descriptions"], ["NSCameraUsageDescription"]
        )
        self.assertEqual(
            [item["path"] for item in report["executables"]],
            [
                "Payload/Fixture.app/Fixture",
                "Payload/Fixture.app/Frameworks/Injected.framework/Injected",
            ],
        )
        self.assertEqual(report["executables"][0]["mach_o"]["architectures"], ["arm64"])
        self.assertEqual(report["signature"]["profile_name"], "Fixture Profile")
        self.assertEqual(report["signature"]["team_identifiers"], ["TEAMFIXTURE"])
        self.assertEqual(
            report["signature"]["entitlements"]["application-identifier"],
            "TEAMFIXTURE.com.example.fixture",
        )
        self.assertTrue(report["signature"]["code_resources_present"])

    def test_rejects_an_archive_without_an_app_info_plist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ipa = Path(directory) / "bad.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("not-an-app.txt", "fixture")

            with self.assertRaisesRegex(ValueError, "Info.plist"):
                audit_ipa(ipa)
