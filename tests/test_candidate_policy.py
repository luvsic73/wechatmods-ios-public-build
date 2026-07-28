import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from wechat_ipa_audit.candidate_policy import inspect_candidate_policy


def _write_ipa(
    path: Path,
    *,
    components: dict[str, bytes] | None = None,
    resources: dict[str, bytes] | None = None,
) -> None:
    app = "Payload/WeChat.app/"
    info = {
        "CFBundleIdentifier": "com.tencent.qy.xin",
        "CFBundleExecutable": "WeChat",
        "CFBundleName": "WeChatGlass",
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(app + "Info.plist", plistlib.dumps(info))
        archive.writestr(app + "WeChat", b"official-main")
        archive.writestr(
            app + "Frameworks/App.framework/App",
            b"official-framework",
        )
        for name, payload in (components or {}).items():
            archive.writestr(app + name, payload)
        for name, payload in (resources or {}).items():
            archive.writestr(app + name, payload)


class CandidatePolicyTests(unittest.TestCase):
    def test_allows_only_the_single_expected_loader_delta(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.ipa"
            candidate = root / "candidate.ipa"
            _write_ipa(baseline)
            _write_ipa(
                candidate,
                components={
                    "Frameworks/WeChatMods.dylib":
                        b"WMLiquidGlassStyle WMSettingsEntry",
                },
            )

            report = inspect_candidate_policy(baseline, candidate)

        self.assertTrue(report["valid"])
        self.assertEqual(
            report["added_executable_components"],
            ["Frameworks/WeChatMods.dylib"],
        )
        self.assertEqual(report["unexpected_executable_components"], [])
        self.assertEqual(report["forbidden_marker_hits"], [])

    def test_blocks_known_unrelated_plugin_binaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.ipa"
            candidate = root / "candidate.ipa"
            _write_ipa(baseline)
            _write_ipa(
                candidate,
                components={
                    "Frameworks/WeChatMods.dylib": b"loader",
                    "Frameworks/wechatku.dylib": b"plugin",
                    "Frameworks/HBWechatHelper.dylib": b"plugin",
                },
            )

            report = inspect_candidate_policy(baseline, candidate)

        self.assertFalse(report["valid"])
        self.assertEqual(
            report["blocked_component_names"],
            ["HBWechatHelper.dylib", "wechatku.dylib"],
        )

    def test_blocks_expiry_and_redirect_markers_in_the_loader(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.ipa"
            candidate = root / "candidate.ipa"
            _write_ipa(baseline)
            _write_ipa(
                candidate,
                components={
                    "Frameworks/WeChatMods.dylib":
                        "证书即将到期 https://wx.plus".encode("utf-8"),
                },
            )

            report = inspect_candidate_policy(baseline, candidate)

        self.assertFalse(report["valid"])
        self.assertEqual(
            {hit["marker"] for hit in report["forbidden_marker_hits"]},
            {"https://wx.plus", "证书即将到期"},
        )

    def test_blocks_unrelated_plugin_scripts_and_ignores_stripped_extensions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.ipa"
            candidate = root / "candidate.ipa"
            _write_ipa(
                baseline,
                components={
                    "PlugIns/Share.appex/Frameworks/"
                    "ExtensionKit.framework/ExtensionKit": b"extension",
                },
            )
            _write_ipa(
                candidate,
                components={
                    "Frameworks/WeChatMods.dylib": b"loader",
                },
                resources={
                    "wechatku.bundle/redirect.js": b"location.href='plugin'",
                },
            )

            report = inspect_candidate_policy(baseline, candidate)

        self.assertFalse(report["valid"])
        self.assertEqual(
            report["blocked_archive_members"],
            ["wechatku.bundle/redirect.js"],
        )
        self.assertEqual(report["removed_executable_components"], [])


if __name__ == "__main__":
    unittest.main()
