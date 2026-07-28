import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from wechat_ipa_audit.coexist import inspect_coexist, make_coexist_ipa


class CoexistPackagingTests(unittest.TestCase):
    def test_relocates_frameworks_needed_after_extensions_are_stripped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.ipa"
            output = root / "coexist.ipa"
            app = "Payload/WeChat.app/"
            old_rpath = (
                b"@executable_path/PlugIns/WeChatScreenCapture.appex"
            )
            new_rpath = b"@executable_path/Frameworks"
            main_info = {
                "CFBundleIdentifier": "com.tencent.xin",
                "CFBundleExecutable": "WeChat",
                "CFBundleName": "WeChat",
            }
            with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(
                    app + "Info.plist",
                    plistlib.dumps(main_info),
                )
                archive.writestr(app + "WeChat", b"main")
                archive.writestr(
                    app + "Frameworks/MMRouter.framework/MMRouter",
                    b"prefix"
                    b"@rpath/JavaScriptCore.framework/JavaScriptCore"
                    b"suffix",
                )
                archive.writestr(
                    app + "detector.bundle/JavaScriptCore.framework/Info.plist",
                    plistlib.dumps(
                        {
                            "CFBundleExecutable": "JavaScriptCore",
                            "CFBundleIdentifier": "fixture.JavaScriptCore",
                        }
                    ),
                )
                archive.writestr(
                    app
                    + "detector.bundle/JavaScriptCore.framework/JavaScriptCore",
                    b"before" + old_rpath + b"\0after",
                )
                archive.writestr(
                    app
                    + "PlugIns/WeChatScreenCapture.appex/"
                    + "MIRMetal.framework/Info.plist",
                    plistlib.dumps(
                        {
                            "CFBundleExecutable": "MIRMetal",
                            "CFBundleIdentifier": "fixture.MIRMetal",
                        }
                    ),
                )
                archive.writestr(
                    app
                    + "PlugIns/WeChatScreenCapture.appex/"
                    + "MIRMetal.framework/MIRMetal",
                    b"mir-metal",
                )

            make_coexist_ipa(
                source,
                output,
                bundle_id="com.luvsic73.wechatmods",
                display_name="WeChat Glass",
                scheme_prefix="wechatmods",
                strip_extensions=True,
            )

            with zipfile.ZipFile(output) as archive:
                names = set(archive.namelist())
                relocated_jsc = archive.read(
                    app
                    + "Frameworks/JavaScriptCore.framework/JavaScriptCore"
                )

        self.assertNotIn(
            app
            + "detector.bundle/JavaScriptCore.framework/JavaScriptCore",
            names,
        )
        self.assertIn(
            app + "Frameworks/JavaScriptCore.framework/Info.plist",
            names,
        )
        self.assertIn(
            app + "Frameworks/MIRMetal.framework/MIRMetal",
            names,
        )
        self.assertFalse(any("/PlugIns/" in name for name in names))
        self.assertEqual(len(relocated_jsc), len(b"before" + old_rpath + b"\0after"))
        self.assertIn(new_rpath + b"\0", relocated_jsc)
        self.assertNotIn(old_rpath, relocated_jsc)

    def test_rejects_a_missing_runtime_framework_before_packaging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.ipa"
            output = root / "coexist.ipa"
            app = "Payload/WeChat.app/"
            with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(
                    app + "Info.plist",
                    plistlib.dumps(
                        {
                            "CFBundleIdentifier": "com.tencent.xin",
                            "CFBundleExecutable": "WeChat",
                            "CFBundleName": "WeChat",
                        }
                    ),
                )
                archive.writestr(app + "WeChat", b"main")
                archive.writestr(
                    app + "Frameworks/MMRouter.framework/MMRouter",
                    b"@rpath/JavaScriptCore.framework/JavaScriptCore",
                )

            with self.assertRaisesRegex(
                ValueError,
                "JavaScriptCore runtime framework",
            ):
                make_coexist_ipa(
                    source,
                    output,
                    bundle_id="com.luvsic73.wechatmods",
                    display_name="WeChat Glass",
                    scheme_prefix="wechatmods",
                    strip_extensions=True,
                )

    def test_powershell_build_uses_encoding_independent_display_name(self) -> None:
        script = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "build-coexist.ps1"
        ).read_text(encoding="utf-8")

        self.assertIn("[char]0x5FAE", script)
        self.assertIn("[char]0x4FE1", script)

    def test_rewrites_identity_and_strips_extension_signing_surface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.ipa"
            output = root / "coexist.ipa"
            main_info = {
                "CFBundleIdentifier": "com.tencent.xin",
                "CFBundleExecutable": "WeChat",
                "CFBundleName": "微信",
                "CFBundleDisplayName": "微信",
                "UIDesignRequiresCompatibility": True,
                "CFBundleURLTypes": [
                    {"CFBundleURLSchemes": ["wechat", "weixin", "prefs"]}
                ],
            }
            extension_info = {
                "CFBundleIdentifier": "com.tencent.xin.sharetimeline",
                "CFBundleExecutable": "Share",
            }
            with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(
                    "Payload/WeChat.app/Info.plist",
                    plistlib.dumps(main_info),
                )
                archive.writestr("Payload/WeChat.app/WeChat", b"main")
                archive.writestr(
                    "Payload/WeChat.app/Frameworks/WeChatMods.dylib",
                    b"loader",
                )
                archive.writestr(
                    "Payload/WeChat.app/_CodeSignature/CodeResources",
                    b"stale",
                )
                archive.writestr(
                    "Payload/WeChat.app/embedded.mobileprovision",
                    b"stale-profile",
                )
                archive.writestr(
                    "Payload/WeChat.app/PlugIns/Share.appex/Info.plist",
                    plistlib.dumps(extension_info),
                )
                archive.writestr(
                    "Payload/WeChat.app/PlugIns/Share.appex/Share",
                    b"extension",
                )
                archive.writestr(
                    "Payload/WeChat.app/Watch/Watch.app/Watch",
                    b"watch",
                )

            make_coexist_ipa(
                source,
                output,
                bundle_id="com.luvsic73.wechatmods",
                bundle_name="WeChatGlass",
                display_name="微信 Glass",
                scheme_prefix="wechatmods",
                strip_extensions=True,
            )

            with zipfile.ZipFile(output) as archive:
                names = archive.namelist()
                rewritten = plistlib.loads(
                    archive.read("Payload/WeChat.app/Info.plist")
                )
            inspection = inspect_coexist(output)

        self.assertEqual(
            rewritten["CFBundleIdentifier"],
            "com.luvsic73.wechatmods",
        )
        self.assertEqual(rewritten["CFBundleName"], "WeChatGlass")
        self.assertEqual(rewritten["CFBundleDisplayName"], "微信 Glass")
        self.assertNotIn("UIDesignRequiresCompatibility", rewritten)
        self.assertEqual(
            rewritten["CFBundleURLTypes"][0]["CFBundleURLSchemes"],
            [
                "wechatmods-wechat",
                "wechatmods-weixin",
                "wechatmods-prefs",
            ],
        )
        self.assertIn("Payload/WeChat.app/WeChat", names)
        self.assertIn(
            "Payload/WeChat.app/Frameworks/WeChatMods.dylib",
            names,
        )
        self.assertFalse(any("/PlugIns/" in name for name in names))
        self.assertFalse(any("/Watch/" in name for name in names))
        self.assertFalse(any("/_CodeSignature/" in name for name in names))
        self.assertFalse(
            any(name.endswith("embedded.mobileprovision") for name in names)
        )
        self.assertTrue(inspection["coexist_ready"])
        self.assertTrue(inspection["native_liquid_glass_ready"])
        self.assertFalse(inspection["design_requires_compatibility"])
        self.assertTrue(inspection["developer_app_id_name_ready"])
        self.assertEqual(inspection["bundle_name"], "WeChatGlass")
        self.assertEqual(inspection["extensions"], [])
        self.assertEqual(inspection["signing_residue"], [])


if __name__ == "__main__":
    unittest.main()
