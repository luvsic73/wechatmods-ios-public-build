import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AntiRevokeSourceTests(unittest.TestCase):
    def test_anti_revoke_is_present_but_default_disabled(self) -> None:
        modules = json.loads(
            (ROOT / "data" / "modules.json").read_text(encoding="utf-8")
        )["modules"]
        enabled = [module for module in modules if module["enabled"]]
        anti_revoke = next(
            module for module in modules if module["id"] == "anti-revoke"
        )

        self.assertEqual(enabled, [])
        self.assertFalse(anti_revoke["enabled"])
        self.assertEqual(
            anti_revoke["hooks"],
            ["CMessageMgr.onRevokeMsg:"],
        )

    def test_runtime_installs_only_the_guarded_message_hook(self) -> None:
        anti_revoke = (ROOT / "ios" / "WeChatMods" / "WMAntiRevokeModule.m").read_text(
            encoding="utf-8"
        )
        runtime = (ROOT / "ios" / "WeChatMods" / "WMModuleRuntime.m").read_text(
            encoding="utf-8"
        )
        bootstrap = (ROOT / "ios" / "WeChatMods" / "WeChatModsBootstrap.m").read_text(
            encoding="utf-8"
        )
        build_script = (ROOT / "scripts" / "build-loader.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('NSClassFromString(@"CMessageMgr")', anti_revoke)
        self.assertIn('NSSelectorFromString(@"onRevokeMsg:")', anti_revoke)
        self.assertIn("method_getNumberOfArguments", anti_revoke)
        self.assertIn("method_setImplementation", anti_revoke)
        self.assertNotIn("Login", anti_revoke)
        self.assertNotIn("Auth", anti_revoke)
        self.assertIn('isEqualToString:@"anti-revoke"', runtime)
        self.assertIn("WMActivationPlanner", bootstrap)
        self.assertIn("installModules:plan.enabledDescriptors", bootstrap)
        self.assertIn("WMAntiRevokeModule.m", build_script)
        self.assertIn("WMModuleRuntime.m", build_script)


if __name__ == "__main__":
    unittest.main()
