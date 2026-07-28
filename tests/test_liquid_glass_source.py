import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class LiquidGlassSourceTests(unittest.TestCase):
    def test_liquid_glass_is_a_fixed_shell_not_a_module(self) -> None:
        modules = json.loads(
            (ROOT / "data" / "modules.json").read_text(encoding="utf-8")
        )["modules"]
        module_ids = {module["id"] for module in modules}
        bootstrap = (
            ROOT / "ios" / "WeChatMods" / "WeChatModsBootstrap.m"
        ).read_text(encoding="utf-8")

        self.assertNotIn("theme", module_ids)
        self.assertIn("[WMLiquidGlassStyle install]", bootstrap)

    def test_build_includes_runtime_native_glass_implementation(self) -> None:
        source = (
            ROOT / "ios" / "WeChatMods" / "WMLiquidGlassStyle.m"
        ).read_text(encoding="utf-8")
        build_script = (ROOT / "scripts" / "build-loader.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('NSClassFromString(@"UIGlassEffect")', source)
        self.assertIn("[effectClass new]", source)
        self.assertIn('NSSelectorFromString(@"setInteractive:")', source)
        self.assertNotIn('NSSelectorFromString(@"initWithStyle:")', source)
        self.assertIn("UIBlurEffectStyleSystemMaterial", source)
        self.assertIn("UIVisualEffectView", source)
        self.assertNotIn("UINavigationBarAppearance", source)
        self.assertNotIn("UITabBarAppearance", source)
        self.assertNotIn("UIToolbarAppearance", source)
        self.assertNotIn("UINavigationBar.appearance", source)
        self.assertNotIn("WMGlassifyViewTree", source)
        self.assertIn("WMLiquidGlassStyle.m", build_script)


if __name__ == "__main__":
    unittest.main()
