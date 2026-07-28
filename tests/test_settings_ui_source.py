import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SettingsUISourceTests(unittest.TestCase):
    def test_settings_entry_uses_wechat_native_settings_table(self) -> None:
        source = (
            ROOT / "ios" / "WeChatMods" / "WMSettingsEntry.m"
        ).read_text(encoding="utf-8")

        self.assertIn('NSClassFromString(@"NewSettingViewController")', source)
        self.assertIn('class_getInstanceVariable(settingsClass, "m_tableViewMgr")', source)
        self.assertIn('NSClassFromString(@"WCTableViewSectionManager")', source)
        self.assertIn('NSClassFromString(@"WCTableViewNormalCellManager")', source)
        self.assertIn('NSSelectorFromString(@"insertSection:At:")', source)
        self.assertIn(
            '@"normalCellForSel:target:title:accessoryType:"',
            source,
        )
        self.assertNotIn("floating", source.lower())

    def test_settings_entry_retries_and_hooks_both_lifecycle_seams(self) -> None:
        source = (
            ROOT / "ios" / "WeChatMods" / "WMSettingsEntry.m"
        ).read_text(encoding="utf-8")

        self.assertIn("UIApplicationDidFinishLaunchingNotification", source)
        self.assertIn("UIApplicationDidBecomeActiveNotification", source)
        self.assertIn('NSSelectorFromString(@"viewDidLoad")', source)
        self.assertIn('NSSelectorFromString(@"reloadTableData")', source)
        self.assertIn("WMSettingsEntryMarkerKey", source)
        self.assertIn("objc_setAssociatedObject", source)

    def test_settings_controller_exposes_real_feature_state(self) -> None:
        controller = (
            ROOT / "ios" / "WeChatMods" / "WMSettingsViewController.m"
        ).read_text(encoding="utf-8")
        store = (
            ROOT / "ios" / "WeChatMods" / "WMFeatureStore.m"
        ).read_text(encoding="utf-8")
        bootstrap = (
            ROOT / "ios" / "WeChatMods" / "WeChatModsBootstrap.m"
        ).read_text(encoding="utf-8")

        self.assertIn("UITableViewStyleInsetGrouped", controller)
        self.assertIn('@"防撤回"', controller)
        self.assertIn("UISwitch", controller)
        self.assertIn('@"更改后重启微信生效"', controller)
        self.assertIn('@"wechatmods.module-overrides"', store)
        self.assertIn("prepareForSchemaVersion", bootstrap)
        self.assertIn("WMFeatureStore.enabledModuleIDs", bootstrap)
        self.assertNotIn("defaultValue:descriptor.isEnabled", bootstrap)

    def test_glass_shell_covers_dynamic_navigation_and_control_bars(self) -> None:
        source = (
            ROOT / "ios" / "WeChatMods" / "WMLiquidGlassStyle.m"
        ).read_text(encoding="utf-8")

        self.assertIn("UIWindowDidBecomeVisibleNotification", source)
        self.assertIn('NSSelectorFromString(@"didMoveToWindow")', source)
        self.assertIn('NSSelectorFromString(@"layoutSubviews")', source)
        self.assertIn("WMRefreshVisibleLayouts", source)
        self.assertIn('NSClassFromString(@"MMUINavigationBar")', source)
        self.assertIn('NSClassFromString(@"MMTabBar")', source)
        self.assertIn("WMCustomNavigationHookInstalled", source)
        self.assertIn("WMInstallDynamicBarHooks();", source)
        self.assertNotIn("WMGlassifyWindows", source)
        self.assertNotIn("UINavigationBar.appearance", source)
        self.assertNotIn("WMInstallWindowGlassChrome", source)
        self.assertNotIn("WMInstallWindowEdgeGlass", source)

    def test_login_layout_adapter_is_ui_only_and_uses_ios_26_background_extension(
        self,
    ) -> None:
        source = (
            ROOT / "ios" / "WeChatMods" / "WMLoginLayoutAdapter.m"
        ).read_text(encoding="utf-8")
        build_script = (ROOT / "scripts" / "build-loader.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('@"WCAccountLoginByQRCodeViewController"', source)
        self.assertIn('NSClassFromString(@"UIBackgroundExtensionView")', source)
        self.assertIn("edgesForExtendedLayout = UIRectEdgeAll", source)
        self.assertIn("extendedLayoutIncludesOpaqueBars = YES", source)
        self.assertNotIn("ManualAuthAesReqData", source)
        self.assertNotIn("setBundleId:", source)
        simulator_script = (
            ROOT / "scripts" / "run-ios-simulator-ui-tests.sh"
        ).read_text(encoding="utf-8")
        bootstrap = (
            ROOT / "ios" / "WeChatMods" / "WeChatModsBootstrap.m"
        ).read_text(encoding="utf-8")
        self.assertIn("WMLoginLayoutAdapter.m", build_script)
        self.assertIn("WMLoginLayoutAdapter.m", simulator_script)
        self.assertIn("[WMLoginLayoutAdapter install]", bootstrap)

    def test_loader_build_includes_settings_sources(self) -> None:
        build_script = (ROOT / "scripts" / "build-loader.sh").read_text(
            encoding="utf-8"
        )

        for source in (
            "WMFeatureStore.m",
            "WMSettingsEntry.m",
            "WMSettingsViewController.m",
        ):
            self.assertIn(source, build_script)

    def test_ios_26_simulator_host_emits_runtime_diagnostics(self) -> None:
        host = (
            ROOT / "ios" / "SimulatorHost" / "SimulatorHost.m"
        ).read_text(encoding="utf-8")
        script = (
            ROOT / "scripts" / "run-ios-simulator-ui-tests.sh"
        ).read_text(encoding="utf-8")
        workflow = (
            ROOT / ".github" / "workflows" / "build-loader.yml"
        ).read_text(encoding="utf-8")

        for key in (
            "loader_constructor_ran",
            "settings_entry_count",
            "settings_controller_opened",
            "glass_effect_count",
            "glass_backdrop_count",
            "glass_effect_api_available",
            "glass_effect_default_initializer_available",
            "glass_effect_class_names",
            "window_matches_screen",
            "content_reaches_top_edge",
            "content_reaches_bottom_edge",
        ):
            self.assertIn(key, host)
        self.assertIn("@interface MMUINavigationBar : UIView", host)
        self.assertIn("@interface MMTabBar : UIView", host)
        self.assertLess(
            host.index("tabs.selectedIndex = 1;"),
            host.index("WMCountGlassEffects(window)"),
        )
        self.assertIn("iPhone 17 Pro Max", script)
        self.assertIn("TARGET_RUNTIME_VERSION", script)
        self.assertIn("module-manifest.json", script)
        self.assertIn("data/modules.json", script)
        self.assertIn("simctl", script)
        self.assertIn("SimulatorHostDiagnostics.json", script)
        self.assertIn('data.get("glass_effect_count", 0) < 2', script)
        self.assertIn('data.get("glass_backdrop_count", 0) < 2', script)
        self.assertIn("simulator-ui", workflow)


if __name__ == "__main__":
    unittest.main()
