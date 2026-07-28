import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IOS = ROOT / "ios" / "WeChatMods"


class IOSModuleBackendSourceTests(unittest.TestCase):
    def test_descriptor_exposes_catalog_runtime_and_conflict_fields(self) -> None:
        header = (IOS / "WMModuleDescriptor.h").read_text(encoding="utf-8")
        implementation = (IOS / "WMModuleDescriptor.m").read_text(encoding="utf-8")

        for field in (
            "title",
            "group",
            "runtime",
            "conflicts",
            "hookOwner",
            "riskReasons",
            "configClassName",
            "sharedSelectorName",
            "setterName",
            "activationGate",
        ):
            self.assertIn(field, header)
        self.assertIn("WMAllowedHooksByOwner", implementation)
        self.assertIn("fixture-validation-required", implementation)

    def test_feature_store_uses_explicit_overrides_and_never_manifest_defaults(
        self,
    ) -> None:
        header = (IOS / "WMFeatureStore.h").read_text(encoding="utf-8")
        implementation = (IOS / "WMFeatureStore.m").read_text(encoding="utf-8")

        self.assertIn("prepareForSchemaVersion", header)
        self.assertIn("enabledModuleIDs", header)
        self.assertIn("return value != nil && value.boolValue", implementation)
        self.assertNotIn("value == nil ? defaultValue", implementation)

    def test_activation_planner_blocks_dependencies_conflicts_and_hook_owners(
        self,
    ) -> None:
        source = (IOS / "WMActivationPlanner.m").read_text(encoding="utf-8")

        for token in (
            "dependency_disabled:",
            "explicit_conflict:",
            "hook_collision:",
            "activation_gate:",
            "riskFlags",
        ):
            self.assertIn(token, source)

    def test_single_feature_collection_adapter_is_hash_pinned_and_local(self) -> None:
        source = (IOS / "WMFeatureCollectionAdapter.m").read_text(encoding="utf-8")

        self.assertIn(
            "846829A8351934AA805F4A77BE59E11DB6424FED53AD151758C8B4EFB480835F",
            source,
        )
        self.assertIn("RTLD_NOW | RTLD_LOCAL", source)
        self.assertIn("methodSignatureForSelector", source)
        self.assertIn("numberOfArguments != 3", source)
        self.assertIn("WeChatMods/FeatureCollection/MiYou.dylib", source)
        self.assertNotIn("PKCWeChatTools", source)
        self.assertNotIn("HBB9", source)

    def test_runtime_hook_firewall_is_plugin_scoped_and_covers_dynamic_hooks(
        self,
    ) -> None:
        header = (IOS / "WMRuntimeHookFirewall.h").read_text(encoding="utf-8")
        source = (IOS / "WMRuntimeHookFirewall.m").read_text(encoding="utf-8")

        self.assertIn("WMIsAddressFromRegisteredPlugin", header)
        self.assertIn("dladdr", source)
        self.assertIn("rebind_symbols", source)
        self.assertIn("__builtin_return_address(0)", source)
        for symbol in (
            "method_setImplementation",
            "method_exchangeImplementations",
            "class_addMethod",
            "class_replaceMethod",
            "dlsym",
            "MSHookMessageEx",
        ):
            self.assertIn(symbol, source)
        for selector in (
            "setBundleId:",
            "setClientSeqId:",
            "setDeviceName:",
            "addLogInfo:withMessage:",
            "HasInstallJailbreakPlugin:",
            "IsJailBreak",
            "sendLoginConfirmRequest",
        ):
            self.assertIn(selector, source)

    def test_plugin_network_firewall_blocks_external_network_and_browser_paths(
        self,
    ) -> None:
        source = (IOS / "WMPluginNetworkFirewall.m").read_text(encoding="utf-8")

        self.assertIn("WMIsAddressFromRegisteredPlugin", source)
        self.assertIn("wm_dataTaskWithRequest:completionHandler:", source)
        self.assertIn("wm_openURL:options:completionHandler:", source)
        self.assertIn("wm_loadRequest:", source)
        self.assertIn("wechatmods.plugin-network-events", source)
        self.assertIn("wechatmods.plugin-network-allowlist", source)
        self.assertIn("plugin_network_blocked", source)
        self.assertNotIn('@"weixin.qq.com"', source)
        self.assertIn("NSURLErrorUnsupportedURL", source)

    def test_runtime_installs_native_and_collection_modules_through_one_plan(
        self,
    ) -> None:
        source = (IOS / "WeChatModsBootstrap.m").read_text(encoding="utf-8")
        runtime = (IOS / "WMModuleRuntime.m").read_text(encoding="utf-8")

        self.assertIn("WMActivationPlanner", source)
        self.assertIn("installModules:plan.enabledDescriptors", source)
        self.assertIn("WMFeatureCollectionAdapter", runtime)
        self.assertIn('isEqualToString:@"feature-collection"', runtime)
        self.assertIn('isEqualToString:@"native-account"', runtime)
        self.assertIn("fixture-validation-required", runtime)
        self.assertIn("WMRuntimeHookFirewall", source)
        self.assertIn("WMPluginNetworkFirewall", source)
        self.assertIn("risk_control_unavailable", source)
        self.assertIn("wechatmods.hook-firewall-installed", source)
        self.assertIn("wechatmods.network-firewall-installed", source)
        self.assertLess(
            source.index("[WMRuntimeHookFirewall install]"),
            source.index("[WMModuleRuntime installModules:"),
        )

    def test_bootstrap_and_settings_share_one_runtime_catalog(self) -> None:
        header = (IOS / "WMModuleCatalog.h").read_text(encoding="utf-8")
        implementation = (IOS / "WMModuleCatalog.m").read_text(encoding="utf-8")
        bootstrap = (IOS / "WeChatModsBootstrap.m").read_text(encoding="utf-8")
        settings = (IOS / "WMSettingsViewController.m").read_text(encoding="utf-8")

        self.assertIn("sharedCatalog", header)
        self.assertIn("module-manifest.json", implementation)
        self.assertIn("duplicate_module_id:", implementation)
        self.assertIn("WMModuleCatalog.sharedCatalog", bootstrap)
        self.assertIn("WMModuleCatalog.sharedCatalog", settings)
        self.assertIn("catalog.loadErrors.count == 0", bootstrap)

    def test_bootstrap_marks_late_loaded_active_launches_stable(self) -> None:
        source = (IOS / "WeChatModsBootstrap.m").read_text(encoding="utf-8")

        self.assertIn("WMArmStableLaunchTimer", source)
        self.assertIn("UIApplicationDidFinishLaunchingNotification", source)
        self.assertIn("UIApplicationDidBecomeActiveNotification", source)
        self.assertIn("UIApplication.sharedApplication.applicationState", source)
        self.assertIn("UIApplicationStateBackground", source)

    def test_settings_are_catalog_driven_with_one_switch_and_risk_state(self) -> None:
        source = (IOS / "WMSettingsViewController.m").read_text(encoding="utf-8")

        self.assertIn("descriptorForIndexPath", source)
        self.assertIn("descriptor.moduleID", source)
        self.assertIn("descriptor.riskLevel", source)
        self.assertIn("descriptor.activationGate", source)
        self.assertIn("toggle.accessibilityIdentifier", source)
        self.assertIn("[WMFeatureStore isModuleEnabled:descriptor.moduleID]", source)
        self.assertNotIn("defaultValue:YES", source)

    def test_builds_include_new_backend_sources(self) -> None:
        for script_name in (
            "build-loader.sh",
            "run-ios-simulator-ui-tests.sh",
        ):
            source = (ROOT / "scripts" / script_name).read_text(encoding="utf-8")
            self.assertIn("WMActivationPlanner.m", source)
            self.assertIn("WMFeatureCollectionAdapter.m", source)
            self.assertIn("WMModuleCatalog.m", source)
            self.assertIn("WMRuntimeHookFirewall.m", source)
            self.assertIn("WMPluginNetworkFirewall.m", source)
            self.assertIn("vendor/fishhook/fishhook.c", source)


if __name__ == "__main__":
    unittest.main()
