#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bash "$ROOT/scripts/fetch-ios-dependencies.sh"
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
OUTPUT="${1:-$ROOT/dist/WeChatMods.dylib}"
mkdir -p "$(dirname "$OUTPUT")"

xcrun --sdk iphoneos clang \
  -fobjc-arc \
  -fmodules \
  -isysroot "$SDK" \
  -arch arm64 \
  -miphoneos-version-min=15.0 \
  -dynamiclib \
  "$ROOT/vendor/fishhook/fishhook.c" \
  "$ROOT/ios/WeChatMods/WMActivationPlanner.m" \
  "$ROOT/ios/WeChatMods/WMAntiRevokeModule.m" \
  "$ROOT/ios/WeChatMods/WMFeatureCollectionAdapter.m" \
  "$ROOT/ios/WeChatMods/WMFeatureStore.m" \
  "$ROOT/ios/WeChatMods/WMLiquidGlassStyle.m" \
  "$ROOT/ios/WeChatMods/WMLoginLayoutAdapter.m" \
  "$ROOT/ios/WeChatMods/WMModuleCatalog.m" \
  "$ROOT/ios/WeChatMods/WMModuleDescriptor.m" \
  "$ROOT/ios/WeChatMods/WMModuleRuntime.m" \
  "$ROOT/ios/WeChatMods/WMPluginNetworkFirewall.m" \
  "$ROOT/ios/WeChatMods/WMRuntimeHookFirewall.m" \
  "$ROOT/ios/WeChatMods/WMSafeModeController.m" \
  "$ROOT/ios/WeChatMods/WMSettingsEntry.m" \
  "$ROOT/ios/WeChatMods/WMSettingsViewController.m" \
  "$ROOT/ios/WeChatMods/WeChatModsBootstrap.m" \
  -framework Foundation \
  -framework UIKit \
  -framework WebKit \
  -install_name "@executable_path/Frameworks/WeChatMods.dylib" \
  -Wl,-dead_strip \
  -o "$OUTPUT"

codesign --force --sign - "$OUTPUT"
file "$OUTPUT"
codesign --display --verbose=2 "$OUTPUT"
PYTHONPATH="$ROOT/src" python3 -m wechat_ipa_audit.cli \
  write-loader-provenance \
  "$OUTPUT" \
  "$OUTPUT.provenance.json"
