#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bash "$ROOT/scripts/fetch-ios-dependencies.sh"
SDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"
ARCH="$(uname -m)"
TARGET_DEVICE_NAME="${TARGET_DEVICE_NAME:-iPhone 17 Pro Max}"
TARGET_RUNTIME_VERSION="${TARGET_RUNTIME_VERSION:-26.2}"
BUNDLE_ID="com.example.wechatmods.simulatorhost"
DIST="$ROOT/dist/simulator-ui"
APP="$DIST/SimulatorHost.app"
ARTIFACTS="$ROOT/reports/simulator-ui"

rm -rf "$APP" "$ARTIFACTS"
mkdir -p "$APP" "$ARTIFACTS"

SOURCES=(
  "$ROOT/ios/SimulatorHost/SimulatorHost.m"
  "$ROOT/vendor/fishhook/fishhook.c"
  "$ROOT/ios/WeChatMods/WMActivationPlanner.m"
  "$ROOT/ios/WeChatMods/WMAntiRevokeModule.m"
  "$ROOT/ios/WeChatMods/WMFeatureCollectionAdapter.m"
  "$ROOT/ios/WeChatMods/WMFeatureStore.m"
  "$ROOT/ios/WeChatMods/WMLiquidGlassStyle.m"
  "$ROOT/ios/WeChatMods/WMLoginLayoutAdapter.m"
  "$ROOT/ios/WeChatMods/WMModuleCatalog.m"
  "$ROOT/ios/WeChatMods/WMModuleDescriptor.m"
  "$ROOT/ios/WeChatMods/WMModuleRuntime.m"
  "$ROOT/ios/WeChatMods/WMPluginNetworkFirewall.m"
  "$ROOT/ios/WeChatMods/WMRuntimeHookFirewall.m"
  "$ROOT/ios/WeChatMods/WMSafeModeController.m"
  "$ROOT/ios/WeChatMods/WMSettingsEntry.m"
  "$ROOT/ios/WeChatMods/WMSettingsViewController.m"
  "$ROOT/ios/WeChatMods/WeChatModsBootstrap.m"
)

xcrun --sdk iphonesimulator clang \
  -fobjc-arc \
  -fmodules \
  -isysroot "$SDK" \
  -arch "$ARCH" \
  -mios-simulator-version-min=15.0 \
  "${SOURCES[@]}" \
  -framework Foundation \
  -framework UIKit \
  -framework WebKit \
  -Wl,-dead_strip \
  -o "$APP/SimulatorHost"

cat > "$APP/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>zh_CN</string>
  <key>CFBundleDisplayName</key>
  <string>WeChatMods UI Fixture</string>
  <key>CFBundleExecutable</key>
  <string>SimulatorHost</string>
  <key>CFBundleIdentifier</key>
  <string>com.example.wechatmods.simulatorhost</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>SimulatorHost</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>8.0.75</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSRequiresIPhoneOS</key>
  <true/>
  <key>MinimumOSVersion</key>
  <string>15.0</string>
  <key>UIDeviceFamily</key>
  <array><integer>1</integer></array>
  <key>UILaunchScreen</key>
  <dict/>
  <key>UIRequiresFullScreen</key>
  <true/>
  <key>UISupportedInterfaceOrientations</key>
  <array><string>UIInterfaceOrientationPortrait</string></array>
</dict>
</plist>
PLIST

mkdir -p "$APP/WeChatMods"
cp "$ROOT/data/modules.json" \
  "$APP/WeChatMods/module-manifest.json"

codesign --force --sign - "$APP"

RUNTIMES_JSON="$(xcrun simctl list runtimes available -j)"
RUNTIME="$(python3 - "$TARGET_RUNTIME_VERSION" "$RUNTIMES_JSON" <<'PY'
import json
import sys

target = sys.argv[1]
runtimes = [
    item for item in json.loads(sys.argv[2])["runtimes"]
    if item["name"].startswith("iOS") and item.get("isAvailable", False)
]
exact = [
    item["identifier"] for item in runtimes
    if item.get("version") == target
]
print(exact[0] if exact else "")
PY
)"
if [[ -z "$RUNTIME" ]]; then
  echo "Required iOS Simulator runtime $TARGET_RUNTIME_VERSION is absent" >&2
  exit 1
fi

DEVICE_JSON="$(xcrun simctl list devices available -j)"
UDID="$(python3 - "$TARGET_DEVICE_NAME" "$RUNTIME" "$DEVICE_JSON" <<'PY'
import json
import sys

target = sys.argv[1]
runtime = sys.argv[2]
data = json.loads(sys.argv[3])
exact = []
for device in data["devices"].get(runtime, []):
    if (
        device.get("isAvailable", False)
        and device["name"] == target
    ):
        exact.append(device["udid"])
print(sorted(exact, reverse=True)[0] if exact else "")
PY
)"

CREATED_DEVICE=0
if [[ -z "$UDID" ]]; then
  DEVICE_TYPES_JSON="$(xcrun simctl list devicetypes -j)"
  DEVICE_TYPE="$(python3 - "$TARGET_DEVICE_NAME" "$DEVICE_TYPES_JSON" <<'PY'
import json
import sys
target = sys.argv[1]
types = json.loads(sys.argv[2])["devicetypes"]
exact = [item["identifier"] for item in types if item["name"] == target]
fallback = [
    item["identifier"] for item in types
    if item["name"].startswith("iPhone")
]
print((exact or fallback)[-1])
PY
)"
  UDID="$(xcrun simctl create \
    "WeChatMods-$TARGET_DEVICE_NAME" "$DEVICE_TYPE" "$RUNTIME")"
  CREATED_DEVICE=1
fi

if ! xcrun simctl list devices | grep -F "$UDID" | grep -q Booted; then
  xcrun simctl boot "$UDID"
fi
xcrun simctl bootstatus "$UDID" -b
xcrun simctl install "$UDID" "$APP"
xcrun simctl launch --terminate-running-process "$UDID" "$BUNDLE_ID"

DATA_CONTAINER="$(xcrun simctl get_app_container \
  "$UDID" "$BUNDLE_ID" data)"
DIAGNOSTICS="$DATA_CONTAINER/Documents/SimulatorHostDiagnostics.json"
for _ in $(seq 1 40); do
  [[ -s "$DIAGNOSTICS" ]] && break
  sleep 0.25
done
test -s "$DIAGNOSTICS"

cp "$DIAGNOSTICS" \
  "$ARTIFACTS/SimulatorHostDiagnostics.json"
xcrun simctl io "$UDID" screenshot \
  "$ARTIFACTS/SimulatorHost.png"

python3 - "$ARTIFACTS/SimulatorHostDiagnostics.json" <<'PY'
import json
import sys

path = sys.argv[1]
data = json.load(open(path, encoding="utf-8"))
expected = {
    "loader_constructor_ran": True,
    "settings_entry_count": 1,
    "settings_controller_opened": True,
    "window_matches_screen": True,
    "content_reaches_top_edge": True,
    "content_reaches_bottom_edge": True,
}
errors = []
for key, value in expected.items():
    if data.get(key) != value:
        errors.append(f"{key}: expected {value!r}, got {data.get(key)!r}")
if data.get("glass_effect_count", 0) < 2:
    errors.append(
        "glass_effect_count: expected two custom native glass effects"
    )
if data.get("glass_backdrop_count", 0) < 2:
    errors.append(
        "glass_backdrop_count: expected two hooked custom glass backdrops"
    )
if data.get("glass_effect_default_initializer_available") is not True:
    errors.append("UIGlassEffect default initializer is not available")
if errors:
    raise SystemExit("\n".join(errors))
print(json.dumps(data, ensure_ascii=False, indent=2))
PY

if [[ "$CREATED_DEVICE" == 1 ]]; then
  xcrun simctl shutdown "$UDID"
  xcrun simctl delete "$UDID"
fi
