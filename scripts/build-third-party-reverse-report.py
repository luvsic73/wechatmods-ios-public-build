from __future__ import annotations

import argparse
import json
import shutil
from collections import defaultdict
from pathlib import Path


SAMPLE_REPORTS = (
    "wechat-8.0.75-unpacked-only.json",
    "wechat-8.0.75-multiopen-windproof.json",
    "wechat-8.0.75-theme.json",
    "wechat-8.0.75-windproof2.json",
)

CONFIRMED_DECOMPILATION = {
    "wechatku_xnsp_identity_layer": {
        "confidence": "high",
        "evidence": "Ghidra function-level decompilation plus named-symbol address match",
        "wechatku_addresses": {
            "ASIdentifierManager advertisingIdentifier": "0x86070",
            "ManualAuthAesReqData setBundleId:": "0x86164",
            "ManualAuthAesReqData setClientSeqId:": "0x862a8",
            "ManualAuthAesReqData setDeviceName:": "0x864f4",
            "MMCrashReportExtLogMgr addLogInfo:withMessage:": "0x865a8",
            "JailBreakHelper HasInstallJailbreakPlugin": "0x865ac",
            "JailBreakHelper HasInstallJailbreakPluginInvalidIAPPurchase": "0x865b4",
            "JailBreakHelper IsJailBreak": "0x865bc",
        },
        "xnsp_addresses": {
            "ASIdentifierManager advertisingIdentifier": "0x85d30",
            "ManualAuthAesReqData setBundleId:": "0x85e24",
            "ManualAuthAesReqData setClientSeqId:": "0x85f68",
            "ManualAuthAesReqData setDeviceName:": "0x861b4",
            "MMCrashReportExtLogMgr addLogInfo:withMessage:": "0x86268",
            "JailBreakHelper HasInstallJailbreakPlugin": "0x8626c",
            "JailBreakHelper HasInstallJailbreakPluginInvalidIAPPurchase": "0x86274",
            "JailBreakHelper IsJailBreak": "0x8627c",
        },
        "behavior": [
            "advertisingIdentifier is replaced with a UUID persisted in NSUserDefaults key idfa",
            "setBundleId: replaces the current alternate bundle identifier with com.tencent.xin",
            "setClientSeqId: uses a persisted hyphen-free UUID in key clientSeqId and preserves the original suffix",
            "setDeviceName: supplies iPhone",
            "MMCrashReportExtLogMgr addLogInfo:withMessage: becomes a no-op",
            "three JailBreakHelper checks return zero",
        ],
        "other_initializers": {
            "0x5d0c8": "fishhook rebinding for ptrace, dlsym and syscall",
            "0x8adc0": "plugin registration and virtual-camera setup",
            "0x8afa8": "large Logos initializer covering many feature hooks",
            "0xae074": "voice-message paths and sendVoiceMessage concurrent queue",
            "0xae198": "destructor registration",
            "0xc3d0c": "configuration parsing",
        },
    },
    "block_tl_jump": {
        "confidence": "high",
        "evidence": "Ghidra decompilation of all seven functions",
        "functions": {
            "0x4000": "UIApplication openURL wrapper",
            "0x4054": "URL normalization and block decision",
            "0x4188": "openURL:options:completionHandler: wrapper",
            "0x4224": "constructor and swizzle installation",
            "0x431c": "post-launch reinforcement",
            "0x4524": "sensitive open wrapper",
            "0x45c4": "web-view loadRequest wrapper",
        },
        "behavior": [
            "normalizes absoluteString and lowercases it",
            "blocks only URLs containing tlvip.net or mzsm.html",
            "returns false through the completion handler when blocked",
            "reinstalls wrappers after UIApplicationDidFinishLaunchingNotification",
        ],
    },
    "wcfix_27_login_qr": {
        "confidence": "high",
        "evidence": "Ghidra decompilation of all six functions",
        "functions": ["0x4000", "0x4034", "0x45bc", "0x4638", "0x470c", "0x471c"],
        "behavior": [
            "hooks WCAccountLoginByQRCodeViewController onGetQRCodeImg:",
            "calls the original implementation first",
            "activates only when systemVersion numerically compares at or above 27.0",
            "reads private ivars _qrCodeImgView, _qrCodeFrameView, _scanQRCodeView and _loadingView",
            "re-renders the QR image with UIGraphicsImageRenderer and nearest filtering",
            "adjusts QR subview visibility, alpha and z-order",
        ],
        "scope": "iOS 27+ QR rendering only; it does not implement iOS 26.2 full-screen login safe-area adaptation",
    },
    "libsubstrote_vendor_logic": {
        "confidence": "high",
        "evidence": "Ghidra constructor/method decompilation plus Strongarm Objective-C runtime extraction",
        "initializers": {
            "0x130e0": "installs nine Logos hooks",
            "0x238f0": "reads embedded.mobileprovision and checks provisioning expiration",
        },
        "hooks": [
            "WCPluginsViewController viewDidAppear:",
            "CContactMgr isInContactList:",
            "WCTableViewCellManager normalCellForSel:target:title:rightValue:",
            "WCTableViewCellManager switchCellForSel:target:title:on:",
            "UILabel setText:",
            "WeChatTweakSettingsController viewDidLoad",
            "BNHelperSettingController followMyOfficalAccount",
            "BNHelperSettingController payingToAuthor",
            "NSURL URLWithString:",
        ],
        "runtime_classes": ["CustomPopupView", "CapsuleAlertView"],
        "decoded_strings": {
            "title": "定制到期提醒",
            "confirm": "续费",
            "other_button": "OK",
            "renewal_url": "https://qm.ioszn.com/",
            "defaults_key": "ProvisionAlertLastDate",
            "date_format": "yyyy-MM-dd",
        },
        "behavior": [
            "CapsuleAlertView doNotRemindToday persists the current date and dismisses",
            "CapsuleAlertView openRenewWebsite checks canOpenURL and opens the renewal URL",
            "CustomPopupView followButtonTapped dismisses and dispatches a delayed action",
        ],
    },
    "miyou_dynamic_replacement": {
        "confidence": "medium-high",
        "evidence": "Capstone selector-reference scan, imported-stub resolution and Strongarm runtime extraction",
        "selector_references": {
            "setBundleId:": [
                "0xa62f70",
                "0xa6ad94",
                "0xa6d610",
                "0xa6d6ec",
                "0xa72b88",
                "0xa72f14",
            ],
            "IsJailBreak": ["0xa636d8", "0xa66708"],
            "HasInstallJailbreakPluginInvalidIAPPurchase": ["0xa682b8"],
            "bundleId": ["0xa684c4"],
            "HasInstallJailbreakPlugin": ["0xa6af04"],
        },
        "imported_stubs": {
            "0xaf7e1c": "class_getInstanceMethod",
            "0xaf7ffc": "method_getImplementation",
            "0xaf80ec": "objc_release",
            "0xaf80f8": "objc_retain",
        },
        "limitation": "heavy control-flow flattening leaves several replacement bodies pending instruction-level recovery",
    },
}


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def third_party_loads(loads: list[str], baseline_loads: set[str]) -> list[str]:
    return sorted(
        load
        for load in loads
        if load not in baseline_loads
        and not load.endswith("/")
        and (
            load.startswith("@executable_path/")
            or load.startswith("@rpath/")
            or load.startswith("@loader_path/")
        )
    )


def build_sample_models(report_root: Path) -> list[dict[str, object]]:
    reports = [load_json(report_root / name) for name in SAMPLE_REPORTS]
    baseline = reports[0]
    baseline_by_path = {item["path"]: item for item in baseline["executables"]}
    baseline_paths = set(baseline_by_path)
    baseline_main = next(
        item
        for item in baseline["executables"]
        if Path(item["path"]).name == baseline["bundle"]["executable"]
    )
    baseline_loads = set(baseline_main["mach_o"]["load_dylibs"])
    sample_models = []
    for report_name, report in zip(SAMPLE_REPORTS, reports):
        main = next(
            item
            for item in report["executables"]
            if Path(item["path"]).name == report["bundle"]["executable"]
        )
        report_by_path = {item["path"]: item for item in report["executables"]}
        added_executables = sorted(
            (
                item
                for item in report["executables"]
                if item["path"] not in baseline_paths
            ),
            key=lambda item: item["path"],
        )
        changed_executables = sorted(
            (
                {
                    "path": path,
                    "official_sha256": baseline_by_path[path]["sha256"],
                    "sample_sha256": item["sha256"],
                    "sample": item,
                }
                for path, item in report_by_path.items()
                if path in baseline_by_path
                and item["sha256"] != baseline_by_path[path]["sha256"]
            ),
            key=lambda item: item["path"],
        )
        sample_models.append(
            {
                "source_report": str((report_root / report_name).resolve()),
                "file": report["file"],
                "bundle": report["bundle"],
                "signature": report["signature"],
                "executable_count": len(report["executables"]),
                "main_executable": {
                    "path": main["path"],
                    "sha256": main["sha256"],
                    "direct_added_loads": third_party_loads(
                        main["mach_o"]["load_dylibs"], baseline_loads
                    ),
                },
                "added_executables_vs_official": added_executables,
                "same_path_sha256_changes_vs_official": changed_executables,
                "removed_executable_paths_vs_official": sorted(
                    baseline_paths - set(report_by_path)
                ),
            }
        )
    return sample_models


def load_runtime_inventories(runtime_dir: Path) -> dict[str, dict[str, object]]:
    index = load_json(runtime_dir / "index.json")
    inventories = {}
    for entry in index["representatives"]:
        inventory = load_json(runtime_dir / entry["output"])
        inventory["inventory_file"] = str((runtime_dir / entry["output"]).resolve())
        inventories[entry["text_sha256"]] = inventory
    return inventories


def package_runtime_inventories(source: Path, destination: Path) -> Path:
    index = load_json(source / "index.json")
    destination.mkdir(parents=True, exist_ok=True)
    names = ["index.json", *(item["output"] for item in index["representatives"])]
    for name in names:
        shutil.copy2(source / name, destination / name)
    return destination


def build_conflicts(
    static_matrix: dict[str, object],
    inventories: dict[str, dict[str, object]],
) -> list[dict[str, object]]:
    sample_families: dict[str, dict[str, str]] = defaultdict(dict)
    for component in static_matrix["components"]:
        for occurrence in component["occurrences"]:
            sample_families[occurrence["sample"]][component["text_sha256"]] = component[
                "component"
            ]
    result = []
    for sample, families in sorted(sample_families.items()):
        target_owners: dict[tuple[str, str, str], set[str]] = defaultdict(set)
        for text_hash, component_name in families.items():
            inventory = inventories[text_hash]
            for hook in inventory["logos"]["hooks"]:
                target = (
                    hook["class"],
                    hook["selector"],
                    hook["method_type"],
                )
                target_owners[target].add(component_name)
        collisions = [
            {
                "class": target[0],
                "selector": target[1],
                "method_type": target[2],
                "components": sorted(owners),
            }
            for target, owners in target_owners.items()
            if len(owners) > 1
        ]
        result.append(
            {
                "sample": sample,
                "collision_count": len(collisions),
                "collisions": sorted(
                    collisions,
                    key=lambda item: (
                        item["class"],
                        item["selector"],
                        item["method_type"],
                    ),
                ),
            }
        )
    return result


def compare_variants(
    inventories: dict[str, dict[str, object]],
) -> dict[str, object]:
    by_name = {item["component"]: item for item in inventories.values()}
    left = by_name["wechatku.dylib"]["logos"]["hooks"]
    right = by_name["xnsp.dylib"]["logos"]["hooks"]

    def key(item: dict[str, str]) -> tuple[str, str, str]:
        return item["class"], item["selector"], item["method_type"]

    left_set = {key(item) for item in left}
    right_set = {key(item) for item in right}

    def records(values: set[tuple[str, str, str]]) -> list[dict[str, str]]:
        return [
            {"class": item[0], "selector": item[1], "method_type": item[2]}
            for item in sorted(values)
        ]

    return {
        "common_hook_count": len(left_set & right_set),
        "wechatku_only_count": len(left_set - right_set),
        "xnsp_only_count": len(right_set - left_set),
        "wechatku_only": records(left_set - right_set),
        "xnsp_only": records(right_set - left_set),
    }


def build_model(
    static_matrix: dict[str, object],
    component_matrix: dict[str, object],
    inventories: dict[str, dict[str, object]],
    samples: list[dict[str, object]],
) -> dict[str, object]:
    families = []
    for family in static_matrix["text_families"]:
        inventory = inventories[family["text_sha256"]]
        families.append(
            {
                "text_sha256": family["text_sha256"],
                "members": family["members"],
                "representative": inventory["component"],
                "representative_sha256": inventory["sha256"],
                "runtime_inventory_file": inventory["inventory_file"],
                "libraries": inventory["libraries"],
                "constructors": inventory["constructors"],
                "logos": {
                    "hook_count": inventory["logos"]["hook_count"],
                    "class_count": inventory["logos"]["class_count"],
                    "hooks_by_class": inventory["logos"]["hooks_by_class"],
                },
                "objc_runtime": {
                    key: inventory["objc_runtime"][key]
                    for key in (
                        "class_count",
                        "selector_count",
                        "ivar_count",
                    )
                },
                "static": inventory["static"],
            }
        )
    return {
        "schema_version": 1,
        "generated_for": "WeChat iOS 8.0.75 third-party IPA reverse analysis",
        "evidence_scope": {
            "sample_count": len(samples),
            "modified_sample_count": len(samples) - 1,
            "priority_component_occurrence_count": static_matrix["component_count"],
            "unique_text_family_count": static_matrix["text_family_count"],
            "methods": [
                "IPA metadata and Mach-O load-command inventory",
                "SHA-256 and __text SHA-256 family grouping",
                "LIEF symbol/section/import inspection",
                "Strongarm Objective-C class, selector and ivar extraction",
                "Logos symbol demangling and exact hook-target collision analysis",
                "Ghidra function-level decompilation for priority paths",
                "Capstone selector-reference scan for flattened code",
            ],
        },
        "samples": samples,
        "component_occurrences": component_matrix["occurrences"],
        "text_families": families,
        "runtime_inventory_index": [
            {
                "component": inventory["component"],
                "text_sha256": text_hash,
                "binary_path": inventory["path"],
                "inventory_file": inventory["inventory_file"],
                "logos_hook_count": inventory["logos"]["hook_count"],
                "objc_class_count": inventory["objc_runtime"]["class_count"],
                "objc_selector_count": inventory["objc_runtime"]["selector_count"],
                "runtime_error": inventory["objc_runtime"].get("error"),
            }
            for text_hash, inventory in sorted(inventories.items())
        ],
        "confirmed_decompilation": CONFIRMED_DECOMPILATION,
        "hook_conflicts": build_conflicts(static_matrix, inventories),
        "variant_comparison": compare_variants(inventories),
        "construction_model": [
            {
                "layer": 1,
                "name": "patched main executable",
                "role": "LC_LOAD_DYLIB entries start the third-party chain before normal app UI is stable",
            },
            {
                "layer": 2,
                "name": "hook and loader layer",
                "components": [
                    "libsubstrate.dylib",
                    "libsubstrote.dylib",
                    "tltdlimitation.dylib",
                    "WCPureExtension.dylib",
                ],
                "role": "method rebinding, plugin entry, vendor UI and provisioning logic",
            },
            {
                "layer": 3,
                "name": "aggregator layer",
                "components": [
                    "wechatku.dylib",
                    "xnsp.dylib",
                    "WeChatTweak.dylib",
                ],
                "role": "shared configuration, settings entry, identity/environment rewrites and feature orchestration",
            },
            {
                "layer": 4,
                "name": "feature layer",
                "components": [
                    "PKCWeChatTools.dylib",
                    "MiYou.dylib",
                    "HBWechatHelper.dylib",
                    "HBB9.1.2.dylib",
                    "WCFix27LoginQR.dylib",
                    "BlockTLJump.dylib",
                ],
                "role": "message, media, privacy, UI, automation and compatibility features",
            },
        ],
        "stability_risks": [
            "multiple components replace the same Objective-C method; order depends on image load and constructor order",
            "theme sample directly loads many feature libraries from the main executable, increasing startup blast radius",
            "private class and ivar names make hooks version-sensitive",
            "WCFix27LoginQR activates only for iOS 27+, leaving iOS 26.2 login layout untouched",
            "broad UIViewController and application-delegate hooks affect unrelated screens and lifecycle transitions",
            "vendor provisioning logic produces expiry UI and a renewal-site jump",
            "remote endpoints and embedded API-like values expand failure and privacy surfaces",
            "three modified samples lower MinimumOSVersion from 15.0 to 10.0 despite using a modern 8.0.75 base",
            "alternate bundle IDs coexist at installation level, while URL schemes, keychain groups, app groups and push entitlements remain separate compatibility dimensions",
        ],
        "reuse_decision": {
            "reuse_as_patterns": [
                "indirect loader with class-existence checks",
                "idempotent hook installation",
                "settings entry installed on multiple lifecycle callbacks",
                "per-module switches and explicit dependency checks",
                "safe mode keyed by last-enabled module",
            ],
            "reimplement_from_source": [
                "coexistence identifier and entitlement mapping",
                "settings entry and lifecycle",
                "anti-revoke",
                "iOS 26.2 full-screen login layout",
                "Liquid Glass navigation and control layer",
                "feature modules selected after hook-collision review",
            ],
            "exclude_from_install_candidate": [
                "libsubstrote vendor expiry/reminder/renewal behavior",
                "opaque remote configuration and embedded API credentials",
                "duplicate hooks whose order is not deterministic",
                "iOS 27-only QR patch as an iOS 26.2 layout solution",
            ],
            "account_layer_gate": [
                "serialize captured login/request fixtures offline",
                "diff official-base and alternate-bundle request fields",
                "assert stable identifiers across cold launches and resign cycles",
                "assert no mutation of credentials, keychain records, payment or core session database",
                "publish an install candidate only after the deterministic differential harness passes",
            ],
        },
        "previous_package_gap": [
            "the previous package was a minimal loader and UI layer rather than the four-layer model found in the samples",
            "it lacked a complete, fixture-verified identity/request differential layer",
            "its settings entry did not cover all observed lifecycle reload paths",
            "its login adapter did not implement iOS 26.2 full-screen safe-area behavior",
            "its Liquid Glass work was not verified against native iOS 26.2 rendering",
            "it was published before account behavior and runtime collision gates were complete",
        ],
    }


def markdown_report(model: dict[str, object], runtime_dir: Path) -> str:
    lines = [
        "# 第三方微信 IPA 完整构建与运行逻辑",
        "",
        "日期：2026-07-28  ",
        "基线：微信 iOS 8.0.75 / build 8.0.75.33  ",
        "证据等级：函数级反编译 > 运行时元数据 > Mach-O/字符串静态信号 > 推断。",
        "",
        "## 1. 本轮得到的确定结论",
        "",
        f"- 已审计 {model['evidence_scope']['modified_sample_count']} 个修改包和 1 个官方砸壳基线。",
        f"- 28 个优先深审组件实例归并为 {model['evidence_scope']['unique_text_family_count']} 个唯一 `__text` 代码族；其余新增 Mach-O 仍逐路径记录在逐包差分中。",
        "- 修改包采用四层链：主程序装载项 → Hook/加载层 → 聚合层 → 功能层。",
        "- `libsubstrote.dylib` 是“定制到期提醒”和续费网站跳转的直接来源。",
        "- `WCFix27LoginQR.dylib` 只修 iOS 27+ 二维码渲染，与 iOS 26.2 登录页铺满无关。",
        "- `wechatku.dylib` 与 `xnsp.dylib` 含相同的账号请求/环境改写核心，但功能和设置入口表面不同。",
        "- 包内同时存在多套大范围 Hook；实际稳定性取决于构造顺序、重复目标和宿主私有类版本。",
        "",
        "## 2. 逐包构建数据",
        "",
    ]
    for sample in model["samples"]:
        bundle = sample["bundle"]
        lines.extend(
            [
                f"### {sample['file']['name']}",
                "",
                f"- IPA SHA-256：`{sample['file']['sha256']}`",
                f"- 大小：{sample['file']['size']} bytes",
                f"- Bundle ID：`{bundle['identifier']}`",
                f"- 版本/build：`{bundle['version']}` / `{bundle['build']}`",
                f"- MinimumOSVersion：`{bundle['minimum_os']}`",
                f"- Mach-O 数：{sample['executable_count']}",
                f"- 主程序 SHA-256：`{sample['main_executable']['sha256']}`",
                "- 主程序新增直接装载：",
            ]
        )
        loads = sample["main_executable"]["direct_added_loads"]
        lines.extend(f"  - `{load}`" for load in loads)
        if not loads:
            lines.append("  - 基线包：无第三方新增装载项")
        lines.extend(
            [
                f"- 相对基线新增可执行路径：{len(sample['added_executables_vs_official'])}",
                f"- 相对基线同路径文件 SHA-256 变化：{len(sample['same_path_sha256_changes_vs_official'])}",
                "",
            ]
        )
    lines.extend(
        [
            "完整签名、Entitlements、URL Scheme、新增/变化/移除的 Mach-O 元数据及原始审计报告路径均保存在同目录 `full-runtime-model.json`。",
            "",
            "## 3. 四层启动与运行链",
            "",
            "```mermaid",
            "flowchart LR",
            '  A["WeChat 主程序 LC_LOAD_DYLIB"] --> B["Hook/加载层"]',
            '  B --> C["聚合层 wechatku / xnsp / WeChatTweak"]',
            '  C --> D["功能层 PKC / MiYou / HB / HBB"]',
            '  B --> E["兼容补丁 BlockTL / WCFix"]',
            '  D --> F["微信私有类与生命周期方法"]',
            "  E --> F",
            "```",
            "",
            "### 三个修改包的直接装载差异",
            "",
            "- 多开防风：主程序只直接拉起 `BlockTLJump`、`libsubstrate`、`libsubstrote`、`tltdlimitation`，其余功能由依赖链递归加载。",
            "- 防风版 2：主程序直接拉起 `WCPureExtension`、`libsubstrate`、`libsubstrote`、`tltdlimitation`，再由递归依赖带入功能组件。",
            "- 美化版：主程序直接拉起 DouTu、JiDe、MiYou、Mikoto、PKC、ThemeBox、WCFix、WCPure、WeChatEnhance、XOS、ZDY、插件管理器、xnsp 等，启动期冲突面最大。",
            "",
            "## 4. 13 个唯一代码族",
            "",
            "| 组件 | `__text` SHA-256 前缀 | Logos Hook | Hook 类 | ObjC 类 | ObjC selectors |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for family in model["text_families"]:
        lines.append(
            f"| {family['representative']} | `{family['text_sha256'][:16]}` | "
            f"{family['logos']['hook_count']} | {family['logos']['class_count']} | "
            f"{family['objc_runtime']['class_count']} | "
            f"{family['objc_runtime']['selector_count']} |"
        )
    lines.extend(
        [
            "",
            f"每个类、selector、ivar、依赖库、Hook 目标和地址保存在：`{runtime_dir}`。",
            "",
            "### PKCWeChatTools",
            "",
            "- 335 个唯一 Logos Hook，覆盖 94 个宿主类。",
            "- 密集目标：`BaseMsgContentViewController` 44、`ChatRoomInfoViewController` 18、`WCImageFullScreenViewController` 17、`WCListViewController` 17、`CMessageMgr` 9。",
            "- 同时触及消息、群聊、联系人、朋友圈、媒体、文件、红包、步数、AppDelegate 和设置页。",
            "- 运行时另提取 75 个自有 ObjC 类、4530 个 selectors；完整表在 PKC 运行清单 JSON。",
            "",
            "### wechatku 与 xnsp",
            "",
            f"- 共同 Hook：{model['variant_comparison']['common_hook_count']}。",
            f"- wechatku 独有：{model['variant_comparison']['wechatku_only_count']}；xnsp 独有：{model['variant_comparison']['xnsp_only_count']}。",
            "- xnsp 独有入口集中在 `NewSettingViewController reloadTableData`、`WCPluginsViewController reloadTableData`、`UIViewController viewDidLoad` 和文件消息菜单。",
            "- wechatku 额外加入设置刷新以及大量 UIViewController 手势、粘贴、截屏和输入处理。",
            "",
            "### MiYou / HB / HBB / WeChatTweak",
            "",
            "- MiYou：52 个 ObjC 类、1629 个 selectors；类名直接显示任务、自动回复、主题、字体、通知、文件、会话盒、ChatGPT、运动和隐私工具。",
            "- HBWechatHelper：55 个 ObjC 类、1894 个 selectors；覆盖键盘、消息、群、朋友圈、壁纸、头像框、语音和多选联系人。",
            "- HBB 9.1.2：59 个高度混淆 Swift/ObjC 类；公开类名信息量低，后续按关键 selector 和调用点继续恢复。",
            "- WeChatTweak：运行时暴露 WCCC 配置、加密、灰度描述和设置控制器；更多行为在 C++/构造器路径。",
            "",
            "## 5. 函数级确认逻辑",
            "",
            "### 账号身份与环境改写（wechatku / xnsp）",
            "",
        ]
    )
    identity = model["confirmed_decompilation"]["wechatku_xnsp_identity_layer"]
    lines.extend(f"- {item}" for item in identity["behavior"])
    lines.extend(
        [
            "",
            "这组行为是样本中实际存在的请求字段和环境改写。它只证明“别人怎么做”，账号结果仍需离线请求差分与稳定标识回归来判定。",
            "",
            "### 到期提醒与网站跳转（libsubstrote）",
            "",
            "- `0x238f0` 读取 `embedded.mobileprovision` 并进入有效期检查。",
            "- `CapsuleAlertView` 显示“定制到期提醒”，按钮包含“续费”。",
            "- `openRenewWebsite` 调用 `canOpenURL` 后打开 `https://qm.ioszn.com/`。",
            "- 当日提醒状态写入 `ProvisionAlertLastDate`，格式为 `yyyy-MM-dd`。",
            "- 同一组件还 Hook `NSURL URLWithString:`、设置页、插件页、联系人和 UILabel。",
            "",
            "### BlockTLJump",
            "",
            "- 只匹配 `tlvip.net` 与 `mzsm.html`，覆盖 UIApplication 打开 URL 和 web-view 请求。",
            "- 它属于针对特定推广链接的补丁；它并非通用恶意外联拦截层。",
            "",
            "### WCFix27LoginQR",
            "",
            "- Hook `WCAccountLoginByQRCodeViewController onGetQRCodeImg:`。",
            "- 仅 `systemVersion >= 27.0` 时重绘二维码并调整私有子视图。",
            "- iOS 26.2 登录页顶部/底部铺满问题需要单独的安全区和窗口层适配。",
            "",
            "## 6. Hook 冲突与卡死/闪退来源",
            "",
        ]
    )
    for conflict in model["hook_conflicts"]:
        lines.append(
            f"- {conflict['sample']}：识别到 {conflict['collision_count']} 个同目标多组件 Hook。"
        )
        for item in conflict["collisions"][:12]:
            lines.append(
                f"  - `{item['class']} {item['selector']}` ← "
                + ", ".join(item["components"])
            )
        if conflict["collision_count"] > 12:
            lines.append("  - 其余目标见 `full-runtime-model.json`。")
    lines.extend(
        [
            "",
            "主要失稳链：",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in model["stability_risks"])
    lines.extend(
        [
            "",
            "## 7. 上一安装包问题为何连续出现",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in model["previous_package_gap"])
    lines.extend(
        [
            "",
            "结论：上一包在完整运行模型尚未建立时提前打包，既没有复用样本已存在的四层加载规律，也没有先消除厂商弹窗/跳站和重复 Hook。",
            "",
            "## 8. 重构边界",
            "",
            "### 复用架构规律",
        ]
    )
    lines.extend(f"- {item}" for item in model["reuse_decision"]["reuse_as_patterns"])
    lines.extend(["", "### 重新实现并纳入测试"])
    lines.extend(
        f"- {item}" for item in model["reuse_decision"]["reimplement_from_source"]
    )
    lines.extend(["", "### 从安装候选剔除"])
    lines.extend(
        f"- {item}"
        for item in model["reuse_decision"]["exclude_from_install_candidate"]
    )
    lines.extend(["", "### 账号层发布门槛"])
    lines.extend(f"- {item}" for item in model["reuse_decision"]["account_layer_gate"])
    lines.extend(
        [
            "",
            "## 9. 当前交付状态",
            "",
            "- 已生成逐组件完整运行清单、逐包元数据、函数级证据、Hook 冲突表和重构决策。",
            "- 旧 IPA 保持隔离，本轮未把任何新文件标记为安装候选。",
            "- 下一阶段直接按此模型重构：先离线账号请求差分，再设置入口/登录布局/Liquid Glass，最后逐模块冲突回归。",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--static-matrix", required=True, type=Path)
    parser.add_argument("--component-matrix", required=True, type=Path)
    parser.add_argument("--runtime-dir", required=True, type=Path)
    parser.add_argument("--sample-report-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    arguments = parser.parse_args()

    static_matrix = load_json(arguments.static_matrix)
    component_matrix = load_json(arguments.component_matrix)
    packaged_runtime_dir = package_runtime_inventories(
        arguments.runtime_dir,
        arguments.output_dir / "runtime-inventory",
    )
    inventories = load_runtime_inventories(packaged_runtime_dir)
    samples = build_sample_models(arguments.sample_report_dir)
    model = build_model(
        static_matrix,
        component_matrix,
        inventories,
        samples,
    )
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    model_path = arguments.output_dir / "full-runtime-model.json"
    report_path = arguments.output_dir / "第三方IPA完整构建与运行逻辑-2026-07-28.md"
    model_path.write_text(
        json.dumps(model, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    report_path.write_text(
        markdown_report(model, packaged_runtime_dir.resolve()),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "model": str(model_path.resolve()),
                "report": str(report_path.resolve()),
                "sample_count": len(model["samples"]),
                "text_family_count": len(model["text_families"]),
                "conflict_count": sum(
                    item["collision_count"] for item in model["hook_conflicts"]
                ),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
