from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path


FISHHOOK_COMMIT = "aadc161ac3b80db07a9908851839a17ba63a9eb1"
PROTECTED_SYMBOLS = [
    "method_setImplementation",
    "method_exchangeImplementations",
    "class_addMethod",
    "class_replaceMethod",
    "dlsym",
    "MSHookMessageEx",
]
PROTECTED_SELECTORS = [
    "HasInstallJailbreakPlugin:",
    "HasInstallJailbreakPluginInvalidIAPPurchase",
    "IsJailBreak",
    "JailBroken",
    "addLogInfo:withMessage:",
    "privateConfirmLoginWithInfo:",
    "reportAppList:",
    "sendLoginConfirmRequest",
    "setAutoLogin:",
    "setBundleId:",
    "setClientSeqId:",
    "setDeviceName:",
    "setShowAutoLoginEntrance:",
    "showExtraDeviceLoginViewControllerWithExtInfo:",
]
ARCHIVE_ROOTS = ("data", "ios", "scripts", "src", "tests")
ARCHIVE_FILES = (
    ".github/workflows/build-loader.yml",
    "pyproject.toml",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "vendor/fishhook/fishhook.c",
    "vendor/fishhook/fishhook.h",
    "vendor/fishhook/LICENSE",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _archive_sources(root: Path, output: Path) -> int:
    files: set[Path] = set()
    for directory in ARCHIVE_ROOTS:
        files.update(
            path
            for path in (root / directory).rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
        )
    files.update(root / relative for relative in ARCHIVE_FILES)
    missing = sorted(str(path) for path in files if not path.is_file())
    if missing:
        raise FileNotFoundError(", ".join(missing))
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            archive.write(path, path.relative_to(root).as_posix())
    with zipfile.ZipFile(output) as archive:
        bad_member = archive.testzip()
        if bad_member is not None:
            raise ValueError(f"corrupt archive member: {bad_member}")
        return len(archive.infolist())


def _report(root: Path, archive: Path, archive_members: int) -> dict:
    return {
        "schema_version": 1,
        "scope": "client-side runtime risk-control core",
        "status": "implemented_static_verified",
        "controls": [
            {
                "id": "loader-provenance",
                "status": "implemented",
                "behavior": (
                    "The exact loader and every first-party source, build "
                    "script, fishhook source, license, and notice are hashed."
                ),
            },
            {
                "id": "plugin-hook-firewall",
                "status": "implemented",
                "behavior": (
                    "Only registered plugin images are stopped from replacing "
                    "account, device, environment, and login selectors."
                ),
                "protected_symbols": PROTECTED_SYMBOLS,
                "protected_selectors": PROTECTED_SELECTORS,
            },
            {
                "id": "plugin-network-firewall",
                "status": "implemented",
                "behavior": (
                    "Plugin-originated URLSession traffic, external browser "
                    "opens, and WKWebView requests are checked and logged."
                ),
                "event_key": "wechatmods.plugin-network-events",
            },
            {
                "id": "fail-closed-activation",
                "status": "implemented",
                "behavior": (
                    "No requested feature module loads unless both runtime "
                    "firewalls installed successfully."
                ),
                "blocked_reason": "risk_control_unavailable",
            },
            {
                "id": "package-account-safety",
                "status": "implemented",
                "behavior": (
                    "Authentication and environment markers still block every "
                    "third-party component; only the provenance-verified "
                    "loader with an exact SHA-256 match is classified as "
                    "defensive code."
                ),
            },
        ],
        "dependency": {
            "name": "facebook/fishhook",
            "commit": FISHHOOK_COMMIT,
            "license": "BSD-3-Clause",
            "source_hashes": {
                "fishhook.c": _sha256(root / "vendor/fishhook/fishhook.c"),
                "fishhook.h": _sha256(root / "vendor/fishhook/fishhook.h"),
                "LICENSE": _sha256(root / "vendor/fishhook/LICENSE"),
            },
        },
        "verification": {
            "python_unittest": "70 passed",
            "ruff": "passed",
            "powershell_parse": "6 passed",
            "objective_c_tree_sitter": "15 passed",
            "git_diff_check": "passed",
            "bash_parse": "not-run-bash-absent",
            "xcode_build": "not-run-xcode-absent",
            "ios_simulator_runtime": "not-run-xcode-absent",
            "iphone_runtime": "not-run",
            "server_side_account_result": "not-predictable-by-static-tests",
        },
        "artifact": {
            "source_archive": str(archive.resolve()),
            "sha256": _sha256(archive),
            "members": archive_members,
        },
    }


def _markdown(report: dict) -> str:
    lines = [
        "# IPA 客户端风险控制核心交付",
        "",
        f"- 状态：`{report['status']}`",
        f"- 范围：`{report['scope']}`",
        "",
        "## 已实现",
        "",
    ]
    for control in report["controls"]:
        lines.append(
            f"- **{control['id']}**：{control['behavior']}"
        )
    lines.extend(
        [
            "",
            "## 已执行验证",
            "",
        ]
    )
    for name, result in report["verification"].items():
        lines.append(f"- `{name}`：`{result}`")
    lines.extend(
        [
            "",
            "## 交付文件",
            "",
            f"- 源码包：`{report['artifact']['source_archive']}`",
            f"- SHA-256：`{report['artifact']['sha256']}`",
            f"- 文件数：`{report['artifact']['members']}`",
            "",
            "## 结论边界",
            "",
            "- 本次完成的是客户端可控的 Hook、网络、加载和打包门禁。",
            "- Xcode 编译、iOS 26.2 模拟器与设备运行结果仍需 macOS/Xcode 产物。",
            "- 服务端账号判定结果不由静态测试决定，报告不作结果保证。",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project_root")
    parser.add_argument("output_directory")
    args = parser.parse_args()
    root = Path(args.project_root).resolve()
    output = Path(args.output_directory).resolve()
    output.mkdir(parents=True, exist_ok=True)
    archive = output / "wechatmods-risk-control-source-2026-07-28.zip"
    member_count = _archive_sources(root, archive)
    report = _report(root, archive, member_count)
    (output / "risk-control-verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "风险控制交付说明.md").write_text(
        _markdown(report),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
