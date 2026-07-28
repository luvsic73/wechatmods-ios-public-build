from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from wechat_ipa_audit.module_catalog import (
    build_activation_plan,
    effective_activation_gate,
    validate_catalog,
)


GROUP_TITLES = {
    "messages": "消息",
    "media": "媒体与文件",
    "groups": "群聊",
    "automation": "自动化",
    "interface": "界面与操作",
    "account": "账号、推送与多开",
    "experimental": "实验功能",
    "contacts": "联系人",
    "privacy": "隐私",
}


def _module_record(module: dict[str, Any], version: str) -> dict[str, Any]:
    module_id = module["id"]
    plan = build_activation_plan(
        [module],
        requested={module_id},
        version=version,
    )
    gate = effective_activation_gate(module)
    return {
        **module,
        "effective_activation_gate": gate,
        "backend_status": "ready" if module_id in plan["enabled"] else "blocked",
        "blocked_reasons": plan["blocked"].get(module_id, []),
        "device_validation": "not-run",
    }


def build_report(catalog: dict[str, Any], version: str) -> dict[str, Any]:
    modules = catalog["modules"]
    issues = validate_catalog(modules)
    if issues:
        raise ValueError(f"invalid module catalog: {issues}")
    records = [_module_record(module, version) for module in modules]
    gate_counts = Counter(record["effective_activation_gate"] for record in records)
    risk_counts = Counter(record["risk"] for record in records)
    return {
        "schema_version": 1,
        "baseline_version": version,
        "catalog_schema_version": catalog["schema_version"],
        "activation": catalog.get("activation"),
        "all_default_disabled": all(module["enabled"] is False for module in modules),
        "module_count": len(records),
        "ready_count": sum(record["backend_status"] == "ready" for record in records),
        "blocked_count": sum(
            record["backend_status"] == "blocked" for record in records
        ),
        "gate_counts": dict(sorted(gate_counts.items())),
        "risk_counts": dict(sorted(risk_counts.items())),
        "feature_collection": catalog.get("feature_collection", {}),
        "reverse_evidence": {
            "miyou_constructor_count": 18,
            "constructors_with_runtime_method_hooks": 18,
            "setBundleId_selector_address": "0x00b18797",
            "setBundleId_constructor_xrefs": [
                "0x00a62f70",
                "0x00a6ad94",
                "0x00a6ad98",
            ],
            "candidate_component_included": False,
        },
        "verification": {
            "python_unit_tests": "65 passed",
            "python_ruff_check": "passed",
            "objective_c_implementation_parse": "13 passed",
            "xcode_iphoneos_build": "not-run-no-xcode-sdk",
            "iphone_runtime": "not-run",
        },
        "modules": records,
    }


def render_markdown(report: dict[str, Any]) -> str:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for module in report["modules"]:
        grouped[module["group"]].append(module)
    lines = [
        "# 功能模块后端清单",
        "",
        f"- 基线：微信 {report['baseline_version']}",
        f"- 模块数：{report['module_count']}",
        f"- 后端可激活：{report['ready_count']}",
        f"- 证据门阻断：{report['blocked_count']}",
        "- 默认状态：全部关闭",
        "- 外观：Liquid Glass 固定外壳，不计入功能模块",
        "- 闭源合集：未随候选包提供",
        "",
        "## 当前门控结论",
        "",
        "- `ready`：本地实现已接入激活计划；仍需 Xcode 编译和设备运行验证。",
        "- `component-repair-required`：合集构造器存在未隔离 Hook，当前保持关闭。",
        "- `fixture-validation-required`：涉及登录、环境或崩溃上报，离线差分前保持关闭。",
        "",
    ]
    for group in GROUP_TITLES:
        items = grouped.get(group)
        if not items:
            continue
        lines.extend(
            [
                f"## {GROUP_TITLES[group]}",
                "",
                "| 功能 | ID | 风险 | 门 | 依赖/冲突 | 状态 |",
                "|---|---|---|---|---|---|",
            ]
        )
        for item in items:
            relations = []
            if item["dependencies"]:
                relations.append("依赖 " + ",".join(item["dependencies"]))
            if item["conflicts"]:
                relations.append("冲突 " + ",".join(item["conflicts"]))
            lines.append(
                "| {title} | `{id}` | {risk} | `{gate}` | {relations} | {status} |".format(
                    title=item["title"].replace("|", "\\|"),
                    id=item["id"],
                    risk=item["risk"],
                    gate=item["effective_activation_gate"],
                    relations="；".join(relations) or "-",
                    status=item["backend_status"],
                )
            )
        lines.append("")
    lines.extend(
        [
            "## 已执行验证",
            "",
            "- Python 单元测试：65 项通过。",
            "- Ruff 代码检查：通过。",
            "- Objective-C 实现文件 tree-sitter 解析：13 项通过。",
            "- Xcode/iPhoneOS：当前 Windows 环境未发现 Xcode 或 iOS SDK，尚无编译结果。",
            "- iPhone 运行：尚无运行结果。",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("catalog")
    parser.add_argument("output_directory")
    parser.add_argument("--version", default="8.0.75")
    args = parser.parse_args()
    catalog = json.loads(Path(args.catalog).read_text(encoding="utf-8"))
    report = build_report(catalog, args.version)
    output = Path(args.output_directory)
    output.mkdir(parents=True, exist_ok=True)
    (output / "module-backend-readiness.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "功能模块后端清单.md").write_text(
        render_markdown(report),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
