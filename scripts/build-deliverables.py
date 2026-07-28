from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"

SAMPLES = [
    {
        "slug": "unpacked-only",
        "id": "qingtian-8075-unpacked-only",
        "report": "wechat-8.0.75-unpacked-only.json",
        "kind": "仅砸壳",
        "verdict": "Inconclusive",
        "confidence": "Medium",
        "reason": "未发现相对基线新增组件；但缺少 App Store 原包逐字节对照和设备动态测试。",
    },
    {
        "slug": "windproof2",
        "id": "qingtian-8075-windproof2",
        "report": "wechat-8.0.75-windproof2.json",
        "diff": "diff-unpacked-vs-windproof2.json",
        "deep": "deep-scan-windproof2.json",
        "kind": "防风版2",
        "verdict": "Suspicious",
        "confidence": "High",
        "reason": "新增 14 个闭源可执行组件，存在反调试、动态加载、敏感数据 API 和多组非官方域名/IP。",
    },
    {
        "slug": "multiopen-windproof",
        "id": "qingtian-8075-multiopen-windproof",
        "report": "wechat-8.0.75-multiopen-windproof.json",
        "diff": "diff-unpacked-vs-multiopen-windproof.json",
        "deep": "deep-scan-multiopen-windproof.json",
        "kind": "多开防风",
        "verdict": "Suspicious",
        "confidence": "High",
        "reason": "新增 14 个闭源可执行组件，含 BlockTLJump、反调试、动态加载、敏感数据 API 和非官方外联。",
    },
    {
        "slug": "theme",
        "id": "qingtian-8075-theme",
        "report": "wechat-8.0.75-theme.json",
        "diff": "diff-unpacked-vs-theme.json",
        "deep": "deep-scan-theme.json",
        "kind": "美化版",
        "verdict": "Suspicious",
        "confidence": "High",
        "reason": "新增 16 个闭源组件，含登录二维码修复组件、敏感数据 API、反调试和多组非官方外联。",
    },
]

CONFLICTS = [
    ("anti-revoke", "message-actions", "message dispatcher overlap", "medium", "单一消息观察器，多订阅者只读分发"),
    ("anti-revoke", "keyword-reply", "message pipeline and database timing", "high", "关键词模块延迟执行且不得写核心消息表"),
    ("message-actions", "keyword-reply", "duplicate action dispatch", "high", "复用 message-actions 注册表"),
    ("multi-instance-routing", "push-adapter", "Bundle ID and token routing", "high", "每个签名配置独立适配器与配置目录"),
    ("multi-instance-routing", "callkit-adapter", "Bundle ID and entitlement routing", "high", "构建期能力校验，缺能力则不生成"),
    ("multi-instance-routing", "ipad-session-adapter", "session routing", "high", "仅观察会话状态，保持登录校验原状"),
    ("push-adapter", "callkit-adapter", "background lifecycle", "high", "统一后台事件总线与超时预算"),
    ("location-fixture", "motion-fixture", "test-fixture state", "medium", "实验模块互斥且只在测试配置出现"),
    ("virtual-video-fixture", "media-export", "camera/media pipeline", "high", "实验模块启用时停用导出 Hook"),
]


def load(name: str):
    return json.loads((REPORTS / name).read_text(encoding="utf-8"))


def source_index() -> tuple[dict, dict]:
    source_data = json.loads((ROOT / "data" / "sources.json").read_text(encoding="utf-8"))
    return (
        {sample["id"]: sample for sample in source_data["samples"]},
        source_data,
    )


def yara_index() -> dict[tuple[str, str], list[str]]:
    index: dict[tuple[str, str], list[str]] = {}
    for row in load("yara-components.json"):
        path = Path(row["file"])
        digest_prefix = path.name.split("-", 1)[0]
        index[(path.parent.name, digest_prefix)] = [
            match["rule"] for match in row["matches"]
        ]
    return index


def write_sample_table(source_samples: dict[str, dict]) -> list[dict]:
    rows = []
    for sample in SAMPLES:
        audit = load(sample["report"])
        source = source_samples[sample["id"]]
        diff = load(sample["diff"]) if sample.get("diff") else {"added": [], "modified": []}
        rows.append(
            {
                "样本": sample["kind"],
                "文件名": audit["file"]["name"],
                "版本": audit["bundle"]["version"],
                "build": audit["bundle"]["build"],
                "Bundle ID": audit["bundle"]["identifier"],
                "最低 iOS": audit["bundle"]["minimum_os"],
                "字节数": audit["file"]["size"],
                "SHA-256": audit["file"]["sha256"],
                "新增可执行组件": len(diff["added"]),
                "修改可执行文件": len(diff["modified"]),
                "结论": sample["verdict"],
                "置信度": sample["confidence"],
                "来源": source["source"],
                "来源链接": source["page_url"],
            }
        )
    path = REPORTS / "聚合站与样本总表.csv"
    with path.open("w", encoding="utf-8-sig", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return rows


def write_component_table() -> tuple[list[dict], Counter]:
    yara = yara_index()
    rows = []
    shared = Counter()
    sample_dir = {
        "windproof2": "windproof2",
        "multiopen-windproof": "multiopen-windproof",
        "theme": "theme",
    }
    for sample in SAMPLES[1:]:
        for component in load(sample["deep"]):
            name = PurePosixPath(component["path"]).name
            shared[component["sha256"]] += 1
            rules = yara.get(
                (sample_dir[sample["slug"]], component["sha256"][:12]), []
            )
            rows.append(
                {
                    "样本": sample["kind"],
                    "组件": name,
                    "SHA-256": component["sha256"],
                    "字节数": component["size"],
                    "风险标记": ";".join(component["risk_markers"]),
                    "疑似硬编码秘密数量": component["hardcoded_secret_count"],
                    "域名或IP": ";".join(component["domains"]),
                    "YARA复核规则": ";".join(rules),
                }
            )
    path = REPORTS / "注入组件风险矩阵.csv"
    with path.open("w", encoding="utf-8-sig", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return rows, shared


def write_conflicts() -> None:
    path = REPORTS / "模块冲突矩阵.csv"
    with path.open("w", encoding="utf-8-sig", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(["模块A", "模块B", "冲突面", "风险", "处理"])
        writer.writerows(CONFLICTS)


def write_dynamic_checklist() -> None:
    (REPORTS / "动态测试与验收清单.md").write_text(
        """# 动态测试与验收清单

当前状态：**未执行设备动态测试**。静态结论不得替代以下项目。

## 账号与消息

- [ ] 两只隔离测试号完成新设备验证和扫码登录。
- [ ] 双向发送文本、图片、语音、视频、文件各 20 次。
- [ ] 群聊、引用、撤回、转发、导出逐项验证。
- [ ] 记录每次账号风险提示；出现提示则该构建判定失败。

## 稳定性

- [ ] 纯净基线 20 次冷启动和 20 次后台恢复。
- [ ] 10 次设备重启/重新登录。
- [ ] 7 天 iLoader 刷新、覆盖升级和配置保留。
- [ ] 各模块逐个启用后重复启动/后台/消息测试。
- [ ] 完成 `模块冲突矩阵.csv` 的两两组合。

## 推送和系统集成

- [ ] 前台、后台、被系统终止后的推送。
- [ ] CallKit 来电、挂断、锁屏与后台超时。
- [ ] iPad 登录、退出和手机端会话状态同步。
- [ ] 记录实际 Bundle ID、Entitlements、App Groups 和 Keychain Groups。

## 性能门槛

- [ ] 启动时间、峰值内存和 30 分钟耗电相对基线回归均不超过 15%。
- [ ] 无 Watchdog、持续闪退、登录状态丢失或聊天数据库损坏。
- [ ] 连续两次异常启动进入 Safe Mode，并标记最后启用模块。
""",
        encoding="utf-8",
    )


def write_rollback() -> None:
    (REPORTS / "回滚说明.md").write_text(
        """# 回滚说明

1. 保留原始 `8.0.75 仅砸壳` 的 SHA-256 和只读备份。
2. iLoader 签名前保存 `wechatmods-iloader.ipa`；签名后另存实际安装结果。
3. 首次安装后导出实际 Bundle ID、Entitlements 与容器路径，禁止把推测值写回构建配置。
4. 单模块异常：删除模块配置中的启用标记并重启；连续两次异常会自动进入 Safe Mode。
5. 启动失败：用 iLoader 覆盖安装全模块关闭的同 Bundle ID 包。
6. 会话或数据库异常：停止模块测试，保留崩溃日志和容器副本，再覆盖回纯净基线。
7. 签名能力变化：停用 push/callkit/qy/wx/mm 配置，重新按实际证书能力生成。

回滚验证：冷启动、登录状态、最近会话、收发消息、后台恢复和推送均恢复到基线表现。
""",
        encoding="utf-8",
    )


def write_summary(rows: list[dict], component_rows: list[dict], shared: Counter, source_data: dict) -> None:
    yara_matched_files = sum(
        1 for row in load("yara-components.json") if row["matches"]
    )
    marker_counts = Counter()
    for row in component_rows:
        marker_counts.update(filter(None, row["风险标记"].split(";")))
    shared_count = sum(1 for count in shared.values() if count > 1)
    site_lines = "\n".join(
        f"- [{site['name']}]({site['url']})：{site['access']}"
        for site in source_data["sites"]
    )
    sample_lines = "\n".join(
        f"- **{sample['kind']} — {sample['verdict']} ({sample['confidence']})**：{sample['reason']}"
        for sample in SAMPLES
    )
    hash_lines = "\n".join(
        f"- `{row['SHA-256']}` — {row['样本']} / {row['文件名']}"
        for row in rows
    )
    report = f"""# 微信 8.0.75 IPA 静态审计总报告

生成时间：2026-07-27（Asia/Shanghai）

## 执行摘要

- Apple 中国区当前稳定版复核为 **8.0.75**；取得的纯净砸壳样本报告 build **8.0.75.33**、最低 iOS **15.0**。
- 8.0.76 仍在候选隔离队列，未作为底座。
- 已取得 4 个唯一 IPA SHA-256：1 个仅砸壳基线、3 个功能包。
- 3 个功能包相对基线共提取 44 个组件副本、{len(shared)} 个唯一组件哈希，其中 {shared_count} 个哈希跨包复用。
- ClamAV 1.5.3 使用 3,627,981 条签名扫描 44 个文件，结果 **0 infected**。
- YARA 的本地启发式复核规则命中 {yara_matched_files}/44 个文件；命中只表示存在敏感 API 或反调试/动态加载组合。
- 四个整包 SHA-256 的公开网页情报检索均无结果；未向多引擎服务上传整包或组件。
- 当前证据支持 `Suspicious`，未支持把功能包直接判为 `Malicious`。

## 样本结论

{sample_lines}

### 不稳定因素

1. 功能包把 Bundle ID 改为 `com.tencent.qy.xin`，部分包把 build 从 `8.0.75.33` 改为 `8.0.75`、最低 iOS 从 15 降为 10。
2. 功能包各有 24 个已有可执行文件发生变化，除签名变更外仍需设备回归验证。
3. `PKCWeChatTools.dylib` 含大量第三方 AI、语音、地图和远程资源域名。
4. `wechatku.dylib` / `xnsp.dylib` 出现硬编码 IP、FTP 风格域名、远程资源与动态加载组合。
5. 美化版包含 `WCFix27LoginQR.dylib`，直接落在登录相关表面，不纳入自有模块。
6. 多个组件同时使用 Substrate、`+load`/构造阶段初始化和消息/媒体接口，存在 Hook 顺序与重复 Hook 风险。

## 工具证据

- **ClamAV**：见 `clamav-components.txt`；0/44 命中已知签名。最终预签包另见 `clamav-final.txt`；扫描 1.64 GiB，0 infected。
- **YARA**：见 `yara-components.json` 和 `注入组件风险矩阵.csv`。
- **LIEF/自研解析器**：记录每个 Mach-O 的 load commands、加密和签名命令。
- **Ghidra 12.1.2 + MCP 5.17.0**：已反编译 PKC、xnsp、HBB 和 WCFix27LoginQR 的初始化路径；摘要见 `ghidra-findings.json`，原始输出见 `ghidra-priority-raw.json`。
- 风险标记计数：`{dict(marker_counts)}`。

## 自用构建决策

- 底座固定为 SHA-256 `f8885ab2fe5e1c4c6604f6c93ddcb4847f4184a020742c3eb09a8a9e5382b474`。
- 任何第三方闭源 dylib 均不复制进最终包。
- Liquid Glass 是固定 UIKit 基础界面层，不占模块开关；iOS 26 使用原生 `UIGlassEffect`。
- 防撤回通过 `CMessageMgr.onRevokeMsg:` 的签名检查后默认开启；其余 15 个功能模块默认关闭且 Hook 列表为空。
- 登录、认证、凭据、Keychain、支付和核心 Session 类处于 Hook 拒绝清单。
- 推送、CallKit、iPad 与多开只通过独立适配器和签名能力校验，不修改登录校验。
- 连续两次异常启动触发 Safe Mode；稳定启动 30 秒后清零计数。

## 已审聚合/索引入口

{site_lines}

元数据未取得直链的付费或人工样本保持 `metadata-only`；未触发购买。

## SHA-256

{hash_lines}

## 结论边界

尚未执行隔离设备上的登录、推送、CallKit、iPad、7 天刷新、耗电与崩溃回归。
因此纯净砸壳包保持 `Inconclusive`，功能包保持 `Suspicious`。设备动态证据出现未解释的外联、
凭据访问、远程下载执行或数据库破坏时，应升级结论并停止该构建。
"""
    (REPORTS / "审计总报告.md").write_text(report, encoding="utf-8")


def main() -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)
    source_samples, source_data = source_index()
    rows = write_sample_table(source_samples)
    components, shared = write_component_table()
    write_conflicts()
    write_dynamic_checklist()
    write_rollback()
    write_summary(rows, components, shared, source_data)
    print(f"wrote deliverables to {REPORTS}")


if __name__ == "__main__":
    main()
