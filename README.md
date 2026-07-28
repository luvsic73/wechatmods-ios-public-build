# WeChat IPA Audit

微信 iOS 8.0.75 样本清点、静态审计、唯一组件差分和模块化加载器工程。

## 已实现

- 逐包记录 SHA-256、Bundle、版本/build、签名配置、Entitlements、URL Scheme。
- 解析所有 Mach-O load commands、加密信息与代码签名命令。
- 相对纯净砸壳基线只提取新增可执行组件，检查域名、动态加载、反调试和敏感 API。
- YARA 与 ClamAV 本地扫描；样本及闭源第三方 dylib 不提交到仓库。
- Liquid Glass 是固定基础界面层，不占模块开关；iOS 26 使用原生
  `UIGlassEffect`，覆盖动态系统栏和窗口上下安全区；较早系统回退到
  `systemMaterial`。
- 16 个 `ModuleDescriptor` 中仅防撤回默认开启；其余功能默认关闭。
- 防撤回仅检查并替换 `CMessageMgr.onRevokeMsg:`，签名不符时保持未安装状态。
- “我 → 设置 → 微信 Glass”提供原生功能入口，防撤回开关重启生效。
- 共存构建使用独立 Bundle ID、独立 URL Scheme 和独立数据容器，并移除扩展签名面。
- 连续两次异常启动进入 Safe Mode。
- 登录、凭据、Keychain、支付和核心会话类在 Hook 拒绝清单中。
- macOS GitHub Actions 构建 arm64 iOS `WeChatMods.dylib`。
- LIEF 向预签名 IPA 写入加载命令；最终由 iLoader 重签和安装。

## 本地验证

```powershell
$env:PYTHONPATH = "src"
py -3 -m unittest discover -s tests -v
py -3 -m wechat_ipa_audit.cli audit SAMPLE.ipa --output reports\SAMPLE.json
py -3 -m wechat_ipa_audit.cli diff reports\BASE.json reports\SAMPLE.json --output reports\DIFF.json
py -3 -m wechat_ipa_audit.cli package BASE.ipa staged.ipa --modules data\modules.json
py -3 -m wechat_ipa_audit.cli inject staged.ipa dist\WeChatMods.dylib wechatmods-iloader.ipa
py -3 -m wechat_ipa_audit.cli verify wechatmods-iloader.ipa

# 等价的一键构建：写入默认模块清单、注入加载器并验证
.\scripts\build-iloader.ps1 -BaseIpa BASE.ipa -OutputIpa wechatmods-iloader.ipa

# 与官方客户端共存的基础多开包
.\scripts\build-coexist.ps1 `
  -BaseIpa BASE.ipa `
  -OutputIpa wechatmods-coexist-iloader.ipa `
  -Report reports\coexist-readiness.json
```

## 构建边界

`wechatmods-iloader.ipa` 是签名前产物。修改 Mach-O 后原签名不再有效，安装前必须由
iLoader v2.2.7 用设备实际可用证书重签。`guanti/qy/wx/mm` 仅应在证书实际具备相应
Bundle ID、App Groups、Keychain Groups 与推送能力时生成。

静态规则命中表示需要复核，不等同于恶意软件结论。动态登录、推送、CallKit、
iPad 登录、7 天刷新和资源回归必须在隔离设备与测试号上补齐。

共存基础包移除了 PlugIns 和 Watch，以减少个人签名所需 App ID 数量与安装冲突。
因此通知服务扩展、系统分享、Siri、Widget、录屏扩展和 Watch 不在该包内。

## 数据隔离

`.gitignore` 排除 `samples/`、`components/`、`reports/`、`tools/`、`dist/` 和
所有 IPA。仓库仅保存分析器、规则、模块源码、测试和可复现构建工作流。
