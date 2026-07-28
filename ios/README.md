# WeChatMods loader

The loader reads `WeChatMods/module-manifest.json`, validates version and the
hook denylist, and enables only anti-revoke by default.
Two consecutive launches that do not reach the 30-second stable mark enable
Safe Mode and record the last enabled module IDs.

Liquid Glass is a fixed UIKit shell rather than a module. On iOS 26 it creates
the native `UIGlassEffect` at runtime and applies it to navigation bars, tab
bars, toolbars, and the top and bottom window safe-area chrome. Dynamic bar
hooks apply the shell to controls created after launch. Earlier systems retain
the same layout with the system material fallback.

`WMSettingsEntry` inserts a guarded native row into
`NewSettingViewController`. The row opens an inset-grouped UIKit settings
screen; feature overrides are stored in `wechatmods.module-overrides` and take
effect after restart.

The denylist covers login, authentication, credential, Keychain, payment, and
core session hook names. Push, CallKit, iPad session, and multi-instance work
remain separate adapters guarded by signing-capability health checks.

The only default-enabled feature is anti-revoke. It verifies the Objective-C
class, selector, argument count, and void return type before replacing
`-[CMessageMgr onRevokeMsg:]`. A failed check leaves the method unchanged, and
Safe Mode skips module installation after two abnormal launches.
