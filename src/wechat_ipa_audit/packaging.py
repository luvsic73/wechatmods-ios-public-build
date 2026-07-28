from __future__ import annotations

import json
import plistlib
import re
import shutil
import zipfile
from pathlib import Path
from typing import Any


_TOP_LEVEL_INFO = re.compile(r"^Payload/[^/]+\.app/Info\.plist$")
_MMROUTER_JSC = b"@rpath/JavaScriptCore.framework/JavaScriptCore"
_JSC_OLD_RPATH = b"@executable_path/PlugIns/WeChatScreenCapture.appex"
_JSC_NEW_RPATH = b"@executable_path/Frameworks"


def _manifest_path(archive: zipfile.ZipFile) -> str:
    infos = sorted(name for name in archive.namelist() if _TOP_LEVEL_INFO.match(name))
    if len(infos) != 1:
        raise ValueError("package must contain one top-level app Info.plist")
    return infos[0][: -len("Info.plist")] + "WeChatMods/module-manifest.json"


def package_all_disabled(
    base_ipa: str | Path,
    output_ipa: str | Path,
    modules: list[dict[str, Any]],
    *,
    feature_collection: dict[str, Any] | None = None,
) -> None:
    base_path = Path(base_ipa)
    output_path = Path(output_ipa)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(base_path) as source:
        manifest_path = _manifest_path(source)
        manifest = {
            "schema_version": 2,
            "activation": "restart-required",
            "safe_mode_crash_threshold": 2,
            "feature_collection": feature_collection
            or {
                "included": False,
                "activation_gate": "not-configured",
            },
            "modules": [
                {
                    **{key: value for key, value in module.items() if key != "enabled"},
                    "enabled": False,
                }
                for module in modules
            ],
        }
        with zipfile.ZipFile(
            output_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
        ) as target:
            for member in source.infolist():
                if member.filename == manifest_path:
                    continue
                with source.open(member) as input_stream:
                    with target.open(member, "w") as output_stream:
                        shutil.copyfileobj(
                            input_stream,
                            output_stream,
                            length=1024 * 1024,
                        )
            target.writestr(
                manifest_path,
                json.dumps(
                    manifest,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                ).encode("utf-8"),
            )


def verify_package(path: str | Path) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        manifest_path = _manifest_path(archive)
        manifest = json.loads(archive.read(manifest_path))
        app_prefix = manifest_path.split("WeChatMods/", 1)[0]
        info_path = app_prefix + "Info.plist"
        loader_path = app_prefix + "Frameworks/WeChatMods.dylib"
        plistlib.loads(archive.read(info_path))
        loader_present = loader_path in archive.namelist()
        loader_executable = loader_present and bool(
            (archive.getinfo(loader_path).external_attr >> 16) & 0o111
        )
        names = set(archive.namelist())
        router_path = app_prefix + "Frameworks/MMRouter.framework/MMRouter"
        runtime_dependency_errors: list[str] = []
        if (
            router_path in names
            and _MMROUTER_JSC in archive.read(router_path)
        ):
            jsc_path = (
                app_prefix
                + "Frameworks/JavaScriptCore.framework/JavaScriptCore"
            )
            mir_path = app_prefix + "Frameworks/MIRMetal.framework/MIRMetal"
            if jsc_path not in names:
                runtime_dependency_errors.append(
                    "Frameworks/JavaScriptCore.framework/JavaScriptCore"
                )
            else:
                jsc = archive.read(jsc_path)
                if (
                    _JSC_OLD_RPATH in jsc
                    or _JSC_NEW_RPATH not in jsc
                ):
                    runtime_dependency_errors.append(
                        "JavaScriptCore runtime rpath"
                    )
            if mir_path not in names:
                runtime_dependency_errors.append(
                    "Frameworks/MIRMetal.framework/MIRMetal"
                )
        runtime_dependencies_resolved = not runtime_dependency_errors
    modules = manifest.get("modules", [])
    enabled = sorted(
        module["id"] for module in modules if module.get("enabled") is True
    )
    unexpected_enabled = sorted(
        module["id"]
        for module in modules
        if module.get("enabled") is True
        and module.get("default_enabled") is not True
    )
    return {
        "valid": (
            not unexpected_enabled
            and loader_present
            and loader_executable
            and runtime_dependencies_resolved
        ),
        "manifest_path": manifest_path,
        "module_count": len(modules),
        "enabled_modules": enabled,
        "unexpected_enabled_modules": unexpected_enabled,
        "loader_present": loader_present,
        "loader_executable": loader_executable,
        "runtime_dependencies_resolved": runtime_dependencies_resolved,
        "runtime_dependency_errors": runtime_dependency_errors,
    }
