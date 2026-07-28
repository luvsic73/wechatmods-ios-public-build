from __future__ import annotations

import copy
import plistlib
import re
import shutil
import zipfile
from pathlib import Path
from typing import Any


OFFICIAL_BUNDLE_PREFIX = "com.tencent.xin"
OFFICIAL_URL_SCHEMES = {
    "QQ41C152CF",
    "fb290293790992170",
    "mp",
    "prefs",
    "wechat",
    "weixin",
    "weixinQRCodePayAPI",
    "weixinStateAPI",
    "weixinULAPI",
    "weixinURLParamsAPI",
    "weixinVideoLocalIdAPI",
    "weixinVideoStateAPI",
    "weixinapp",
    "wexinVideoAPI",
    "wx7015",
    "wx703",
}
_BUNDLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]+$")
_BUNDLE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_TOP_LEVEL_INFO = re.compile(r"^Payload/[^/]+\.app/Info\.plist$")
_MMROUTER_JSC = b"@rpath/JavaScriptCore.framework/JavaScriptCore"
_JSC_OLD_RPATH = b"@executable_path/PlugIns/WeChatScreenCapture.appex"
_JSC_NEW_RPATH = b"@executable_path/Frameworks"


def _top_level_info(archive: zipfile.ZipFile) -> str:
    matches = sorted(
        name for name in archive.namelist() if _TOP_LEVEL_INFO.match(name)
    )
    if len(matches) != 1:
        raise ValueError("package must contain one top-level app Info.plist")
    return matches[0]


def _replace_identity(value: Any, old_bundle_id: str, new_bundle_id: str) -> Any:
    if isinstance(value, str):
        return value.replace(old_bundle_id, new_bundle_id)
    if isinstance(value, list):
        return [
            _replace_identity(item, old_bundle_id, new_bundle_id)
            for item in value
        ]
    if isinstance(value, dict):
        return {
            key: _replace_identity(item, old_bundle_id, new_bundle_id)
            for key, item in value.items()
        }
    return value


def _rewrite_info(
    data: bytes,
    *,
    old_bundle_id: str,
    new_bundle_id: str,
    bundle_name: str,
    display_name: str,
    scheme_prefix: str,
) -> bytes:
    info = _replace_identity(
        plistlib.loads(data),
        old_bundle_id,
        new_bundle_id,
    )
    info["CFBundleIdentifier"] = new_bundle_id
    info["CFBundleName"] = bundle_name
    info["CFBundleDisplayName"] = display_name
    info.pop("UIDesignRequiresCompatibility", None)
    for item in info.get("CFBundleURLTypes", []):
        schemes = item.get("CFBundleURLSchemes")
        if isinstance(schemes, list):
            item["CFBundleURLSchemes"] = [
                f"{scheme_prefix}-{scheme}" for scheme in schemes
            ]
    return plistlib.dumps(info, fmt=plistlib.FMT_BINARY, sort_keys=False)


def _runtime_framework_relocations(
    source: zipfile.ZipFile,
    app_prefix: str,
    *,
    strip_extensions: bool,
) -> dict[str, str]:
    if not strip_extensions:
        return {}

    names = set(source.namelist())
    router = app_prefix + "Frameworks/MMRouter.framework/MMRouter"
    if router not in names or _MMROUTER_JSC not in source.read(router):
        return {}

    root = app_prefix + "Frameworks/"
    jsc_source = app_prefix + "detector.bundle/JavaScriptCore.framework/"
    jsc_target = root + "JavaScriptCore.framework/"
    mir_source = (
        app_prefix
        + "PlugIns/WeChatScreenCapture.appex/MIRMetal.framework/"
    )
    mir_target = root + "MIRMetal.framework/"
    relocations: dict[str, str] = {}

    if jsc_target + "JavaScriptCore" not in names:
        if jsc_source + "JavaScriptCore" not in names:
            raise ValueError(
                "JavaScriptCore runtime framework is missing from the IPA"
            )
        relocations[jsc_source] = jsc_target
    if mir_target + "MIRMetal" not in names:
        if mir_source + "MIRMetal" not in names:
            raise ValueError(
                "MIRMetal runtime framework is missing from the stripped extension"
            )
        relocations[mir_source] = mir_target
    return relocations


def _patch_relocated_jsc(data: bytes) -> bytes:
    old = _JSC_OLD_RPATH + b"\0"
    if data.count(old) != 1:
        raise ValueError("JavaScriptCore runtime rpath does not match")
    replacement = (
        _JSC_NEW_RPATH
        + b"\0"
        + b"\0" * (len(_JSC_OLD_RPATH) - len(_JSC_NEW_RPATH))
    )
    return data.replace(old, replacement, 1)


def make_coexist_ipa(
    input_ipa: str | Path,
    output_ipa: str | Path,
    *,
    bundle_id: str,
    bundle_name: str = "WeChatGlass",
    display_name: str,
    scheme_prefix: str,
    strip_extensions: bool,
) -> None:
    if not _BUNDLE_ID.fullmatch(bundle_id):
        raise ValueError(f"invalid bundle identifier: {bundle_id}")
    if bundle_id == OFFICIAL_BUNDLE_PREFIX or bundle_id.startswith(
        OFFICIAL_BUNDLE_PREFIX + "."
    ):
        raise ValueError("coexist bundle identifier must use another prefix")
    if not _BUNDLE_NAME.fullmatch(bundle_name):
        raise ValueError(f"invalid ASCII bundle name: {bundle_name}")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9.-]*", scheme_prefix):
        raise ValueError(f"invalid URL scheme prefix: {scheme_prefix}")

    source_path = Path(input_ipa).resolve()
    output_path = Path(output_ipa).resolve()
    if source_path == output_path:
        raise ValueError("input and output IPA paths must differ")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(source_path) as source:
        info_path = _top_level_info(source)
        app_prefix = info_path[: -len("Info.plist")]
        original_info = plistlib.loads(source.read(info_path))
        original_bundle_id = original_info.get("CFBundleIdentifier")
        if not isinstance(original_bundle_id, str) or not original_bundle_id:
            raise ValueError("top-level Info.plist has no CFBundleIdentifier")

        plugin_prefix = app_prefix + "PlugIns/"
        watch_prefix = app_prefix + "Watch/"
        relocations = _runtime_framework_relocations(
            source,
            app_prefix,
            strip_extensions=strip_extensions,
        )
        with zipfile.ZipFile(
            output_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=6,
        ) as target:
            for member in source.infolist():
                name = member.filename
                if "/_CodeSignature/" in name or name.endswith(
                    "/embedded.mobileprovision"
                ):
                    continue
                relocation = next(
                    (
                        (source_prefix, target_prefix)
                        for source_prefix, target_prefix in relocations.items()
                        if name.startswith(source_prefix)
                    ),
                    None,
                )
                if relocation is not None:
                    source_prefix, target_prefix = relocation
                    relocated = copy.copy(member)
                    relocated.filename = target_prefix + name[len(source_prefix) :]
                    data = source.read(member)
                    if name == source_prefix + "JavaScriptCore":
                        data = _patch_relocated_jsc(data)
                    target.writestr(relocated, data)
                    continue
                if strip_extensions and (
                    name.startswith(plugin_prefix)
                    or name.startswith(watch_prefix)
                ):
                    continue
                if name == info_path:
                    target.writestr(
                        member,
                        _rewrite_info(
                            source.read(member),
                            old_bundle_id=original_bundle_id,
                            new_bundle_id=bundle_id,
                            bundle_name=bundle_name,
                            display_name=display_name,
                            scheme_prefix=scheme_prefix,
                        ),
                    )
                    continue
                with source.open(member) as input_stream:
                    with target.open(member, "w") as output_stream:
                        shutil.copyfileobj(
                            input_stream,
                            output_stream,
                            length=1024 * 1024,
                        )


def inspect_coexist(path: str | Path) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        info_path = _top_level_info(archive)
        app_prefix = info_path[: -len("Info.plist")]
        info = plistlib.loads(archive.read(info_path))
        bundle_id = info.get("CFBundleIdentifier")
        bundle_name = info.get("CFBundleName")
        design_requires_compatibility = (
            info.get("UIDesignRequiresCompatibility") is True
        )
        schemes = sorted(
            {
                scheme
                for item in info.get("CFBundleURLTypes", [])
                for scheme in item.get("CFBundleURLSchemes", [])
                if isinstance(scheme, str)
            }
        )
        extensions = sorted(
            name
            for name in archive.namelist()
            if name.startswith(app_prefix + "PlugIns/")
            or name.startswith(app_prefix + "Watch/")
        )
        signing_residue = sorted(
            name
            for name in archive.namelist()
            if "/_CodeSignature/" in name
            or name.endswith("/embedded.mobileprovision")
        )
    bundle_collision = (
        not isinstance(bundle_id, str)
        or bundle_id == OFFICIAL_BUNDLE_PREFIX
        or bundle_id.startswith(OFFICIAL_BUNDLE_PREFIX + ".")
    )
    developer_app_id_name_ready = (
        isinstance(bundle_name, str)
        and _BUNDLE_NAME.fullmatch(bundle_name) is not None
    )
    scheme_collisions = sorted(OFFICIAL_URL_SCHEMES.intersection(schemes))
    return {
        "coexist_ready": (
            not bundle_collision
            and developer_app_id_name_ready
            and not scheme_collisions
            and not extensions
            and not signing_residue
            and not design_requires_compatibility
        ),
        "native_liquid_glass_ready": not design_requires_compatibility,
        "design_requires_compatibility": design_requires_compatibility,
        "bundle_id": bundle_id,
        "bundle_name": bundle_name,
        "developer_app_id_name_ready": developer_app_id_name_ready,
        "bundle_collision": bundle_collision,
        "registered_url_schemes": schemes,
        "official_url_scheme_collisions": scheme_collisions,
        "extensions": extensions,
        "signing_residue": signing_residue,
    }
