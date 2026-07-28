from __future__ import annotations

import hashlib
import plistlib
import re
import zipfile
from pathlib import Path
from typing import Any


_TOP_LEVEL_INFO = re.compile(r"^Payload/[^/]+\.app/Info\.plist$")
_EXPECTED_LOADER = "Frameworks/WeChatMods.dylib"
_BLOCKED_COMPONENT_NAMES = {
    "hbb9.1.2.dylib",
    "hbwechathelper.dylib",
    "miyou.dylib",
    "pkcwechattools.dylib",
    "tltdlimitation.dylib",
    "videos.dylib",
    "wcplugins.dylib",
    "wechattweak.dylib",
    "wechatku.dylib",
    "wcpureextension.dylib",
    "libsubstrate.dylib",
    "libsubstrote.dylib",
}
_BLOCKED_MEMBER_TOKENS = tuple(
    name.removesuffix(".dylib")
    for name in _BLOCKED_COMPONENT_NAMES
)
_FORBIDDEN_MARKERS = (
    "https://wx.plus",
    "证书即将到期",
    "请及时续费避免聊天记录丢失",
    "证书过期时间",
    "您当前证书还有",
    "expireDate",
)


def _top_level_app(
    archive: zipfile.ZipFile,
) -> tuple[str, str, dict[str, Any]]:
    matches = sorted(
        name for name in archive.namelist() if _TOP_LEVEL_INFO.match(name)
    )
    if len(matches) != 1:
        raise ValueError("package must contain one top-level app Info.plist")
    info_path = matches[0]
    app_prefix = info_path[: -len("Info.plist")]
    info = plistlib.loads(archive.read(info_path))
    executable = info.get("CFBundleExecutable")
    if not isinstance(executable, str) or not executable:
        raise ValueError("top-level Info.plist has no CFBundleExecutable")
    return app_prefix, executable, info


def _is_executable_component(relative: str) -> bool:
    if not relative or relative.endswith("/"):
        return False
    if relative.lower().endswith(".dylib"):
        return True
    parts = relative.split("/")
    if len(parts) < 2:
        return False
    framework = parts[-2]
    return (
        framework.lower().endswith(".framework")
        and parts[-1] == framework[: -len(".framework")]
    )


def _components(
    archive: zipfile.ZipFile,
    app_prefix: str,
    main_executable: str,
) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in archive.namelist():
        if not name.startswith(app_prefix):
            continue
        relative = name[len(app_prefix) :]
        if (
            relative == main_executable
            or relative.startswith(("PlugIns/", "Watch/"))
            or not _is_executable_component(relative)
        ):
            continue
        result[relative] = name
    return result


def _sha256(archive: zipfile.ZipFile, name: str) -> str:
    digest = hashlib.sha256()
    with archive.open(name) as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _marker_hits(
    archive: zipfile.ZipFile,
    paths: dict[str, str],
) -> list[dict[str, str]]:
    encoded = {
        marker: marker.encode("utf-8")
        for marker in _FORBIDDEN_MARKERS
    }
    hits: list[dict[str, str]] = []
    for relative, member in sorted(paths.items()):
        data = archive.read(member)
        for marker, needle in encoded.items():
            if needle in data:
                hits.append({"path": relative, "marker": marker})
    return hits


def inspect_candidate_policy(
    baseline_ipa: str | Path,
    candidate_ipa: str | Path,
) -> dict[str, Any]:
    baseline_path = Path(baseline_ipa).resolve()
    candidate_path = Path(candidate_ipa).resolve()
    with (
        zipfile.ZipFile(baseline_path) as baseline,
        zipfile.ZipFile(candidate_path) as candidate,
    ):
        baseline_prefix, baseline_main, _ = _top_level_app(baseline)
        candidate_prefix, candidate_main, _ = _top_level_app(candidate)
        baseline_components = _components(
            baseline,
            baseline_prefix,
            baseline_main,
        )
        candidate_components = _components(
            candidate,
            candidate_prefix,
            candidate_main,
        )
        added = sorted(
            set(candidate_components) - set(baseline_components)
        )
        removed = sorted(
            set(baseline_components) - set(candidate_components)
        )
        modified = sorted(
            relative
            for relative in (
                set(candidate_components) & set(baseline_components)
            )
            if _sha256(
                candidate,
                candidate_components[relative],
            )
            != _sha256(
                baseline,
                baseline_components[relative],
            )
        )
        unexpected = sorted(
            relative
            for relative in added
            if relative != _EXPECTED_LOADER
        )
        blocked_names = sorted(
            {
                Path(relative).name
                for relative in candidate_components
                if Path(relative).name.lower() in _BLOCKED_COMPONENT_NAMES
            },
            key=str.lower,
        )
        blocked_members = sorted(
            {
                name[len(candidate_prefix) :]
                for name in candidate.namelist()
                if name.startswith(candidate_prefix)
                and any(
                    token in name[len(candidate_prefix) :].lower()
                    for token in _BLOCKED_MEMBER_TOKENS
                )
            },
            key=str.lower,
        )
        changed_paths = {
            relative: candidate_components[relative]
            for relative in added + modified
        }
        marker_hits = _marker_hits(candidate, changed_paths)

    loader_present = _EXPECTED_LOADER in candidate_components
    valid = not (
        unexpected
        or removed
        or modified
        or blocked_names
        or blocked_members
        or marker_hits
        or not loader_present
    )
    return {
        "schema_version": 1,
        "baseline_ipa": str(baseline_path),
        "candidate_ipa": str(candidate_path),
        "valid": valid,
        "expected_loader": _EXPECTED_LOADER,
        "loader_present": loader_present,
        "added_executable_components": added,
        "removed_executable_components": removed,
        "modified_executable_components": modified,
        "unexpected_executable_components": unexpected,
        "blocked_component_names": blocked_names,
        "blocked_archive_members": blocked_members,
        "forbidden_marker_hits": marker_hits,
    }
