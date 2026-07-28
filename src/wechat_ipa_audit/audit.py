from __future__ import annotations

import hashlib
import plistlib
import re
import zipfile
from datetime import date, datetime
from pathlib import Path
from typing import Any, BinaryIO

from .macho import is_macho, parse_macho


_TOP_LEVEL_INFO = re.compile(r"^Payload/[^/]+\.app/Info\.plist$")


def _sha256_stream(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return _sha256_stream(stream)


def _url_schemes(info: dict[str, Any]) -> list[str]:
    schemes: set[str] = set()
    for item in info.get("CFBundleURLTypes", []):
        if not isinstance(item, dict):
            continue
        for scheme in item.get("CFBundleURLSchemes", []):
            if isinstance(scheme, str):
                schemes.add(scheme)
    return sorted(schemes)


def _usage_descriptions(info: dict[str, Any]) -> list[str]:
    return sorted(
        key
        for key, value in info.items()
        if key.startswith("NS")
        and key.endswith("UsageDescription")
        and isinstance(value, str)
    )


def _app_info_name(names: list[str]) -> str:
    candidates = sorted(name for name in names if _TOP_LEVEL_INFO.match(name))
    if len(candidates) != 1:
        raise ValueError(
            f"expected exactly one top-level app Info.plist, found {len(candidates)}"
        )
    return candidates[0]


def _json_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return value


def _mobileprovision(data: bytes) -> dict[str, Any]:
    start = data.find(b"<?xml")
    end = data.find(b"</plist>", start)
    if start < 0 or end < 0:
        raise ValueError("embedded.mobileprovision does not contain an XML plist")
    return plistlib.loads(data[start : end + len(b"</plist>")])


def audit_ipa(path: str | Path) -> dict[str, Any]:
    ipa_path = Path(path)
    with zipfile.ZipFile(ipa_path) as archive:
        names = archive.namelist()
        info_name = _app_info_name(names)
        info = plistlib.loads(archive.read(info_name))
        app_prefix = info_name[: -len("Info.plist")]
        profile_name = app_prefix + "embedded.mobileprovision"
        profile = (
            _mobileprovision(archive.read(profile_name))
            if profile_name in names
            else {}
        )
        entitlements = _json_value(profile.get("Entitlements", {}))
        executables: list[dict[str, Any]] = []

        for member in sorted(archive.infolist(), key=lambda item: item.filename):
            if member.is_dir() or not member.filename.startswith(app_prefix):
                continue
            with archive.open(member) as stream:
                header = stream.read(min(member.file_size, 8 * 1024 * 1024))
            if not is_macho(header):
                continue
            with archive.open(member) as stream:
                sha256 = _sha256_stream(stream)
            executables.append(
                {
                    "path": member.filename,
                    "size": member.file_size,
                    "sha256": sha256,
                    "mach_o": parse_macho(header),
                }
            )

    return {
        "schema_version": 1,
        "file": {
            "name": ipa_path.name,
            "size": ipa_path.stat().st_size,
            "sha256": _sha256_file(ipa_path),
        },
        "bundle": {
            "identifier": info.get("CFBundleIdentifier"),
            "version": info.get("CFBundleShortVersionString"),
            "build": str(info.get("CFBundleVersion", "")),
            "executable": info.get("CFBundleExecutable"),
            "minimum_os": info.get("MinimumOSVersion"),
            "url_schemes": _url_schemes(info),
            "usage_descriptions": _usage_descriptions(info),
            "background_modes": sorted(info.get("UIBackgroundModes", [])),
        },
        "signature": {
            "mobileprovision_present": bool(profile),
            "code_resources_present": (
                app_prefix + "_CodeSignature/CodeResources" in names
            ),
            "profile_name": profile.get("Name"),
            "team_identifiers": sorted(profile.get("TeamIdentifier", [])),
            "creation_date": _json_value(profile.get("CreationDate")),
            "expiration_date": _json_value(profile.get("ExpirationDate")),
            "entitlements": entitlements,
        },
        "executables": executables,
    }
