from __future__ import annotations

import hashlib
import ipaddress
import re
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
_URL = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
_SECRET = re.compile(
    r"(?i)(?:bearer\s+|api[_-]?key\s*[:=]\s*|token\s*[:=]\s*)"
    r"[A-Za-z0-9._~+/=-]{16,}"
)

_MARKERS = {
    "anti_debug": (b"ptrace", b"PT_DENY_ATTACH", b"sysctl"),
    "clipboard": (b"UIPasteboard", b"generalPasteboard"),
    "contacts": (b"CNContactStore", b"ABAddressBook"),
    "credential_store": (
        b"SecItemCopyMatching",
        b"SecItemAdd",
        b"kSecClassGenericPassword",
    ),
    "dynamic_loading": (b"dlopen", b"dlsym", b"NSClassFromString"),
    "photos": (b"PHPhotoLibrary", b"UIImagePickerController"),
    "remote_configuration": (
        b"remoteConfig",
        b"remote_config",
        b"configURL",
        b"updateURL",
    ),
}


def _valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return "." in host and all(
        re.fullmatch(r"[A-Za-z0-9-]{1,63}", label)
        and not label.startswith("-")
        and not label.endswith("-")
        for label in host.split(".")
    )


def scan_binary(data: bytes) -> dict[str, Any]:
    strings = [match.group().decode("utf-8", errors="ignore") for match in _PRINTABLE.finditer(data)]
    joined = "\n".join(strings)
    domains: set[str] = set()
    for url in _URL.findall(joined):
        try:
            host = urlsplit(url).hostname
        except ValueError:
            continue
        if host and _valid_host(host):
            domains.add(host.lower().rstrip("."))

    markers = {
        name
        for name, needles in _MARKERS.items()
        if any(needle in data for needle in needles)
    }
    secret_matches = _SECRET.findall(joined)
    if secret_matches:
        markers.add("hardcoded_secret")

    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "printable_string_count": len(strings),
        "domains": sorted(domains),
        "risk_markers": sorted(markers),
        "hardcoded_secret_count": len(secret_matches),
    }


def scan_ipa_members(
    ipa_path: str | Path,
    members: list[str],
    *,
    extract_directory: str | Path | None = None,
) -> list[dict[str, Any]]:
    requested = sorted(set(members))
    output_directory = Path(extract_directory) if extract_directory else None
    if output_directory:
        output_directory.mkdir(parents=True, exist_ok=True)

    reports: list[dict[str, Any]] = []
    with zipfile.ZipFile(ipa_path) as archive:
        available = set(archive.namelist())
        missing = sorted(set(requested) - available)
        if missing:
            raise ValueError(f"archive members not found: {missing}")
        for member in requested:
            data = archive.read(member)
            report = {"path": member, "size": len(data), **scan_binary(data)}
            if output_directory:
                destination = (
                    output_directory
                    / f"{report['sha256'][:12]}-{Path(member).name}"
                ).resolve()
                if output_directory.resolve() not in destination.parents:
                    raise ValueError("component extraction left output directory")
                destination.write_bytes(data)
                report["extracted_to"] = str(destination)
            reports.append(report)
    return reports
