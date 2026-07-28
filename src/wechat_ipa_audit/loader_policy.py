from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .macho import is_macho, parse_macho


_REQUIRED_MARKERS = (
    "WMLoginLayoutAdapter",
    "UIBackgroundExtensionView",
    "WMLiquidGlassStyle",
    "WMSettingsEntry",
    "WMAntiRevokeModule",
    "setInteractive:",
)
_FORBIDDEN_MARKERS = (
    "https://wx.plus",
    "expireDate",
)


def inspect_loader_policy(path: str | Path) -> dict[str, Any]:
    loader_path = Path(path).resolve()
    data = loader_path.read_bytes()
    macho = parse_macho(data) if is_macho(data) else None
    missing = sorted(
        marker
        for marker in _REQUIRED_MARKERS
        if marker.encode("utf-8") not in data
    )
    forbidden = sorted(
        marker
        for marker in _FORBIDDEN_MARKERS
        if marker.encode("utf-8") in data
    )
    architecture_ready = (
        macho is not None
        and "arm64" in macho["architectures"]
        and macho["file_type"] == "dylib"
    )
    valid = architecture_ready and not missing and not forbidden
    return {
        "schema_version": 1,
        "loader": str(loader_path),
        "sha256": hashlib.sha256(data).hexdigest().upper(),
        "size": len(data),
        "valid": valid,
        "architecture_ready": architecture_ready,
        "mach_o": macho,
        "required_markers": list(_REQUIRED_MARKERS),
        "missing_required_markers": missing,
        "forbidden_marker_hits": forbidden,
    }
