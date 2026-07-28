from __future__ import annotations

import re
from typing import Any


def _version_tuple(value: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", value)
    return tuple(int(number) for number in numbers)


def select_current_targets(
    entries: list[dict[str, Any]], *, stable_version: str
) -> dict[str, list[dict[str, Any]]]:
    stable = _version_tuple(stable_version)
    deep_audit: list[dict[str, Any]] = []
    quarantine: list[dict[str, Any]] = []
    regression: list[dict[str, Any]] = []
    for entry in entries:
        version = _version_tuple(str(entry.get("version", "")))
        if version == stable:
            deep_audit.append(entry)
        elif version > stable:
            quarantine.append(entry)
        elif stable and version and version[0] == stable[0]:
            regression.append(entry)
    return {
        "deep_audit": deep_audit,
        "quarantine": quarantine,
        "regression": regression,
    }

