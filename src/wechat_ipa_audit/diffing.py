from __future__ import annotations

from typing import Any


def diff_reports(
    baseline: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, list[str]]:
    before = {item["path"]: item["sha256"] for item in baseline["executables"]}
    after = {item["path"]: item["sha256"] for item in candidate["executables"]}
    before_paths = set(before)
    after_paths = set(after)
    return {
        "added": sorted(after_paths - before_paths),
        "removed": sorted(before_paths - after_paths),
        "modified": sorted(
            path
            for path in before_paths & after_paths
            if before[path] != after[path]
        ),
        "unchanged": sorted(
            path
            for path in before_paths & after_paths
            if before[path] == after[path]
        ),
    }

