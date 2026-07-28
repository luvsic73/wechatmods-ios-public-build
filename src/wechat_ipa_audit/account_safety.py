from __future__ import annotations

import hashlib
import plistlib
import re
import zipfile
from pathlib import Path
from typing import Any


_TOP_LEVEL_INFO = re.compile(r"^Payload/[^/]+\.app/Info\.plist$")
_FORBIDDEN_MARKERS = {
    b"ManualAuthAesReqData": "auth_request",
    b"setBundleId:": "auth_identity",
    b"setClientSeqId:": "auth_identity",
    b"setDeviceName:": "device_identity",
    b"JailBreakHelper": "environment_signal",
    b"_my_ptrace": "debugger_signal",
    b"_orig_ptrace": "debugger_signal",
    b"advertisingIdentifier_super": "device_identity",
}
_BLOCKING_SEVERITIES = {"critical"}


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
    return app_prefix, app_prefix + executable, info


def _member_sha256(archive: zipfile.ZipFile, name: str) -> str:
    digest = hashlib.sha256()
    with archive.open(name) as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _is_executable_component(name: str, app_prefix: str) -> bool:
    if not name.startswith(app_prefix) or name.endswith("/"):
        return False
    relative = name[len(app_prefix) :]
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


def _scan_member_markers(
    archive: zipfile.ZipFile,
    name: str,
) -> list[dict[str, str]]:
    remaining = set(_FORBIDDEN_MARKERS)
    hits: list[dict[str, str]] = []
    overlap_size = max(map(len, remaining)) - 1
    overlap = b""
    with archive.open(name) as stream:
        while remaining and (chunk := stream.read(1024 * 1024)):
            window = overlap + chunk
            found = [marker for marker in remaining if marker in window]
            for marker in sorted(found):
                hits.append(
                    {
                        "path": name,
                        "marker": marker.decode("ascii"),
                        "category": _FORBIDDEN_MARKERS[marker],
                    }
                )
                remaining.remove(marker)
            overlap = window[-overlap_size:]
    return hits


def assess_account_safety(
    baseline_ipa: str | Path,
    candidate_ipa: str | Path,
    *,
    expected_bundle_id: str | None = None,
    trusted_loader: str | Path | None = None,
) -> dict[str, Any]:
    baseline_path = Path(baseline_ipa).resolve()
    candidate_path = Path(candidate_ipa).resolve()
    trusted_loader_path = (
        Path(trusted_loader).resolve()
        if trusted_loader is not None
        else None
    )
    trusted_loader_sha256 = (
        _file_sha256(trusted_loader_path)
        if trusted_loader_path is not None
        else None
    )
    trusted_loader_name = (
        trusted_loader_path.name
        if trusted_loader_path is not None
        else None
    )
    trusted_loader_matched = False
    defensive_loader_hits: list[dict[str, str]] = []
    findings: list[dict[str, Any]] = []

    with (
        zipfile.ZipFile(baseline_path) as baseline,
        zipfile.ZipFile(candidate_path) as candidate,
    ):
        baseline_prefix, baseline_main, baseline_info = _top_level_app(
            baseline
        )
        candidate_prefix, candidate_main, candidate_info = _top_level_app(
            candidate
        )
        baseline_bundle_id = baseline_info.get("CFBundleIdentifier")
        candidate_bundle_id = candidate_info.get("CFBundleIdentifier")
        identity_consistent = (
            isinstance(baseline_bundle_id, str)
            and baseline_bundle_id == candidate_bundle_id
        )
        if not identity_consistent and expected_bundle_id is None:
            findings.append(
                {
                    "code": "bundle_identity_changed",
                    "severity": "critical",
                    "baseline": baseline_bundle_id,
                    "candidate": candidate_bundle_id,
                    "reason": (
                        "The account-facing application identity differs "
                        "from the baseline."
                    ),
                }
            )
        elif not identity_consistent and candidate_bundle_id != expected_bundle_id:
            findings.append(
                {
                    "code": "bundle_identity_unexpected",
                    "severity": "critical",
                    "baseline": baseline_bundle_id,
                    "expected": expected_bundle_id,
                    "candidate": candidate_bundle_id,
                    "reason": (
                        "The candidate identity does not match the declared "
                        "coexist application identity."
                    ),
                }
            )
        elif not identity_consistent:
            findings.append(
                {
                    "code": "declared_coexist_identity_change",
                    "severity": "high",
                    "baseline": baseline_bundle_id,
                    "candidate": candidate_bundle_id,
                    "reason": (
                        "The candidate uses the exact application identity "
                        "declared by the coexist build."
                    ),
                }
            )

        baseline_names = set(baseline.namelist())
        candidate_components = {
            name
            for name in candidate.namelist()
            if _is_executable_component(name, candidate_prefix)
            and name != candidate_main
        }
        baseline_components = {
            name
            for name in baseline.namelist()
            if _is_executable_component(name, baseline_prefix)
            and name != baseline_main
        }
        added_components = sorted(
            candidate_components - baseline_components
        )
        modified_components = sorted(
            name
            for name in candidate_components.intersection(
                baseline_components
            )
            if _member_sha256(candidate, name)
            != _member_sha256(baseline, name)
        )
        changed_components = added_components + modified_components

        if added_components:
            findings.append(
                {
                    "code": "injected_executable_components",
                    "severity": "high",
                    "paths": added_components,
                    "reason": (
                        "The candidate adds executable code that is absent "
                        "from the baseline."
                    ),
                }
            )

        forbidden_hits: list[dict[str, str]] = []
        for name in changed_components:
            hits = _scan_member_markers(candidate, name)
            is_trusted_loader = (
                trusted_loader_name is not None
                and Path(name).name == trusted_loader_name
                and _member_sha256(candidate, name)
                == trusted_loader_sha256
            )
            if is_trusted_loader:
                trusted_loader_matched = True
                defensive_loader_hits.extend(hits)
            else:
                forbidden_hits.extend(hits)
        if defensive_loader_hits:
            findings.append(
                {
                    "code": "verified_loader_defensive_markers",
                    "severity": "info",
                    "hits": defensive_loader_hits,
                    "reason": (
                        "The markers belong to the exact hash-matched "
                        "loader already accepted by the provenance gate."
                    ),
                }
            )
        if forbidden_hits:
            findings.append(
                {
                    "code": "auth_or_environment_tampering",
                    "severity": "critical",
                    "hits": forbidden_hits,
                    "reason": (
                        "Added or modified code references authentication, "
                        "device identity, jailbreak, or debugger signals."
                    ),
                }
            )

        main_binary_modified = (
            baseline_main not in baseline_names
            or candidate_main not in candidate.namelist()
            or _member_sha256(baseline, baseline_main)
            != _member_sha256(candidate, candidate_main)
        )
        if main_binary_modified:
            findings.append(
                {
                    "code": "main_binary_modified",
                    "severity": "high",
                    "reason": (
                        "The candidate main executable differs from the "
                        "baseline, including loader-command changes."
                    ),
                }
            )

    release_blocked = any(
        finding["severity"] in _BLOCKING_SEVERITIES
        for finding in findings
    )
    if release_blocked:
        verdict = "blocked"
    elif findings:
        verdict = "elevated"
    else:
        verdict = "minimal_delta"
    return {
        "schema_version": 1,
        "baseline_ipa": str(baseline_path),
        "candidate_ipa": str(candidate_path),
        "baseline_bundle_id": baseline_bundle_id,
        "candidate_bundle_id": candidate_bundle_id,
        "expected_bundle_id": expected_bundle_id,
        "trusted_loader": (
            str(trusted_loader_path)
            if trusted_loader_path is not None
            else None
        ),
        "trusted_loader_sha256": trusted_loader_sha256,
        "trusted_loader_matched": trusted_loader_matched,
        "identity_consistent": identity_consistent,
        "main_binary_modified": main_binary_modified,
        "added_executable_components": added_components,
        "modified_executable_components": modified_components,
        "forbidden_marker_hits": forbidden_hits,
        "defensive_loader_marker_hits": defensive_loader_hits,
        "findings": findings,
        "verdict": verdict,
        "release_blocked": release_blocked,
        "limits": [
            "Static inspection does not predict server-side enforcement.",
            "Signing identity and runtime network behavior require separate evidence.",
        ],
    }
