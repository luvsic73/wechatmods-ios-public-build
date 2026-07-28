from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _source_hashes(source_paths: Iterable[str | Path]) -> dict[str, str]:
    sources = [Path(path).resolve() for path in source_paths]
    names = [path.name for path in sources]
    if len(names) != len(set(names)):
        raise ValueError("loader provenance source names must be unique")
    return {
        path.name: _sha256(path) for path in sorted(sources, key=lambda item: item.name)
    }


def project_loader_sources(project_root: str | Path) -> list[Path]:
    root = Path(project_root).resolve()
    sources = sorted((root / "ios" / "WeChatMods").glob("*.[mh]"))
    sources.extend(
        [
            root / "vendor" / "fishhook" / "fishhook.c",
            root / "vendor" / "fishhook" / "fishhook.h",
            root / "vendor" / "fishhook" / "LICENSE",
            root / "scripts" / "build-loader.sh",
            root / "scripts" / "fetch-ios-dependencies.sh",
            root / "THIRD_PARTY_NOTICES.md",
        ]
    )
    return sources


def build_loader_provenance(
    loader: str | Path,
    source_paths: Iterable[str | Path],
) -> dict[str, Any]:
    loader_path = Path(loader).resolve()
    return {
        "schema_version": 1,
        "loader_name": loader_path.name,
        "loader_sha256": _sha256(loader_path),
        "sources": _source_hashes(source_paths),
    }


def verify_loader_provenance(
    loader: str | Path,
    provenance: dict[str, Any],
    source_paths: Iterable[str | Path],
) -> dict[str, Any]:
    loader_path = Path(loader).resolve()
    expected_sources = provenance.get("sources")
    current_sources = _source_hashes(source_paths)
    errors: list[str] = []
    if provenance.get("schema_version") != 1:
        errors.append("provenance_schema_invalid")
    if provenance.get("loader_name") != loader_path.name:
        errors.append("loader_name_mismatch")
    if provenance.get("loader_sha256") != _sha256(loader_path):
        errors.append("loader_hash_mismatch")
    if not isinstance(expected_sources, dict):
        errors.append("source_manifest_invalid")
        expected_sources = {}
    for name in sorted(set(expected_sources) | set(current_sources)):
        if name not in expected_sources:
            errors.append(f"unexpected_source:{name}")
        elif name not in current_sources:
            errors.append(f"missing_source:{name}")
        elif expected_sources[name] != current_sources[name]:
            errors.append(f"source_hash_mismatch:{name}")
    return {
        "valid": not errors,
        "loader": str(loader_path),
        "errors": errors,
        "current_loader_sha256": _sha256(loader_path),
        "current_sources": current_sources,
    }
