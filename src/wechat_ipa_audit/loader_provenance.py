from __future__ import annotations

import argparse
import hashlib
import json
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="loader-provenance")
    commands = parser.add_subparsers(dest="command", required=True)
    write = commands.add_parser("write-loader-provenance")
    write.add_argument("loader")
    write.add_argument("output")
    verify = commands.add_parser("verify-loader-provenance")
    verify.add_argument("loader")
    verify.add_argument("provenance")
    verify.add_argument("--output")
    args = parser.parse_args(argv)
    project_root = Path(__file__).resolve().parents[2]
    if args.command == "write-loader-provenance":
        result = build_loader_provenance(
            args.loader,
            project_loader_sources(project_root),
        )
        output = Path(args.output)
    else:
        provenance = json.loads(
            Path(args.provenance).read_text(encoding="utf-8")
        )
        result = verify_loader_provenance(
            args.loader,
            provenance,
            project_loader_sources(project_root),
        )
        output = Path(args.output) if args.output else None
    rendered = json.dumps(
        result,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    if output is None:
        print(rendered, end="")
    else:
        output.write_text(rendered, encoding="utf-8")
    return 0 if result.get("valid", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
