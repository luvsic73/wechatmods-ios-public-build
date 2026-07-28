from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from collections import defaultdict
from pathlib import Path

import lief


SENSITIVE_TERMS = (
    "ManualAuthAesReqData",
    "setBundleId:",
    "setClientSeqId:",
    "setDeviceName:",
    "JailBreakHelper",
    "advertisingIdentifier",
    "identifierForVendor",
    "ptrace",
    "sysctl",
    "dlsym",
    "MSHookMessageEx",
    "method_setImplementation",
    "class_addMethod",
    "task_get_exception_ports",
    "addLogInfo:withMessage:",
)

DOMAIN_PATTERN = re.compile(
    rb"(?i)(?:https?://)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    rb"(?:com|cn|net|org|io|cc|top|vip|xyz|app|me|co)(?::\d+)?"
    rb"(?:/[^\x00\s\"'<>]*)?"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def section_bytes(binary: lief.MachO.Binary, name: str) -> bytes:
    for section in binary.sections:
        if section.name == name:
            return bytes(section.content)
    return b""


def section_address(binary: lief.MachO.Binary, name: str) -> int | None:
    for section in binary.sections:
        if section.name == name:
            return section.virtual_address
    return None


def c_strings(data: bytes, minimum: int = 4) -> list[str]:
    values: list[str] = []
    for item in data.split(b"\0"):
        if len(item) < minimum:
            continue
        try:
            decoded = item.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if all(character.isprintable() for character in decoded):
            values.append(decoded)
    return values


def symbol_name(value: object) -> str:
    name = getattr(value, "name", "")
    if isinstance(name, bytes):
        return name.decode("utf-8", errors="backslashreplace")
    return str(name)


def constructor_addresses(binary: lief.MachO.Binary) -> list[str]:
    content = section_bytes(binary, "__mod_init_func")
    return [
        f"0x{value:x}"
        for (value,) in struct.iter_unpack("<Q", content[: len(content) // 8 * 8])
        if value
    ]


def analyze(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    binary = lief.parse(str(path))
    if not isinstance(binary, lief.MachO.Binary):
        raise ValueError(f"Not a thin Mach-O binary: {path}")

    text = section_bytes(binary, "__text")
    methnames = c_strings(section_bytes(binary, "__objc_methname"), minimum=3)
    cstring_values = c_strings(section_bytes(binary, "__cstring"), minimum=4)
    imports = sorted({symbol_name(function) for function in binary.imported_functions})
    exports = sorted({symbol_name(function) for function in binary.exported_functions})
    libraries = [library.name for library in binary.libraries]
    decoded = data.decode("latin-1", errors="ignore")
    sensitive_hits = [
        term for term in SENSITIVE_TERMS if term.lower() in decoded.lower()
    ]
    domains = sorted(
        {
            match.group(0).decode("utf-8", errors="ignore")
            for match in DOMAIN_PATTERN.finditer(data)
        }
    )
    encryption = binary.encryption_info
    return {
        "path": str(path),
        "component": path.name,
        "size": len(data),
        "sha256": sha256(data),
        "text_size": len(text),
        "text_sha256": sha256(text),
        "architecture": str(binary.header.cpu_type),
        "file_type": str(binary.header.file_type),
        "encrypted": bool(encryption and encryption.crypt_id != 0),
        "load_commands": len(binary.commands),
        "libraries": libraries,
        "constructors": constructor_addresses(binary),
        "text_address": (
            f"0x{section_address(binary, '__text'):x}"
            if section_address(binary, "__text") is not None
            else None
        ),
        "import_count": len(imports),
        "export_count": len(exports),
        "objc_method_name_count": len(methnames),
        "imports_of_interest": [
            name
            for name in imports
            if any(
                token.lower() in name.lower()
                for token in (
                    "hook",
                    "substrate",
                    "implementation",
                    "ptrace",
                    "sysctl",
                    "dlsym",
                    "objc_getclass",
                    "class_addmethod",
                )
            )
        ],
        "sensitive_hits": sensitive_hits,
        "domains": domains,
        "objc_methods_of_interest": [
            method
            for method in methnames
            if any(
                token.lower() in method.lower()
                for token in (
                    "auth",
                    "login",
                    "bundle",
                    "clientseq",
                    "device",
                    "jail",
                    "crash",
                    "report",
                    "identifier",
                    "debug",
                    "risk",
                    "ban",
                    "token",
                )
            )
        ],
        "cstrings_of_interest": [
            value
            for value in cstring_values
            if any(
                token.lower() in value.lower()
                for token in (
                    "auth",
                    "login",
                    "bundle",
                    "clientseq",
                    "device",
                    "jail",
                    "crash",
                    "report",
                    "identifier",
                    "debug",
                    "risk",
                    "ban",
                    "token",
                    "expire",
                    "http",
                )
            )
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("component_root", type=Path)
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()

    matrix = json.loads(arguments.matrix.read_text(encoding="utf-8"))
    occurrence_by_hash: dict[str, list[dict[str, object]]] = defaultdict(list)
    for occurrence in matrix["occurrences"]:
        occurrence_by_hash[occurrence["sha256"]].append(occurrence)

    analyses: list[dict[str, object]] = []
    for binary_path in sorted(arguments.component_root.glob("*/*")):
        if not binary_path.is_file():
            continue
        result = analyze(binary_path)
        result["occurrences"] = occurrence_by_hash[result["sha256"]]
        analyses.append(result)

    text_families: dict[str, list[dict[str, object]]] = defaultdict(list)
    for result in analyses:
        text_families[result["text_sha256"]].append(
            {
                "component": result["component"],
                "sha256": result["sha256"],
                "occurrences": result["occurrences"],
            }
        )

    report = {
        "schema_version": 1,
        "component_count": len(analyses),
        "text_family_count": len(text_families),
        "components": analyses,
        "text_families": [
            {
                "text_sha256": digest,
                "members": members,
            }
            for digest, members in sorted(text_families.items())
        ],
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "component_count": report["component_count"],
                "text_family_count": report["text_family_count"],
                "output": str(arguments.output),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
