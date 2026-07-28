from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

import lief

from wechat_ipa_audit.reverse_inventory import parse_logos_hooks


SYMBOL_TOKENS = (
    "ManualAuth",
    "BundleId",
    "ClientSeq",
    "DeviceName",
    "JailBreak",
    "advertisingIdentifier",
    "identifierForVendor",
    "CrashReport",
    "ptrace",
    "syscall",
    "dlsym",
    "MSHook",
    "method_setImplementation",
    "class_addMethod",
    "openURL",
    "Login",
    "QRCode",
    "Provision",
    "Expiration",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def symbol_name(symbol: object) -> str:
    value = getattr(symbol, "name", "")
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="backslashreplace")
    return str(value)


def load_strongarm(strongarm_root: Path) -> tuple[type, type]:
    sys.path.insert(0, str(strongarm_root.resolve()))
    from strongarm.macho.macho_parse import MachoParser
    from strongarm.macho.objc_runtime_data_parser import ObjcRuntimeDataParser

    return MachoParser, ObjcRuntimeDataParser


def serialize_runtime(path: Path, strongarm_root: Path) -> dict[str, object]:
    MachoParser, ObjcRuntimeDataParser = load_strongarm(strongarm_root)
    parser = MachoParser(path)
    binary = parser.get_arm64_slice() or parser.slices[0]
    runtime = ObjcRuntimeDataParser(binary)
    classes = []
    for objc_class in sorted(runtime.classes, key=lambda item: item.name):
        selectors = [
            {
                "name": selector.name,
                "implementation": (
                    f"0x{int(selector.implementation):x}"
                    if selector.implementation
                    else None
                ),
            }
            for selector in objc_class.selectors
        ]
        ivars = [
            {
                "name": ivar.name,
                "type": ivar.class_name,
                "offset": ivar.field_offset,
                "offset_address": f"0x{int(ivar.field_offset_addr):x}",
            }
            for ivar in objc_class.ivars
        ]
        classes.append(
            {
                "name": objc_class.name,
                "superclass": objc_class.superclass_name,
                "selectors": selectors,
                "ivars": ivars,
                "protocols": sorted(protocol.name for protocol in objc_class.protocols),
            }
        )
    return {
        "class_count": len(classes),
        "selector_count": sum(len(item["selectors"]) for item in classes),
        "ivar_count": sum(len(item["ivars"]) for item in classes),
        "classes": classes,
        "protocols": sorted(protocol.name for protocol in runtime.protocols),
    }


def analyze_representative(
    component: dict[str, object],
    strongarm_root: Path,
) -> dict[str, object]:
    path = Path(str(component["path"])).resolve()
    binary = None
    symbols: list[str] = []
    if component["text_size"] != 0:
        binary = lief.parse(str(path))
        if not isinstance(binary, lief.MachO.Binary):
            raise ValueError(f"Not a thin Mach-O binary: {path}")
        symbols = [symbol_name(symbol) for symbol in binary.symbols]
    hooks = parse_logos_hooks(symbols)
    hook_counts = Counter(hook["class"] for hook in hooks)
    named_symbols = [
        {
            "name": symbol_name(symbol),
            "address": f"0x{int(getattr(symbol, 'value', 0)):x}",
        }
        for symbol in (binary.symbols if binary else [])
        if any(token.lower() in symbol_name(symbol).lower() for token in SYMBOL_TOKENS)
    ]
    result: dict[str, object] = {
        "schema_version": 1,
        "component": component["component"],
        "path": str(path),
        "sha256": component["sha256"],
        "calculated_sha256": sha256(path),
        "text_sha256": component["text_sha256"],
        "occurrences": component["occurrences"],
        "libraries": component["libraries"],
        "constructors": component["constructors"],
        "static": {
            "size": component["size"],
            "architecture": component["architecture"],
            "encrypted": component["encrypted"],
            "imports_of_interest": component["imports_of_interest"],
            "sensitive_hits": component["sensitive_hits"],
            "domains": component["domains"],
            "objc_methods_of_interest": component["objc_methods_of_interest"],
            "cstrings_of_interest": component["cstrings_of_interest"],
        },
        "logos": {
            "hook_count": len(hooks),
            "class_count": len(hook_counts),
            "hooks": hooks,
            "hooks_by_class": [
                {"class": class_name, "count": count}
                for class_name, count in sorted(
                    hook_counts.items(), key=lambda item: (-item[1], item[0])
                )
            ],
        },
        "named_symbols_of_interest": named_symbols,
    }
    if component["text_size"] == 0:
        result["objc_runtime"] = {
            "error": "Skipped: representative has an empty __text section",
            "class_count": 0,
            "selector_count": 0,
            "ivar_count": 0,
            "classes": [],
            "protocols": [],
        }
    else:
        try:
            result["objc_runtime"] = serialize_runtime(path, strongarm_root)
        except Exception as error:
            result["objc_runtime"] = {
                "error": f"{type(error).__name__}: {error}",
                "class_count": 0,
                "selector_count": 0,
                "ivar_count": 0,
                "classes": [],
                "protocols": [],
            }
    return result


def representatives(matrix: dict[str, object]) -> list[dict[str, object]]:
    by_text_hash: dict[str, list[dict[str, object]]] = {}
    for component in matrix["components"]:
        by_text_hash.setdefault(component["text_sha256"], []).append(component)
    return [
        min(members, key=lambda item: (item["component"], item["sha256"]))
        for _, members in sorted(by_text_hash.items())
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--strongarm-root", required=True, type=Path)
    arguments = parser.parse_args()

    matrix = json.loads(arguments.matrix.read_text(encoding="utf-8"))
    arguments.output.mkdir(parents=True, exist_ok=True)
    index_entries = []
    for component in representatives(matrix):
        print(
            f"analyzing {component['component']} {str(component['text_sha256'])[:16]}",
            file=sys.stderr,
            flush=True,
        )
        result = analyze_representative(component, arguments.strongarm_root)
        output_name = (
            f"{Path(str(component['component'])).stem}-"
            f"{str(component['text_sha256'])[:16]}.json"
        )
        output_path = arguments.output / output_name
        output_path.write_text(
            json.dumps(result, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        runtime = result["objc_runtime"]
        index_entries.append(
            {
                "component": result["component"],
                "sha256": result["sha256"],
                "text_sha256": result["text_sha256"],
                "output": output_name,
                "logos_hook_count": result["logos"]["hook_count"],
                "logos_class_count": result["logos"]["class_count"],
                "objc_class_count": runtime["class_count"],
                "objc_selector_count": runtime["selector_count"],
                "runtime_error": runtime.get("error"),
            }
        )
    index = {
        "schema_version": 1,
        "representative_count": len(index_entries),
        "representatives": index_entries,
    }
    index_path = arguments.output / "index.json"
    index_path.write_text(
        json.dumps(index, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(index, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
