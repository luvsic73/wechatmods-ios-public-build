from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


GLASS_LOADER_SHA256 = (
    "712c8bacc90ba2a5eb4df827fb366ec86b68af723b4c70076b11d48d636e5907"
)
SETTINGS_INSTALL_OFFSET = 0x9480
SETTINGS_INSTALL_INSTRUCTION = bytes.fromhex("00ed45f9")
OBJC_MESSAGE_TO_NIL_INSTRUCTION = bytes.fromhex("000080d2")


def prepare_glass_loader(
    input_dylib: str | Path,
    output_dylib: str | Path,
    *,
    expected_sha256: str | None = GLASS_LOADER_SHA256,
) -> dict[str, Any]:
    input_path = Path(input_dylib).resolve()
    output_path = Path(output_dylib).resolve()
    if input_path == output_path:
        raise ValueError("input and output dylib paths must differ")

    data = bytearray(input_path.read_bytes())
    input_sha256 = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and input_sha256 != expected_sha256:
        raise ValueError(
            f"unexpected glass loader SHA-256: {input_sha256}"
        )

    start = SETTINGS_INSTALL_OFFSET
    end = start + len(SETTINGS_INSTALL_INSTRUCTION)
    if data[start:end] != SETTINGS_INSTALL_INSTRUCTION:
        raise ValueError(
            "glass loader settings-install instruction does not match"
        )
    data[start:end] = OBJC_MESSAGE_TO_NIL_INSTRUCTION

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(data)
    return {
        "input": str(input_path),
        "output": str(output_path),
        "input_sha256": input_sha256,
        "output_sha256": hashlib.sha256(data).hexdigest(),
        "patch": {
            "file_offset": SETTINGS_INSTALL_OFFSET,
            "original": SETTINGS_INSTALL_INSTRUCTION.hex(),
            "replacement": OBJC_MESSAGE_TO_NIL_INSTRUCTION.hex(),
            "effect": "disable duplicate WMSettingsEntry installation",
        },
        "retained": [
            "WMLiquidGlassStyle",
            "empty module runtime",
            "safe launch bookkeeping",
        ],
    }
