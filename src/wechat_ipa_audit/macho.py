from __future__ import annotations

import struct
from typing import Any


_CPU_NAMES = {
    12: "arm",
    0x0100000C: "arm64",
    7: "x86",
    0x01000007: "x86_64",
}

_FILE_TYPES = {
    2: "execute",
    6: "dylib",
    8: "bundle",
}

_DYLIB_COMMANDS = {
    0x0C,
    0x18,
    0x1F,
    0x23,
    0x80000018,
    0x8000001C,
    0x8000001F,
    0x80000023,
}


def is_macho(data: bytes) -> bool:
    return data[:4] in {
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    }


def _read_c_string(data: bytes, start: int, limit: int) -> str:
    if start < 0 or start >= min(limit, len(data)):
        return ""
    end = data.find(b"\0", start, min(limit, len(data)))
    if end < 0:
        end = min(limit, len(data))
    return data[start:end].decode("utf-8", errors="replace")


def _thin(data: bytes, offset: int = 0) -> dict[str, Any]:
    magic = data[offset : offset + 4]
    if magic in {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"}:
        endian = "<"
        is_64 = magic == b"\xcf\xfa\xed\xfe"
    elif magic in {b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"}:
        endian = ">"
        is_64 = magic == b"\xfe\xed\xfa\xcf"
    else:
        raise ValueError("unsupported thin Mach-O magic")

    header_size = 32 if is_64 else 28
    if len(data) < offset + header_size:
        raise ValueError("truncated Mach-O header")
    cputype, _, filetype, ncmds, sizeofcmds = struct.unpack_from(
        endian + "IIIII", data, offset + 4
    )
    command_offset = offset + header_size
    command_limit = min(len(data), command_offset + sizeofcmds)
    dylibs: list[str] = []
    encrypted = False
    has_code_signature = False

    for _ in range(ncmds):
        if command_offset + 8 > command_limit:
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", data, command_offset)
        if cmdsize < 8 or command_offset + cmdsize > command_limit:
            break
        if cmd in _DYLIB_COMMANDS and cmdsize >= 12:
            name_offset = struct.unpack_from(endian + "I", data, command_offset + 8)[0]
            name = _read_c_string(
                data,
                command_offset + name_offset,
                command_offset + cmdsize,
            )
            if name:
                dylibs.append(name)
        elif cmd in {0x21, 0x2C} and cmdsize >= 20:
            cryptid = struct.unpack_from(endian + "I", data, command_offset + 16)[0]
            encrypted = encrypted or cryptid != 0
        elif cmd == 0x1D:
            has_code_signature = True
        command_offset += cmdsize

    return {
        "architectures": [_CPU_NAMES.get(cputype, hex(cputype))],
        "file_type": _FILE_TYPES.get(filetype, str(filetype)),
        "load_dylibs": sorted(set(dylibs)),
        "encrypted": encrypted,
        "has_code_signature": has_code_signature,
    }


def _fat(data: bytes) -> dict[str, Any]:
    magic = data[:4]
    endian = ">" if magic in {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"} else "<"
    is_64 = magic in {b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}
    if len(data) < 8:
        raise ValueError("truncated fat Mach-O header")
    count = struct.unpack_from(endian + "I", data, 4)[0]
    entry_size = 32 if is_64 else 20
    architectures: list[str] = []
    slices: list[dict[str, Any]] = []
    for index in range(count):
        entry = 8 + index * entry_size
        if entry + entry_size > len(data):
            break
        cputype = struct.unpack_from(endian + "I", data, entry)[0]
        architectures.append(_CPU_NAMES.get(cputype, hex(cputype)))
        if is_64:
            slice_offset = struct.unpack_from(endian + "Q", data, entry + 8)[0]
        else:
            slice_offset = struct.unpack_from(endian + "I", data, entry + 8)[0]
        if slice_offset + 4 <= len(data):
            try:
                slices.append(_thin(data, int(slice_offset)))
            except ValueError:
                pass
    return {
        "architectures": sorted(set(architectures)),
        "file_type": slices[0]["file_type"] if slices else "fat",
        "load_dylibs": sorted(
            {item for slice_report in slices for item in slice_report["load_dylibs"]}
        ),
        "encrypted": any(item["encrypted"] for item in slices),
        "has_code_signature": any(item["has_code_signature"] for item in slices),
    }


def parse_macho(data: bytes) -> dict[str, Any]:
    if data[:4] in {
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    }:
        return _fat(data)
    return _thin(data)

