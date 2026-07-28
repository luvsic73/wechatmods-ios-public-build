from __future__ import annotations

import plistlib
import shutil
import struct
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path


LOADER_NAME = "WeChatMods.dylib"
LOADER_INSTALL_NAME = f"@executable_path/Frameworks/{LOADER_NAME}"
_MACH_HEADER_64_SIZE = 32
_MH_MAGIC_64 = 0xFEEDFACF
_LC_LOAD_DYLIB = 0xC


def _app_paths(archive: zipfile.ZipFile) -> tuple[str, str, str]:
    info_paths = sorted(
        name
        for name in archive.namelist()
        if name.startswith("Payload/")
        and name.count("/") == 2
        and name.endswith(".app/Info.plist")
    )
    if len(info_paths) != 1:
        raise ValueError("package must contain one top-level app Info.plist")
    info_path = info_paths[0]
    app_prefix = info_path[: -len("Info.plist")]
    info = plistlib.loads(archive.read(info_path))
    executable = info.get("CFBundleExecutable")
    if not isinstance(executable, str) or not executable:
        raise ValueError("top-level Info.plist has no CFBundleExecutable")
    return app_prefix, app_prefix + executable, app_prefix + "Frameworks/" + LOADER_NAME


def _dylib_command(install_name: str) -> bytes:
    encoded_name = install_name.encode("utf-8") + b"\0"
    command_size = (24 + len(encoded_name) + 7) & ~7
    return struct.pack(
        "<IIIIII",
        _LC_LOAD_DYLIB,
        command_size,
        24,
        0,
        0,
        0,
    ) + encoded_name.ljust(command_size - 24, b"\0")


def _in_place_patch(binary_path: Path, install_name: str) -> None:
    data = bytearray(binary_path.read_bytes())
    if len(data) < _MACH_HEADER_64_SIZE:
        raise ValueError("main executable is smaller than a Mach-O 64 header")

    magic, _, _, _, command_count, command_bytes, _, _ = struct.unpack_from(
        "<IIIIIIII", data
    )
    if magic != _MH_MAGIC_64:
        raise ValueError("main executable is not a thin little-endian Mach-O 64")

    cursor = _MACH_HEADER_64_SIZE
    command_end = cursor + command_bytes
    for _ in range(command_count):
        if cursor + 8 > command_end:
            raise ValueError("Mach-O load command table is truncated")
        command, size = struct.unpack_from("<II", data, cursor)
        if size < 8 or cursor + size > command_end:
            raise ValueError("Mach-O load command has an invalid size")
        if command == _LC_LOAD_DYLIB and size >= 24:
            name_offset = struct.unpack_from("<I", data, cursor + 8)[0]
            if 24 <= name_offset < size:
                raw_name = data[cursor + name_offset : cursor + size]
                existing = bytes(raw_name).split(b"\0", 1)[0].decode(
                    "utf-8", errors="replace"
                )
                if existing == install_name:
                    return
        cursor += size
    if cursor != command_end:
        raise ValueError("Mach-O load command byte count is inconsistent")

    new_command = _dylib_command(install_name)
    new_end = command_end + len(new_command)
    if new_end > len(data):
        raise ValueError("Mach-O has no room for another load command")
    if any(data[command_end:new_end]):
        raise ValueError("Mach-O header slack is occupied")

    data[command_end:new_end] = new_command
    struct.pack_into(
        "<II",
        data,
        16,
        command_count + 1,
        command_bytes + len(new_command),
    )
    binary_path.write_bytes(data)


def inject_loader(
    input_ipa: str | Path,
    loader: str | Path,
    output_ipa: str | Path,
    *,
    patch_binary: Callable[[Path, str], None] | None = None,
) -> None:
    input_path = Path(input_ipa).resolve()
    loader_path = Path(loader).resolve()
    output_path = Path(output_ipa).resolve()
    if input_path == output_path:
        raise ValueError("input and output IPA paths must differ")
    if not loader_path.is_file():
        raise FileNotFoundError(loader_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    patch = patch_binary or _in_place_patch

    with zipfile.ZipFile(input_path) as source:
        app_prefix, executable_member, loader_member = _app_paths(source)
        signature_prefix = app_prefix + "_CodeSignature/"
        with tempfile.TemporaryDirectory() as directory:
            executable_path = Path(directory) / "main"
            with source.open(executable_member) as input_stream:
                with executable_path.open("wb") as output_stream:
                    shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
            patch(executable_path, LOADER_INSTALL_NAME)
            patched_executable = executable_path.read_bytes()

        with zipfile.ZipFile(
            output_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
        ) as target:
            for member in source.infolist():
                if member.filename == loader_member or member.filename.startswith(
                    signature_prefix
                ):
                    continue
                if member.filename == executable_member:
                    target.writestr(member, patched_executable)
                    continue
                with source.open(member) as input_stream:
                    with target.open(member, "w") as output_stream:
                        shutil.copyfileobj(
                            input_stream,
                            output_stream,
                            length=1024 * 1024,
                        )

            loader_info = zipfile.ZipInfo(loader_member)
            loader_info.create_system = 3
            loader_info.external_attr = 0o100755 << 16
            loader_info.compress_type = zipfile.ZIP_DEFLATED
            with loader_path.open("rb") as input_stream:
                with target.open(loader_info, "w") as output_stream:
                    shutil.copyfileobj(
                        input_stream,
                        output_stream,
                        length=1024 * 1024,
                    )
