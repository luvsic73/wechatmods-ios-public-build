from __future__ import annotations

import hashlib
import io
import json
import plistlib
import re
import shutil
import struct
import zipfile
from pathlib import Path
from typing import Any

from PIL import Image


_TOP_LEVEL_INFO = re.compile(r"^Payload/[^/]+\.app/Info\.plist$")
_ROOT_ICON_FILE = re.compile(r"^(?:AppIcon.*|Icon(?:@.*)?)\.png$", re.IGNORECASE)
_ICON_DIMENSIONS = re.compile(
    r"^(?P<prefix>.*?)(?P<width>\d+(?:\.\d+)?)x(?P<height>\d+(?:\.\d+)?)$"
)
_LEGACY_ICON_FILES = (
    "WeChatGlassIcon.png",
    "WeChatGlassIcon@2x.png",
    "WeChatGlassIcon@3x.png",
)


def _top_level_info(archive: zipfile.ZipFile) -> str:
    matches = sorted(
        name for name in archive.namelist() if _TOP_LEVEL_INFO.match(name)
    )
    if len(matches) != 1:
        raise ValueError("package must contain one top-level app Info.plist")
    return matches[0]


def _png_size(data: bytes) -> tuple[int, int]:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("app icon is not a PNG")
    offset = 8
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        if kind == b"IHDR" and len(payload) >= 8:
            return struct.unpack(">II", payload[:8])
        offset += 12 + length
    raise ValueError("app icon PNG has no IHDR chunk")


def _validate_icon_document(path: Path) -> dict[str, Any]:
    document_path = path / "icon.json"
    if not document_path.is_file():
        raise ValueError("icon document must contain icon.json")
    document = json.loads(document_path.read_text(encoding="utf-8"))
    for group in document.get("groups", []):
        for layer in group.get("layers", []):
            image_name = layer.get("image-name")
            if not isinstance(image_name, str) or not image_name:
                raise ValueError("every icon layer must name an image")
            if Path(image_name).name != image_name:
                raise ValueError(f"invalid icon layer image name: {image_name}")
            if not (path / "Assets" / image_name).is_file():
                raise ValueError(f"missing icon layer asset: {image_name}")
    return document


def _render_icon(master: Image.Image, size: tuple[int, int]) -> bytes:
    resampling = getattr(Image, "Resampling", Image)
    rendered = master.resize(size, resampling.LANCZOS)
    output = io.BytesIO()
    rendered.save(output, format="PNG", optimize=True)
    return output.getvalue()


def _primary_icon_files(info: dict[str, Any], key: str) -> list[str]:
    files = (
        info.get(key, {})
        .get("CFBundlePrimaryIcon", {})
        .get("CFBundleIconFiles", [])
    )
    return [name for name in files if isinstance(name, str) and name]


def _missing_scale_icons(
    info: dict[str, Any],
    app_prefix: str,
) -> dict[str, tuple[int, int]]:
    desired: dict[str, tuple[int, int]] = {}
    phone_files = _primary_icon_files(info, "CFBundleIcons")
    ipad_files = _primary_icon_files(info, "CFBundleIcons~ipad")

    for raw_name in phone_files:
        base = raw_name.removesuffix(".png")
        dimensions = _ICON_DIMENSIONS.fullmatch(base)
        if dimensions is None:
            continue
        width = float(dimensions.group("width"))
        height = float(dimensions.group("height"))
        for scale in (2, 3):
            desired[app_prefix + f"{base}@{scale}x.png"] = (
                round(width * scale),
                round(height * scale),
            )

    for raw_name in ipad_files:
        base = raw_name.removesuffix(".png")
        dimensions = _ICON_DIMENSIONS.fullmatch(base)
        if dimensions is None:
            continue
        width = float(dimensions.group("width"))
        height = float(dimensions.group("height"))
        desired[app_prefix + f"{base}~ipad.png"] = (
            round(width),
            round(height),
        )
        desired[app_prefix + f"{base}@2x~ipad.png"] = (
            round(width * 2),
            round(height * 2),
        )
    return desired


def replace_app_icon(
    input_ipa: str | Path,
    master_png: str | Path,
    icon_document: str | Path,
    output_ipa: str | Path,
) -> dict[str, Any]:
    source_path = Path(input_ipa).resolve()
    output_path = Path(output_ipa).resolve()
    if source_path == output_path:
        raise ValueError("input and output IPA paths must differ")

    master_path = Path(master_png)
    with Image.open(master_path) as source_master:
        if source_master.size != (1024, 1024):
            raise ValueError("master app icon must be 1024x1024")
        if "A" in source_master.getbands():
            alpha = source_master.getchannel("A")
            if alpha.getextrema() != (255, 255):
                raise ValueError("master app icon must be opaque")
        master = source_master.convert("RGB")

    document_path = Path(icon_document)
    _validate_icon_document(document_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    replaced: list[dict[str, Any]] = []
    added: list[dict[str, Any]] = []
    with zipfile.ZipFile(source_path) as source:
        info_path = _top_level_info(source)
        app_prefix = info_path[: -len("Info.plist")]
        info = plistlib.loads(source.read(info_path))
        icon_name = (
            info.get("CFBundleIcons", {})
            .get("CFBundlePrimaryIcon", {})
            .get("CFBundleIconName", "AppIcon")
        )
        if not isinstance(icon_name, str) or not icon_name:
            icon_name = "AppIcon"
        document_archive_prefix = app_prefix + icon_name + ".icon/"
        existing_names = set(source.namelist())
        missing_scale_icons = _missing_scale_icons(info, app_prefix)
        info.pop("CFBundleIcons", None)
        info.pop("CFBundleIcons~ipad", None)
        info["CFBundleIconFiles"] = list(_LEGACY_ICON_FILES)

        icon_members: dict[str, bytes] = {}
        for member in source.infolist():
            relative = member.filename[len(app_prefix) :]
            if (
                member.filename.startswith(app_prefix)
                and "/" not in relative
                and _ROOT_ICON_FILE.fullmatch(relative)
            ):
                original = source.read(member)
                size = _png_size(original)
                replacement = _render_icon(master, size)
                icon_members[member.filename] = replacement
                replaced.append(
                    {
                        "path": member.filename,
                        "size": list(size),
                        "original_sha256": hashlib.sha256(original).hexdigest(),
                        "replacement_sha256": hashlib.sha256(
                            replacement
                        ).hexdigest(),
                    }
                )

        if not replaced:
            raise ValueError("package has no top-level raster app icons")

        for relative_name in _LEGACY_ICON_FILES:
            name = app_prefix + relative_name
            replacement = _render_icon(master, (512, 512))
            icon_members[name] = replacement
            record = {
                "path": name,
                "size": [512, 512],
                "replacement_sha256": hashlib.sha256(
                    replacement
                ).hexdigest(),
            }
            if name in existing_names:
                original = source.read(name)
                record["original_sha256"] = hashlib.sha256(
                    original
                ).hexdigest()
                replaced.append(record)
            else:
                added.append(record)

        for name, size in missing_scale_icons.items():
            if name in existing_names:
                continue
            replacement = _render_icon(master, size)
            icon_members[name] = replacement
            added.append(
                {
                    "path": name,
                    "size": list(size),
                    "replacement_sha256": hashlib.sha256(
                        replacement
                    ).hexdigest(),
                }
            )

        with zipfile.ZipFile(
            output_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=6,
        ) as target:
            for member in source.infolist():
                if member.filename.startswith(document_archive_prefix):
                    continue
                if member.filename == info_path:
                    target.writestr(
                        member,
                        plistlib.dumps(
                            info,
                            fmt=plistlib.FMT_BINARY,
                            sort_keys=False,
                        ),
                    )
                    continue
                replacement = icon_members.get(member.filename)
                if replacement is not None:
                    target.writestr(member, replacement)
                    continue
                with source.open(member) as input_stream:
                    with target.open(member, "w") as output_stream:
                        shutil.copyfileobj(
                            input_stream,
                            output_stream,
                            length=1024 * 1024,
                        )

            for name in sorted(item["path"] for item in added):
                member = zipfile.ZipInfo(name)
                member.create_system = 3
                member.external_attr = 0o100644 << 16
                target.writestr(member, icon_members[name])

            for file_path in sorted(
                path for path in document_path.rglob("*") if path.is_file()
            ):
                relative = file_path.relative_to(document_path).as_posix()
                member = zipfile.ZipInfo(document_archive_prefix + relative)
                member.create_system = 3
                member.external_attr = 0o100644 << 16
                target.writestr(member, file_path.read_bytes())

    return {
        "input_ipa": str(source_path),
        "output_ipa": str(output_path),
        "master_sha256": hashlib.sha256(master_path.read_bytes()).hexdigest(),
        "icon_document": icon_name + ".icon",
        "replaced_count": len(replaced),
        "added_count": len(added),
        "replaced": replaced,
        "added": added,
    }
