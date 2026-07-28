import io
import json
import plistlib
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from PIL import Image

from wechat_ipa_audit.app_icon import replace_app_icon


def _png(size: tuple[int, int], color: tuple[int, int, int]) -> bytes:
    output = io.BytesIO()
    Image.new("RGB", size, color).save(output, format="PNG")
    return output.getvalue()


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def _cgbi_png_header(size: tuple[int, int]) -> bytes:
    width, height = size
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"CgBI", b"\x40\x00\x20\x02")
        + _png_chunk(
            b"IHDR",
            struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0),
        )
        + _png_chunk(b"IEND", b"")
    )


class AppIconPackagingTests(unittest.TestCase):
    def test_production_icon_document_has_two_glass_depth_groups(self) -> None:
        root = Path(__file__).resolve().parents[1]
        icon_bundle = root / "assets" / "AppIcon.icon"
        document = json.loads(
            (icon_bundle / "icon.json").read_text(encoding="utf-8")
        )

        self.assertEqual(document["supported-platforms"]["squares"], "shared")
        self.assertEqual(len(document["groups"]), 2)
        for group in document["groups"]:
            self.assertTrue(group["specular"])
            self.assertTrue(group["translucency"]["enabled"])
            self.assertEqual(len(group["layers"]), 2)
            self.assertTrue(group["layers"][0]["glass"])
            for layer in group["layers"]:
                image = Image.open(
                    icon_bundle / "Assets" / layer["image-name"]
                )
                self.assertEqual(image.size, (1024, 1024))
                self.assertEqual(image.mode, "RGBA")
                self.assertEqual(image.getchannel("A").getextrema(), (0, 255))

    def test_replaces_raster_fallbacks_and_adds_layered_icon_document(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.ipa"
            output = root / "output.ipa"
            second_output = root / "output-second-pass.ipa"
            master = root / "master.png"
            icon_bundle = root / "AppIcon.icon"
            (icon_bundle / "Assets").mkdir(parents=True)

            Image.new("RGB", (1024, 1024), (17, 24, 39)).save(master)
            icon_json = {
                "fill": {"solid": "srgb:0.00000,0.00000,0.00000,1.00000"},
                "groups": [
                    {
                        "layers": [
                            {
                                "glass": True,
                                "image-name": "bubble.png",
                                "name": "bubble",
                            }
                        ],
                        "specular": True,
                    }
                ],
                "supported-platforms": {"squares": "shared"},
            }
            (icon_bundle / "icon.json").write_text(
                json.dumps(icon_json),
                encoding="utf-8",
            )
            (icon_bundle / "Assets" / "bubble.png").write_bytes(
                _png((1024, 1024), (255, 255, 255))
            )

            info = {
                "CFBundleIdentifier": "com.example.fixture",
                "CFBundleIcons": {
                    "CFBundlePrimaryIcon": {
                        "CFBundleIconFiles": ["AppIcon60x60"],
                        "CFBundleIconName": "AppIcon",
                    }
                },
                "CFBundleIcons~ipad": {
                    "CFBundlePrimaryIcon": {
                        "CFBundleIconFiles": [
                            "AppIcon60x60",
                            "AppIcon76x76",
                        ],
                        "CFBundleIconName": "AppIcon",
                    }
                },
            }
            with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(
                    "Payload/Fixture.app/Info.plist",
                    plistlib.dumps(info),
                )
                archive.writestr(
                    "Payload/Fixture.app/AppIcon60x60@2x.png",
                    _cgbi_png_header((120, 120)),
                )
                archive.writestr(
                    "Payload/Fixture.app/AppIcon76x76@2x~ipad.png",
                    _png((152, 152), (0, 255, 0)),
                )
                archive.writestr(
                    "Payload/Fixture.app/Icon@2x.png",
                    _png((114, 114), (0, 255, 0)),
                )
                archive.writestr("Payload/Fixture.app/content.bin", b"unchanged")

            report = replace_app_icon(
                source,
                master,
                icon_bundle,
                output,
            )

            with zipfile.ZipFile(output) as archive:
                names = archive.namelist()
                packaged_info = plistlib.loads(
                    archive.read("Payload/Fixture.app/Info.plist")
                )
                self.assertEqual(
                    archive.read("Payload/Fixture.app/content.bin"),
                    b"unchanged",
                )
                rewritten = {
                    name: Image.open(io.BytesIO(archive.read(name)))
                    for name in names
                    if name.rsplit("/", 1)[-1]
                    in {
                        "AppIcon60x60@2x.png",
                        "AppIcon60x60@3x.png",
                        "AppIcon76x76@2x~ipad.png",
                        "AppIcon76x76~ipad.png",
                        "Icon@2x.png",
                    }
                }
                bundled_json = json.loads(
                    archive.read(
                        "Payload/Fixture.app/AppIcon.icon/icon.json"
                    )
                )

            self.assertEqual(
                {name.rsplit("/", 1)[-1]: image.size for name, image in rewritten.items()},
                {
                    "AppIcon60x60@2x.png": (120, 120),
                    "AppIcon60x60@3x.png": (180, 180),
                    "AppIcon76x76@2x~ipad.png": (152, 152),
                    "AppIcon76x76~ipad.png": (76, 76),
                    "Icon@2x.png": (114, 114),
                },
            )
            self.assertTrue(all(image.mode == "RGB" for image in rewritten.values()))
            self.assertIn(
                "Payload/Fixture.app/AppIcon.icon/Assets/bubble.png",
                names,
            )
            self.assertTrue(bundled_json["groups"][0]["specular"])
            self.assertEqual(report["replaced_count"], 3)
            self.assertGreaterEqual(report["added_count"], 2)
            self.assertEqual(report["icon_document"], "AppIcon.icon")
            self.assertNotIn("CFBundleIcons", packaged_info)
            self.assertNotIn("CFBundleIcons~ipad", packaged_info)
            self.assertEqual(
                packaged_info["CFBundleIconFiles"],
                [
                    "WeChatGlassIcon.png",
                    "WeChatGlassIcon@2x.png",
                    "WeChatGlassIcon@3x.png",
                ],
            )
            for name in packaged_info["CFBundleIconFiles"]:
                image = Image.open(
                    io.BytesIO(
                        zipfile.ZipFile(output).read(
                            f"Payload/Fixture.app/{name}"
                        )
                    )
                )
                self.assertEqual(image.size, (512, 512))

            replace_app_icon(
                output,
                master,
                icon_bundle,
                second_output,
            )
            with zipfile.ZipFile(second_output) as archive:
                self.assertEqual(
                    len(archive.namelist()),
                    len(set(archive.namelist())),
                )


if __name__ == "__main__":
    unittest.main()
