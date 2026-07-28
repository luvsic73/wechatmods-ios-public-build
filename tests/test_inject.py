import plistlib
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from wechat_ipa_audit.inject import LOADER_INSTALL_NAME, inject_loader


class InjectTests(unittest.TestCase):
    @staticmethod
    def _minimal_arm64_macho() -> bytes:
        segment = struct.pack(
            "<II16sQQQQiiII",
            0x19,
            72,
            b"__TEXT".ljust(16, b"\0"),
            0,
            4096,
            0,
            4096,
            5,
            5,
            0,
            0,
        )
        header = struct.pack(
            "<IIIIIIII",
            0xFEEDFACF,
            0x0100000C,
            0,
            2,
            1,
            len(segment),
            0,
            0,
        )
        return (header + segment).ljust(4096, b"\0") + b"UNCHANGED"

    def test_injects_loader_and_removes_stale_top_level_signature(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.ipa"
            loader = root / "WeChatMods.dylib"
            output = root / "output.ipa"
            loader.write_bytes(b"loader")
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr(
                    "Payload/Fixture.app/Info.plist",
                    plistlib.dumps({"CFBundleExecutable": "Fixture"}),
                )
                archive.writestr("Payload/Fixture.app/Fixture", b"main")
                archive.writestr(
                    "Payload/Fixture.app/_CodeSignature/CodeResources", b"stale"
                )
                archive.writestr(
                    "Payload/Fixture.app/PlugIns/Share.appex/Share", b"extension"
                )

            def fake_patch(path: Path, install_name: str) -> None:
                self.assertEqual(install_name, LOADER_INSTALL_NAME)
                path.write_bytes(path.read_bytes() + b"|patched|")

            inject_loader(source, loader, output, patch_binary=fake_patch)

            with zipfile.ZipFile(output) as archive:
                names = archive.namelist()
                main = archive.read("Payload/Fixture.app/Fixture")
                added_loader = archive.read(
                    "Payload/Fixture.app/Frameworks/WeChatMods.dylib"
                )
                loader_mode = (
                    archive.getinfo(
                        "Payload/Fixture.app/Frameworks/WeChatMods.dylib"
                    ).external_attr
                    >> 16
                )

        self.assertEqual(main, b"main|patched|")
        self.assertEqual(added_loader, b"loader")
        self.assertNotIn(
            "Payload/Fixture.app/_CodeSignature/CodeResources", names
        )
        self.assertIn("Payload/Fixture.app/PlugIns/Share.appex/Share", names)
        self.assertEqual(loader_mode & 0o111, 0o111)

    def test_default_patch_preserves_every_byte_outside_header_slack(self) -> None:
        original = self._minimal_arm64_macho()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.ipa"
            loader = root / "WeChatMods.dylib"
            output = root / "output.ipa"
            loader.write_bytes(b"loader")
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr(
                    "Payload/Fixture.app/Info.plist",
                    plistlib.dumps({"CFBundleExecutable": "Fixture"}),
                )
                archive.writestr("Payload/Fixture.app/Fixture", original)

            inject_loader(source, loader, output)

            with zipfile.ZipFile(output) as archive:
                patched = archive.read("Payload/Fixture.app/Fixture")

        self.assertEqual(len(patched), len(original))
        self.assertEqual(patched[4096:], original[4096:])
        ncmds, sizeofcmds = struct.unpack_from("<II", patched, 16)
        self.assertEqual(ncmds, 2)
        self.assertEqual(sizeofcmds, 144)
        command = patched[104:176]
        cmd, cmdsize, name_offset = struct.unpack_from("<III", command)
        self.assertEqual((cmd, cmdsize, name_offset), (0xC, 72, 24))
        self.assertEqual(
            command[name_offset:].rstrip(b"\0").decode(),
            LOADER_INSTALL_NAME,
        )


if __name__ == "__main__":
    unittest.main()
