from __future__ import annotations

import tempfile
import unittest
import struct
from pathlib import Path

from wechat_ipa_audit.loader_policy import inspect_loader_policy


class LoaderPolicyTests(unittest.TestCase):
    def _write_loader(self, root: Path, *markers: bytes) -> Path:
        path = root / "WeChatMods.dylib"
        header = struct.pack(
            "<IIIIIIII",
            0xFEEDFACF,
            0x0100000C,
            0,
            6,
            0,
            0,
            0,
            0,
        )
        path.write_bytes(header + b"\x00".join(markers))
        return path

    def test_accepts_a_loader_with_every_required_runtime_seam(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            loader = self._write_loader(
                Path(temporary),
                b"WMLoginLayoutAdapter",
                b"UIBackgroundExtensionView",
                b"WMLiquidGlassStyle",
                b"WMSettingsEntry",
                b"WMAntiRevokeModule",
                b"setInteractive:",
            )

            result = inspect_loader_policy(loader)

            self.assertTrue(result["valid"])
            self.assertEqual(result["missing_required_markers"], [])
            self.assertEqual(result["forbidden_marker_hits"], [])

    def test_rejects_the_previous_loader_missing_login_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            loader = self._write_loader(
                Path(temporary),
                b"WMLiquidGlassStyle",
                b"WMSettingsEntry",
                b"WMAntiRevokeModule",
                b"setInteractive:",
            )

            result = inspect_loader_policy(loader)

            self.assertFalse(result["valid"])
            self.assertIn(
                "WMLoginLayoutAdapter",
                result["missing_required_markers"],
            )

    def test_allows_shared_uikit_initializer_but_rejects_redirects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            loader = self._write_loader(
                Path(temporary),
                b"WMLoginLayoutAdapter",
                b"UIBackgroundExtensionView",
                b"WMLiquidGlassStyle",
                b"WMSettingsEntry",
                b"WMAntiRevokeModule",
                b"setInteractive:",
                b"initWithStyle:",
                b"https://wx.plus",
            )

            result = inspect_loader_policy(loader)

            self.assertFalse(result["valid"])
            self.assertEqual(
                result["forbidden_marker_hits"],
                ["https://wx.plus"],
            )


if __name__ == "__main__":
    unittest.main()
