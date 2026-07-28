import tempfile
import unittest
from pathlib import Path

from wechat_ipa_audit.reference_candidate import (
    OBJC_MESSAGE_TO_NIL_INSTRUCTION,
    SETTINGS_INSTALL_INSTRUCTION,
    SETTINGS_INSTALL_OFFSET,
    prepare_glass_loader,
)


class ReferenceCandidateTests(unittest.TestCase):
    def test_build_uses_clean_coexist_baseline_and_unpatched_loader(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        script = (
            root / "scripts" / "build-reference-candidate.ps1"
        ).read_text(encoding="utf-8")

        self.assertLess(
            script.index("cli coexist"),
            script.index("cli package"),
        )
        self.assertLess(
            script.index("cli package"),
            script.index("cli inject"),
        )
        self.assertIn(
            'Join-Path $projectRoot "data\\modules.json"',
            script,
        )
        self.assertNotIn("prepare-glass-loader", script)
        self.assertIn("$coexistBase $candidateIpa", script)
        self.assertIn("candidate-policy", script)
        self.assertIn("inspect-coexist", script)

    def test_disables_only_duplicate_settings_installation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.dylib"
            output = root / "output.dylib"
            payload = bytearray(SETTINGS_INSTALL_OFFSET + 16)
            payload[
                SETTINGS_INSTALL_OFFSET:
                SETTINGS_INSTALL_OFFSET + 4
            ] = SETTINGS_INSTALL_INSTRUCTION
            source.write_bytes(payload)

            report = prepare_glass_loader(
                source,
                output,
                expected_sha256=None,
            )

            patched = output.read_bytes()
            self.assertEqual(
                patched[
                    SETTINGS_INSTALL_OFFSET:
                    SETTINGS_INSTALL_OFFSET + 4
                ],
                OBJC_MESSAGE_TO_NIL_INSTRUCTION,
            )
            self.assertEqual(
                patched[:SETTINGS_INSTALL_OFFSET],
                bytes(payload[:SETTINGS_INSTALL_OFFSET]),
            )
            self.assertEqual(
                patched[SETTINGS_INSTALL_OFFSET + 4:],
                bytes(payload[SETTINGS_INSTALL_OFFSET + 4:]),
            )
            self.assertEqual(
                report["patch"]["effect"],
                "disable duplicate WMSettingsEntry installation",
            )

    def test_rejects_an_unknown_loader_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.dylib"
            output = root / "output.dylib"
            source.write_bytes(b"\0" * (SETTINGS_INSTALL_OFFSET + 16))

            with self.assertRaisesRegex(
                ValueError,
                "settings-install instruction",
            ):
                prepare_glass_loader(
                    source,
                    output,
                    expected_sha256=None,
                )


if __name__ == "__main__":
    unittest.main()
