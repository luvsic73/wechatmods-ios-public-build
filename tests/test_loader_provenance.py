import tempfile
import unittest
from pathlib import Path

from wechat_ipa_audit.loader_provenance import (
    build_loader_provenance,
    project_loader_sources,
    verify_loader_provenance,
)


class LoaderProvenanceTests(unittest.TestCase):
    def test_project_sources_pin_the_runtime_rebinding_dependency(self) -> None:
        root = Path(__file__).resolve().parents[1]
        names = {
            path.relative_to(root).as_posix()
            for path in project_loader_sources(root)
        }

        self.assertIn("vendor/fishhook/fishhook.c", names)
        self.assertIn("vendor/fishhook/fishhook.h", names)
        self.assertIn("vendor/fishhook/LICENSE", names)
        self.assertIn("scripts/fetch-ios-dependencies.sh", names)
        self.assertIn("THIRD_PARTY_NOTICES.md", names)

    def test_verifies_matching_loader_and_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            loader = root / "WeChatMods.dylib"
            source = root / "Module.m"
            loader.write_bytes(b"loader")
            source.write_text("module", encoding="utf-8")
            provenance = build_loader_provenance(loader, [source])

            result = verify_loader_provenance(
                loader,
                provenance,
                [source],
            )

        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_rejects_stale_loader_or_changed_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            loader = root / "WeChatMods.dylib"
            source = root / "Module.m"
            loader.write_bytes(b"loader")
            source.write_text("first", encoding="utf-8")
            provenance = build_loader_provenance(loader, [source])
            source.write_text("second", encoding="utf-8")

            source_result = verify_loader_provenance(
                loader,
                provenance,
                [source],
            )
            source.write_text("first", encoding="utf-8")
            loader.write_bytes(b"changed")
            loader_result = verify_loader_provenance(
                loader,
                provenance,
                [source],
            )

        self.assertIn("source_hash_mismatch:Module.m", source_result["errors"])
        self.assertIn("loader_hash_mismatch", loader_result["errors"])

    def test_build_and_packaging_scripts_enforce_provenance(self) -> None:
        root = Path(__file__).resolve().parents[1]
        build = (root / "scripts" / "build-loader.sh").read_text(encoding="utf-8")
        self.assertIn("write-loader-provenance", build)
        self.assertIn(
            "-m wechat_ipa_audit.loader_provenance",
            build,
        )
        for script_name in (
            "build-iloader.ps1",
            "build-coexist.ps1",
            "build-reference-candidate.ps1",
        ):
            source = (root / "scripts" / script_name).read_text(encoding="utf-8")
            self.assertIn("assert-loader-current.ps1", source)
        helper = (root / "scripts" / "assert-loader-current.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("verify-loader-provenance", helper)


if __name__ == "__main__":
    unittest.main()
