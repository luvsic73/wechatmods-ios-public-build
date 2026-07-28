import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from test_audit import make_ipa
from wechat_ipa_audit.packaging import package_all_disabled, verify_package


class PackagingTests(unittest.TestCase):
    def test_packages_a_manifest_with_every_module_disabled(self) -> None:
        modules = [
            {"id": "anti-revoke", "risk": "medium"},
            {"id": "theme", "risk": "low"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.ipa"
            output = root / "output.ipa"
            make_ipa(base)

            package_all_disabled(base, output, modules)

            with zipfile.ZipFile(output) as archive:
                manifest = json.loads(
                    archive.read(
                        "Payload/Fixture.app/WeChatMods/module-manifest.json"
                    )
                )
            verification = verify_package(output)

        self.assertEqual(
            manifest["modules"],
            [
                {"enabled": False, "id": "anti-revoke", "risk": "medium"},
                {"enabled": False, "id": "theme", "risk": "low"},
            ],
        )
        self.assertEqual(manifest["schema_version"], 2)
        self.assertFalse(verification["valid"])
        self.assertEqual(verification["enabled_modules"], [])
        self.assertFalse(verification["loader_present"])
        self.assertFalse(verification["loader_executable"])

    def test_preserves_feature_collection_gate_without_bundling_binary(
        self,
    ) -> None:
        metadata = {
            "component": "MiYou.dylib",
            "included": False,
            "activation_gate": "component-repair-required",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.ipa"
            output = root / "output.ipa"
            make_ipa(base)

            package_all_disabled(
                base,
                output,
                [{"id": "forward-voice", "runtime": "feature-collection"}],
                feature_collection=metadata,
            )

            with zipfile.ZipFile(output) as archive:
                manifest = json.loads(
                    archive.read(
                        "Payload/Fixture.app/WeChatMods/module-manifest.json"
                    )
                )
                matching_members = [
                    name for name in archive.namelist() if "MiYou" in name
                ]

        self.assertEqual(manifest["feature_collection"], metadata)
        self.assertEqual(matching_members, [])

    def test_verifies_a_complete_package_with_an_executable_loader(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.ipa"
            output = root / "output.ipa"
            make_ipa(base)
            package_all_disabled(base, output, [{"id": "theme"}])
            loader = zipfile.ZipInfo(
                "Payload/Fixture.app/Frameworks/WeChatMods.dylib"
            )
            loader.create_system = 3
            loader.external_attr = 0o100755 << 16
            with zipfile.ZipFile(output, "a", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(loader, b"loader")

            verification = verify_package(output)

        self.assertTrue(verification["valid"])
        self.assertTrue(verification["loader_present"])
        self.assertTrue(verification["loader_executable"])
        self.assertTrue(verification["runtime_dependencies_resolved"])

    def test_rejects_the_captured_mmrouter_missing_library_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.ipa"
            output = root / "output.ipa"
            make_ipa(base)
            package_all_disabled(base, output, [{"id": "theme"}])
            loader = zipfile.ZipInfo(
                "Payload/Fixture.app/Frameworks/WeChatMods.dylib"
            )
            loader.create_system = 3
            loader.external_attr = 0o100755 << 16
            router = zipfile.ZipInfo(
                "Payload/Fixture.app/Frameworks/MMRouter.framework/MMRouter"
            )
            router.create_system = 3
            router.external_attr = 0o100755 << 16
            with zipfile.ZipFile(output, "a", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(loader, b"loader")
                archive.writestr(
                    router,
                    b"@rpath/JavaScriptCore.framework/JavaScriptCore",
                )

            verification = verify_package(output)

        self.assertFalse(verification["valid"])
        self.assertFalse(verification["runtime_dependencies_resolved"])
        self.assertIn(
            "Frameworks/JavaScriptCore.framework/JavaScriptCore",
            verification["runtime_dependency_errors"],
        )

    def test_forces_every_module_disabled_even_with_legacy_default(self) -> None:
        modules = [
            {
                "id": "anti-revoke",
                "default_enabled": True,
                "enabled": True,
            },
            {"id": "media-export", "enabled": False},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.ipa"
            output = root / "output.ipa"
            make_ipa(base)
            package_all_disabled(base, output, modules)
            with zipfile.ZipFile(output) as archive:
                manifest = json.loads(
                    archive.read(
                        "Payload/Fixture.app/WeChatMods/module-manifest.json"
                    )
                )

        self.assertEqual(
            [module["id"] for module in manifest["modules"] if module["enabled"]],
            [],
        )
