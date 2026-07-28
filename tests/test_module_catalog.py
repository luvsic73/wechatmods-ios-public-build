import json
import unittest
from pathlib import Path

from wechat_ipa_audit.module_catalog import (
    build_activation_plan,
    validate_catalog,
)


class ModuleCatalogTests(unittest.TestCase):
    def test_project_catalog_is_unique_all_disabled_and_risk_annotated(self) -> None:
        root = Path(__file__).resolve().parents[1]
        catalog = json.loads(
            (root / "data" / "modules.json").read_text(encoding="utf-8")
        )

        issues = validate_catalog(catalog["modules"])

        self.assertEqual(issues, [])
        self.assertGreaterEqual(len(catalog["modules"]), 30)
        self.assertTrue(
            all(module.get("enabled") is False for module in catalog["modules"])
        )
        self.assertTrue(
            all(
                "title" in module and "group" in module for module in catalog["modules"]
            )
        )
        self.assertTrue(
            all(
                module.get("risk") not in {"high", "critical"}
                or module.get("risk_reasons")
                for module in catalog["modules"]
            )
        )
        collection_modules = [
            module
            for module in catalog["modules"]
            if module.get("runtime") == "feature-collection"
        ]
        plan = build_activation_plan(
            catalog["modules"],
            requested={module["id"] for module in collection_modules},
            version="8.0.75",
        )
        self.assertEqual(plan["enabled"], [])
        self.assertTrue(
            all(
                "activation_gate:component-repair-required" in reasons
                for reasons in plan["blocked"].values()
            )
        )

    def test_plan_blocks_cross_owner_hook_collision(self) -> None:
        modules = [
            {
                "id": "first",
                "title": "First",
                "group": "messages",
                "compatible_versions": ["8.0.75"],
                "dependencies": [],
                "conflicts": [],
                "hooks": ["CMessageMgr.onRevokeMsg:"],
                "hook_owner": "native-first",
                "risk": "medium",
                "risk_reasons": [],
                "enabled": False,
            },
            {
                "id": "second",
                "title": "Second",
                "group": "messages",
                "compatible_versions": ["8.0.75"],
                "dependencies": [],
                "conflicts": [],
                "hooks": ["CMessageMgr.onRevokeMsg:"],
                "hook_owner": "native-second",
                "risk": "medium",
                "risk_reasons": [],
                "enabled": False,
            },
        ]

        plan = build_activation_plan(
            modules,
            requested={"first", "second"},
            version="8.0.75",
        )

        self.assertEqual(plan["enabled"], [])
        self.assertEqual(
            plan["blocked"],
            {
                "first": ["hook_collision:CMessageMgr.onRevokeMsg:"],
                "second": ["hook_collision:CMessageMgr.onRevokeMsg:"],
            },
        )

    def test_plan_allows_shared_hook_owner_and_marks_high_risk(self) -> None:
        modules = [
            {
                "id": "preview",
                "title": "Preview",
                "group": "messages",
                "compatible_versions": ["8.0.75"],
                "dependencies": [],
                "conflicts": [],
                "hooks": ["CMessageMgr.AsyncOnAddMsg:MsgWrap:"],
                "hook_owner": "feature-collection",
                "risk": "medium",
                "risk_reasons": [],
                "enabled": False,
            },
            {
                "id": "auto-reply",
                "title": "Auto reply",
                "group": "automation",
                "compatible_versions": ["8.0.75"],
                "dependencies": [],
                "conflicts": [],
                "hooks": ["CMessageMgr.AsyncOnAddMsg:MsgWrap:"],
                "hook_owner": "feature-collection",
                "risk": "high",
                "risk_reasons": ["automatic-message-send"],
                "enabled": False,
            },
        ]

        plan = build_activation_plan(
            modules,
            requested={"preview", "auto-reply"},
            version="8.0.75",
        )

        self.assertEqual(plan["enabled"], ["auto-reply", "preview"])
        self.assertEqual(plan["blocked"], {})
        self.assertEqual(plan["risk_flags"], {"auto-reply": ["automatic-message-send"]})

    def test_plan_blocks_a_module_until_its_evidence_gate_is_ready(self) -> None:
        modules = [
            {
                "id": "request-identity",
                "title": "Request identity",
                "group": "account",
                "runtime": "native-account",
                "compatible_versions": ["8.0.75"],
                "dependencies": [],
                "conflicts": [],
                "hooks": ["ManualAuthAesReqData.setBundleId:"],
                "hook_owner": "account-adapter",
                "risk": "critical",
                "risk_reasons": ["login-request-change"],
                "activation_gate": "fixture-validation-required",
                "enabled": False,
            }
        ]

        plan = build_activation_plan(
            modules,
            requested={"request-identity"},
            version="8.0.75",
        )

        self.assertEqual(plan["enabled"], [])
        self.assertEqual(
            plan["blocked"],
            {"request-identity": ["activation_gate:fixture-validation-required"]},
        )
