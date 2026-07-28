import unittest

from wechat_ipa_audit.inventory import select_current_targets


class InventoryTests(unittest.TestCase):
    def test_selects_current_stable_and_quarantines_beta_claims(self) -> None:
        entries = [
            {"name": "微信_8.0.75_仅砸壳.ipa", "version": "8.0.75"},
            {"name": "微信_8.0.75防风版2.ipa", "version": "8.0.75"},
            {"name": "微信8.0.76.ipa", "version": "8.0.76"},
            {"name": "微信8.0.74.ipa", "version": "8.0.74"},
        ]

        selected = select_current_targets(entries, stable_version="8.0.75")

        self.assertEqual(
            [item["name"] for item in selected["deep_audit"]],
            ["微信_8.0.75_仅砸壳.ipa", "微信_8.0.75防风版2.ipa"],
        )
        self.assertEqual(
            [item["name"] for item in selected["quarantine"]],
            ["微信8.0.76.ipa"],
        )
        self.assertEqual(
            [item["name"] for item in selected["regression"]],
            ["微信8.0.74.ipa"],
        )

