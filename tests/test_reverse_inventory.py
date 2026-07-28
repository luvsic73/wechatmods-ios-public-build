import unittest

from wechat_ipa_audit.reverse_inventory import parse_logos_hooks


class ParseLogosHooksTests(unittest.TestCase):
    def test_decodes_instance_and_class_method_selectors_and_deduplicates(self) -> None:
        symbols = [
            "__ZL61_logos_orig$_ungrouped$WCPluginsViewController$viewDidAppear$",
            "__ZL92_logos_meta_orig$_ungrouped$WCTableViewCellManager$"
            "normalCellForSel$target$title$rightValue$",
            "__ZL61_logos_orig$_ungrouped$WCPluginsViewController$viewDidAppear$",
            "__ZL50_logos_meta_method$_ungrouped$NSURL$URLWithString$P10objc_class",
        ]

        self.assertEqual(
            parse_logos_hooks(symbols),
            [
                {
                    "class": "NSURL",
                    "selector": "URLWithString:",
                    "method_type": "class",
                },
                {
                    "class": "WCPluginsViewController",
                    "selector": "viewDidAppear:",
                    "method_type": "instance",
                },
                {
                    "class": "WCTableViewCellManager",
                    "selector": "normalCellForSel:target:title:rightValue:",
                    "method_type": "class",
                },
            ],
        )
