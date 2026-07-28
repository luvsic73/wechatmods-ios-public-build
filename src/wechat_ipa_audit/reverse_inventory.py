from __future__ import annotations

import re
from collections.abc import Iterable


_LOGOS_ORIG = re.compile(
    r"_logos_(?P<meta>meta_)?orig\$_ungrouped\$"
    r"(?P<class>[^$]+)\$(?P<selector>.*)$"
)
_LOGOS_METHOD = re.compile(
    r"_logos_(?P<meta>meta_)?method\$_ungrouped\$"
    r"(?P<class>[^$]+)\$(?P<body>.*)$"
)


def parse_logos_hooks(symbols: Iterable[str]) -> list[dict[str, str]]:
    """Decode unique Logos hook targets from their original-IMP symbols."""
    hooks: set[tuple[str, str, str]] = set()
    for symbol in symbols:
        match = _LOGOS_ORIG.search(symbol)
        if match:
            selector = match.group("selector").replace("$", ":")
        else:
            match = _LOGOS_METHOD.search(symbol)
            if not match:
                continue
            body = match.group("body")
            self_type = (
                re.search(r"P10objc_class", body)
                if match.group("meta")
                else re.search(rf"P\d+{re.escape(match.group('class'))}", body)
            )
            if not self_type:
                continue
            selector = body[: self_type.start()].replace("$", ":")
        hooks.add(
            (
                match.group("class"),
                selector,
                "class" if match.group("meta") else "instance",
            )
        )
    return [
        {"class": class_name, "selector": selector, "method_type": method_type}
        for class_name, selector, method_type in sorted(hooks)
    ]
