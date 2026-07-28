from __future__ import annotations

import argparse
import json
from pathlib import Path

import yara


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--rules", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    rules = yara.compile(filepath=args.rules)
    root = Path(args.directory).resolve()
    results = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        matches = rules.match(data=path.read_bytes(), timeout=30)
        results.append(
            {
                "file": str(path.relative_to(root)),
                "matches": [
                    {
                        "rule": match.rule,
                        "namespace": match.namespace,
                        "tags": list(match.tags),
                        "meta": dict(match.meta),
                    }
                    for match in matches
                ],
            }
        )

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(results, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
