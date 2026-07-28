from __future__ import annotations

import json
import urllib.parse
import urllib.request
from pathlib import Path


BASE = "http://127.0.0.1:8089"
ROOT = Path(__file__).resolve().parents[1]

TARGETS = [
    {
        "program": "5efaee04e485-WCFix27LoginQR.dylib",
        "constructors": [
            ("0x4000", "InitializeWcfixLoginQr"),
            ("0x4034", "HandleOnGetQrCodeImage"),
        ],
        "string_pattern": "(?i)login|qr|scan|hook",
    },
    {
        "program": "eaa8110f246c-PKCWeChatTools.dylib",
        "constructors": [("0x152814", "InitializePkc")],
        "string_pattern": (
            "(?i)api\\.|openai|deepseek|siliconflow|authorization|bearer|"
            "pasteboard|clipboard|keychain|token"
        ),
    },
    {
        "program": "8fdf485a5170-xnsp.dylib",
        "constructors": [
            ("0x5cadc", "InitializeXnspPart1"),
            ("0x85678", "InitializeXnspPart2"),
            ("0x8a9b8", "InitializeXnspPart3"),
            ("0x8ab24", "InitializeXnspPart4"),
            ("0xa9684", "InitializeXnspPart5"),
            ("0xa97a8", "InitializeXnspPart6"),
            ("0xbf140", "InitializeXnspPart7"),
        ],
        "string_pattern": (
            "(?i)122\\.114|124\\.222|43\\.143|wqwlkj|e-jt|fengchuan|"
            "wx\\.plus|ptrace|sysctl|pasteboard|clipboard|token|keychain"
        ),
    },
    {
        "program": "36efdd3a4794-HBB9.1.2.dylib",
        "constructors": [("0x4000", "InitializeHbb")],
        "string_pattern": (
            "(?i)ptrace|sysctl|pasteboard|clipboard|token|keychain|"
            "login|session|http"
        ),
    },
]


def get(endpoint: str, **query) -> str:
    url = BASE + endpoint + "?" + urllib.parse.urlencode(query)
    with urllib.request.urlopen(url, timeout=180) as response:
        return response.read().decode("utf-8")


def post(endpoint: str, program: str, body: dict) -> str:
    url = BASE + endpoint + "?" + urllib.parse.urlencode({"program": program})
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        return response.read().decode("utf-8")


def json_or_text(value: str):
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def main() -> None:
    results = {
        "schema_version": 1,
        "ghidra_version": "12.1.2",
        "mcp_extension_version": "5.17.0",
        "targets": [],
    }
    for target in TARGETS:
        row = {
            "program": target["program"],
            "constructors": [],
            "strings": json_or_text(
                get(
                    "/search_strings",
                    program=target["program"],
                    search_term=target["string_pattern"],
                    limit=500,
                )
            ),
            "api_call_chains": json_or_text(
                get("/analyze_api_call_chains", program=target["program"])
            ),
        }
        for address, name in target["constructors"]:
            creation = json_or_text(
                post(
                    "/create_function",
                    target["program"],
                    {
                        "address": address,
                        "name": name,
                        "disassemble_first": True,
                    },
                )
            )
            decompile = get(
                "/decompile_function",
                program=target["program"],
                address=address,
                timeout=120,
            )
            row["constructors"].append(
                {
                    "address": address,
                    "name": name,
                    "creation": creation,
                    "decompile": decompile,
                }
            )
        results["targets"].append(row)
    destination = ROOT / "reports" / "ghidra-priority-raw.json"
    destination.write_text(
        json.dumps(results, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(destination)


if __name__ == "__main__":
    main()
