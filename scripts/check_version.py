"""
Assert every place that declares the package version agrees.

The version lives in four places, and a release that disagrees between them
publishes inconsistent metadata — or fails MCP registry validation, which
matches server.json against what is actually on PyPI.

Usage:
    python scripts/check_version.py              # just check they agree
    python scripts/check_version.py --expect 0.1.0
    python scripts/check_version.py --expect-tag v0.1.0
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _pyproject() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    return data["project"]["version"]


def _dunder() -> str:
    text = (ROOT / "behavry_proxy" / "__init__.py").read_text()
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if not match:
        raise SystemExit("could not find __version__ in behavry_proxy/__init__.py")
    return match.group(1)


def _server_json() -> dict[str, str]:
    data = json.loads((ROOT / "server.json").read_text())
    found = {"server.json version": data["version"]}
    for package in data.get("packages", []):
        label = f"server.json packages[{package.get('identifier', '?')}].version"
        found[label] = package["version"]
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect", help="Version every site must equal")
    parser.add_argument("--expect-tag", help="Git tag (a leading 'v' is stripped)")
    args = parser.parse_args()

    versions = {
        "pyproject.toml [project].version": _pyproject(),
        "behavry_proxy/__init__.py __version__": _dunder(),
        **_server_json(),
    }

    width = max(len(k) for k in versions)
    for site, value in versions.items():
        print(f"  {site:<{width}}  {value}")

    distinct = set(versions.values())
    if len(distinct) != 1:
        print(f"\nversion mismatch: {sorted(distinct)}", file=sys.stderr)
        return 1

    actual = distinct.pop()

    expected = args.expect
    if args.expect_tag:
        expected = args.expect_tag.removeprefix("refs/tags/").removeprefix("v")

    if expected and actual != expected:
        print(
            f"\nexpected {expected!r} but the package declares {actual!r}\n"
            "Bump the version in all four places before tagging.",
            file=sys.stderr,
        )
        return 1

    print(f"\nversion {actual} is consistent" + (f" and matches {expected}" if expected else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
