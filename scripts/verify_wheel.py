"""
Post-install smoke check for a built wheel.

Run with the *installed* interpreter, from a directory outside the checkout,
so the source tree cannot shadow the installed package:

    python -m venv /tmp/clean
    /tmp/clean/bin/pip install dist/*.whl
    cd /tmp/elsewhere && /tmp/clean/bin/python .../scripts/verify_wheel.py

Every assertion here corresponds to a way the package has actually broken:
a dependency the code imports but pyproject never declared, and data files
the code reads at runtime but the wheel never shipped.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

FAILURES: list[str] = []
SKIPPED: list[str] = []

# CI passes this so a missing opa is a failure there rather than a quiet skip,
# while a local run without opa installed still exercises everything else.
REQUIRE_OPA = "--require-opa" in sys.argv


def check(label: str, fn) -> None:
    try:
        detail = fn()
    except Exception as exc:  # noqa: BLE001 - report, do not abort
        FAILURES.append(f"{label}: {type(exc).__name__}: {exc}")
        print(f"  FAIL  {label}: {type(exc).__name__}: {exc}")
    else:
        if isinstance(detail, str) and detail.startswith("SKIPPED"):
            SKIPPED.append(f"{label}: {detail}")
            print(f"  skip  {label}: {detail}")
        else:
            print(f"  ok    {label}{f' ({detail})' if detail else ''}")


def installed_not_source() -> str:
    import behavry_proxy

    location = Path(behavry_proxy.__file__).resolve().parent
    assert "site-packages" in location.parts, f"resolved to the source tree: {location}"
    return str(location)


def tui_imports() -> str:
    """rich is a real dependency — the terminal dashboard imports it."""
    from behavry_proxy.tui import dashboard  # noqa: F401

    return "rich available"


def metrics_without_prometheus() -> str:
    """metrics.py renders the Prometheus format itself; no client library needed."""
    from behavry_proxy import metrics

    text = metrics.ProxyMetrics().to_prometheus()
    assert "behavry_proxy_tool_calls_total" in text
    for forbidden in ("prometheus_client",):
        assert forbidden not in sys.modules, f"{forbidden} was imported"
    return f"{len(text.splitlines())} lines"


def app_imports() -> str:
    from behavry_proxy.main import app

    assert app.title == "Behavry Proxy", app.title
    return app.title


def bundled_resources() -> str:
    from behavry_proxy.resources import (
        bundled_compose_file,
        bundled_policies_dir,
        bundled_servers_example,
    )

    policies = bundled_policies_dir()
    assert "site-packages" in str(policies), f"not from the wheel: {policies}"
    assert policies.is_dir(), f"missing: {policies}"

    rego = sorted(p.name for p in policies.rglob("*.rego"))
    assert "decision.rego" in rego, rego
    assert len(rego) >= 8, f"expected the full reference set, got {rego}"

    assert bundled_servers_example().is_file()
    assert bundled_compose_file().is_file()
    return f"{len(rego)} policies + 2 templates"


def installed_policies_parse() -> str:
    """
    Ask OPA to parse the policies *as installed*, which is the only check here
    that the `opa check` CI step cannot make — that step only ever sees the
    checkout, and shadowing by the source tree is the whole reason this script
    exists.

    Grepping for `import future.keywords` is not a substitute: a Rego v0 file
    without that import parses as v0 regardless, and the import is a legal
    no-op under v1, so it is unreliable in both directions.
    """
    import subprocess

    from behavry_proxy.resources import bundled_policies_dir

    policies = bundled_policies_dir()
    opa = shutil.which("opa")
    if opa is None:
        if REQUIRE_OPA:
            raise AssertionError("opa is not on PATH and --require-opa was given")
        return "SKIPPED - opa not on PATH"

    proc = subprocess.run(
        [opa, "check", "--strict", str(policies)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        f"opa check --strict failed on the installed policies at {policies}:\n"
        f"{(proc.stderr or proc.stdout).strip()}"
    )
    return f"opa check --strict clean ({len(list(policies.rglob('*.rego')))} files)"


def init_scaffolds(tmp: Path) -> str:
    from behavry_proxy.resources import scaffold

    written, skipped = scaffold(tmp)
    assert not skipped, skipped
    for expected in (
        "config/servers.yaml",
        "docker-compose.yml",
        "policies/decision.rego",
        "policies/servers/github.rego",
    ):
        assert (tmp / expected).is_file(), f"init did not create {expected}"
    return f"{len(written)} files"


def main() -> int:
    import tempfile

    # Every check below is an assert, so under -O they all vanish and this
    # script would exit 0 having verified nothing.
    if not __debug__:
        print("ERROR: run without -O; every check in this script is an assert")
        return 1

    print(f"verifying wheel with {sys.executable}")
    check("installed from wheel, not source", installed_not_source)
    check("TUI imports (rich)", tui_imports)
    check("metrics needs no prometheus-client", metrics_without_prometheus)
    check("FastAPI app imports", app_imports)
    check("bundled policies and templates ship", bundled_resources)
    check("installed policies parse on OPA", installed_policies_parse)

    with tempfile.TemporaryDirectory() as tmp:
        check("init scaffolds a full setup", lambda: init_scaffolds(Path(tmp)))

    if FAILURES:
        print(f"\n{len(FAILURES)} check(s) failed")
        return 1
    if SKIPPED:
        # Not a failure, but do not let it read as a clean run.
        print(f"\nall checks passed, {len(SKIPPED)} skipped:")
        for entry in SKIPPED:
            print(f"  - {entry}")
        return 0
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
