"""
Locating the data files shipped inside the wheel.

A pip-installed proxy has no repository to read policies or server config
from, so both ship inside the package under ``behavry_proxy/bundled`` and are
resolved through :mod:`importlib.resources`. ``behavry-proxy init`` copies
them into the working directory when a user wants to edit them.
"""
from __future__ import annotations

import shutil
from importlib import resources
from pathlib import Path

# Where load_config() looks for servers.yaml when nothing is configured,
# relative to the current working directory, in order.
SERVERS_CONFIG_SEARCH_PATH: tuple[str, ...] = (
    "config/servers.yaml",
    "servers.yaml",
)


def bundled_dir() -> Path:
    """Filesystem path to the bundled data directory."""
    return Path(str(resources.files("behavry_proxy.bundled")))


def bundled_policies_dir() -> Path:
    """Filesystem path to the reference Rego policies shipped with the package."""
    return bundled_dir() / "policies"


def bundled_servers_example() -> Path:
    """Filesystem path to the annotated servers.yaml template."""
    return bundled_dir() / "servers.yaml.example"


def bundled_compose_file() -> Path:
    """Filesystem path to the docker-compose.yml template (proxy + OPA)."""
    return bundled_dir() / "docker-compose.yml"


def find_servers_config(explicit: str | None = None) -> Path | None:
    """
    Resolve the servers.yaml to load.

    ``explicit`` (from --config / BEHAVRY_SERVERS_CONFIG) wins and is returned
    even when missing, so the caller can warn about the path the user actually
    asked for. Otherwise the search path is tried against the working
    directory. Returns None when nothing is found.
    """
    if explicit:
        return Path(explicit)

    for candidate in SERVERS_CONFIG_SEARCH_PATH:
        path = Path(candidate)
        if path.is_file():
            return path
    return None


def scaffold(target: Path, *, force: bool = False) -> tuple[list[Path], list[Path]]:
    """
    Copy the bundled policies, servers.yaml and docker-compose.yml into ``target``.

    Returns (written, skipped). Existing files are left alone unless ``force``
    is set, so re-running init never silently discards edited policies.
    """
    written: list[Path] = []
    skipped: list[Path] = []

    def _copy(src: Path, dest: Path) -> None:
        if dest.exists() and not force:
            skipped.append(dest)
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        written.append(dest)

    _copy(bundled_servers_example(), target / "config" / "servers.yaml")
    _copy(bundled_compose_file(), target / "docker-compose.yml")

    policies_root = bundled_policies_dir()
    for rego in sorted(policies_root.rglob("*.rego")):
        _copy(rego, target / "policies" / rego.relative_to(policies_root))

    return written, skipped
