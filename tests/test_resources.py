"""Tests for bundled policy/config resources and the `init` scaffold."""
from pathlib import Path

from behavry_proxy.resources import (
    bundled_compose_file,
    bundled_policies_dir,
    bundled_servers_example,
    find_servers_config,
    scaffold,
)


class TestBundledFiles:
    def test_policies_ship_with_the_package(self):
        """A pip install has no repo to read policies from, so they must be bundled."""
        policies = bundled_policies_dir()
        assert policies.is_dir()

        rego = list(policies.rglob("*.rego"))
        assert rego, "no .rego files bundled"
        assert (policies / "decision.rego").is_file()

    def test_every_bundled_policy_is_rego_v1(self):
        """
        OPA 1.x cannot parse Rego v0. `import rego.v1` (or no imports at all)
        keeps the bundle loadable on current OPA images.
        """
        for rego in bundled_policies_dir().rglob("*.rego"):
            text = rego.read_text()
            assert "import future.keywords" not in text, f"{rego.name} uses Rego v0 imports"

    def test_policies_use_the_deny_aggregation_contract(self):
        """
        Only decision.rego may define `decision`. Any other file defining it
        conflicts at eval time once two rules match the same request.
        """
        for rego in bundled_policies_dir().rglob("*.rego"):
            if rego.name == "decision.rego":
                continue
            for line in rego.read_text().splitlines():
                assert not line.startswith("decision :="), f"{rego.name} defines decision directly"
                assert not line.startswith("default decision"), f"{rego.name} defines decision directly"

    def test_config_and_compose_templates_ship(self):
        assert bundled_servers_example().is_file()
        assert bundled_compose_file().is_file()

    def test_compose_template_uses_real_env_var_names(self):
        """The proxy reads BEHAVRY_OPA_URL, not BEHAVRY_PROXY_OPA_URL."""
        text = bundled_compose_file().read_text()
        assert "BEHAVRY_OPA_URL" in text
        assert "BEHAVRY_PROXY_OPA_URL" not in text

    def test_bundled_servers_example_parses_and_is_inert(self):
        """A freshly scaffolded config must not register phantom backends."""
        import yaml

        from behavry_proxy.config import load_servers_yaml

        data = yaml.safe_load(bundled_servers_example().read_text())
        assert "servers" in data
        assert not data["servers"], "template ships with active server entries"
        assert load_servers_yaml(bundled_servers_example()) == []


class TestFindServersConfig:
    def test_explicit_path_wins_even_when_missing(self):
        """A bad --config should surface as a warning, not be silently ignored."""
        result = find_servers_config("/nope/servers.yaml")
        assert result == Path("/nope/servers.yaml")

    def test_finds_config_subdirectory(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "config").mkdir()
        (tmp_path / "config" / "servers.yaml").write_text("servers: []")
        assert find_servers_config() == Path("config/servers.yaml")

    def test_falls_back_to_cwd_servers_yaml(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "servers.yaml").write_text("servers: []")
        assert find_servers_config() == Path("servers.yaml")

    def test_returns_none_when_nothing_found(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert find_servers_config() is None


class TestScaffold:
    def test_writes_a_complete_setup(self, tmp_path):
        written, skipped = scaffold(tmp_path)

        assert not skipped
        assert (tmp_path / "config" / "servers.yaml").is_file()
        assert (tmp_path / "docker-compose.yml").is_file()
        assert (tmp_path / "policies" / "decision.rego").is_file()
        assert (tmp_path / "policies" / "servers" / "github.rego").is_file()

        # Everything reported as written is actually on disk, and nothing else is.
        assert all(p.is_file() for p in written)
        assert set(written) == {p for p in tmp_path.rglob("*") if p.is_file()}

    def test_does_not_clobber_existing_files(self, tmp_path):
        scaffold(tmp_path)
        edited = tmp_path / "policies" / "decision.rego"
        edited.write_text("# my edits\n")

        written, skipped = scaffold(tmp_path)

        assert not written
        assert edited in skipped
        assert edited.read_text() == "# my edits\n"

    def test_force_overwrites(self, tmp_path):
        scaffold(tmp_path)
        edited = tmp_path / "policies" / "decision.rego"
        edited.write_text("# my edits\n")

        written, skipped = scaffold(tmp_path, force=True)

        assert not skipped
        assert edited in written
        assert edited.read_text() != "# my edits\n"


class TestConfigDefaults:
    def test_policies_default_to_the_bundled_set(self, tmp_path, monkeypatch):
        """Without BEHAVRY_POLICIES_DIR there must still be valid policy to push."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("BEHAVRY_POLICIES_DIR", raising=False)
        monkeypatch.delenv("BEHAVRY_SERVERS_CONFIG", raising=False)

        from behavry_proxy.config import load_config

        cfg = load_config()
        assert cfg.policies_are_bundled is True
        assert Path(cfg.policies_dir) == bundled_policies_dir()

    def test_explicit_policies_dir_is_not_marked_bundled(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("BEHAVRY_POLICIES_DIR", str(tmp_path / "mine"))

        from behavry_proxy.config import load_config

        cfg = load_config()
        assert cfg.policies_are_bundled is False
        assert cfg.policies_dir == str(tmp_path / "mine")

    def test_missing_servers_config_is_not_fatal(self, tmp_path, monkeypatch):
        """Starting from an arbitrary cwd must warn, not crash."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("BEHAVRY_SERVERS_CONFIG", raising=False)

        from behavry_proxy.config import load_config

        cfg = load_config()
        assert cfg.servers == []
