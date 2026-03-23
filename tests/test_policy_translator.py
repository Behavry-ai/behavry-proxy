"""Tests for tool call → OPA input translation."""
from behavry_proxy.policy.translator import extract_action, extract_resource


class TestExtractAction:
    def test_underscore_separator(self):
        assert extract_action("read_file") == "read"

    def test_dash_separator(self):
        assert extract_action("create-issue") == "create"

    def test_slash_separator(self):
        assert extract_action("tools/call") == "tools"

    def test_no_separator(self):
        assert extract_action("search") == "search"


class TestExtractResource:
    def test_from_parameters_path(self):
        assert extract_resource("read_file", {"path": "/tmp/test.txt"}) == "/tmp/test.txt"

    def test_from_parameters_repo(self):
        assert extract_resource("create_issue", {"repo": "behavry/proxy"}) == "behavry/proxy"

    def test_from_parameters_url(self):
        assert extract_resource("fetch_page", {"url": "https://example.com"}) == "https://example.com"

    def test_fallback_to_tool_name_noun(self):
        assert extract_resource("read_file") == "file"

    def test_fallback_multi_word(self):
        assert extract_resource("create_pull_request") == "pull_request"

    def test_no_separator(self):
        assert extract_resource("search") == "search"

    def test_empty_param_falls_back(self):
        assert extract_resource("read_file", {"path": ""}) == "file"
