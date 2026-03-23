"""
Tool call → OPA input document translator.

Extracts action and resource from MCP tool call parameters to build
the OPA input document. Simple heuristic-based extraction.
"""
from __future__ import annotations

from typing import Any


def extract_action(tool_name: str) -> str:
    """Extract action verb from tool name.

    Follows MCP convention where tool names use verb_noun or verb-noun format.
    Falls back to the full tool name if no separator found.
    """
    # Common patterns: read_file, create_issue, list_repos
    for sep in ("_", "-", "/"):
        if sep in tool_name:
            return tool_name.split(sep)[0]
    return tool_name


def extract_resource(tool_name: str, parameters: dict[str, Any] | None = None) -> str:
    """Extract resource identifier from tool name and parameters.

    Checks common parameter names for path/resource identifiers.
    Falls back to the noun portion of the tool name.
    """
    # Check parameters for resource hints
    if parameters:
        for key in ("path", "file", "url", "resource", "repo", "repository",
                     "channel", "database", "table", "collection", "bucket"):
            if key in parameters:
                val = parameters[key]
                if isinstance(val, str) and val:
                    return val

    # Fall back to noun from tool name
    for sep in ("_", "-", "/"):
        if sep in tool_name:
            parts = tool_name.split(sep)
            return sep.join(parts[1:])  # everything after the verb
    return tool_name
