"""Tests for MCP protocol types."""
from behavry_proxy.proxy.mcp import (
    JsonRpcRequest,
    JsonRpcResponse,
    JsonRpcError,
    ToolCallParams,
    MCPServerConfig,
    ProxyResult,
)


def test_json_rpc_request_defaults():
    req = JsonRpcRequest(method="tools/call")
    assert req.jsonrpc == "2.0"
    assert req.id is None
    assert req.params is None


def test_json_rpc_request_full():
    req = JsonRpcRequest(id=1, method="tools/call", params={"name": "read_file"})
    assert req.id == 1
    assert req.params["name"] == "read_file"


def test_json_rpc_response_success():
    resp = JsonRpcResponse(id=1, result={"content": "hello"})
    assert resp.error is None
    assert resp.result["content"] == "hello"


def test_json_rpc_response_error():
    resp = JsonRpcResponse(
        id=1,
        error=JsonRpcError(code=-32001, message="Policy denied"),
    )
    assert resp.error.code == -32001
    assert resp.result is None


def test_tool_call_params():
    params = ToolCallParams(name="read_file", arguments={"path": "/tmp/test.txt"})
    assert params.name == "read_file"
    assert params.arguments["path"] == "/tmp/test.txt"


def test_tool_call_params_no_args():
    params = ToolCallParams(name="list_tools")
    assert params.arguments is None


def test_mcp_server_config_defaults():
    config = MCPServerConfig(id="test", name="Test Server")
    assert config.transport == "http"
    assert config.enabled is True
    assert config.url is None


def test_mcp_server_config_http():
    config = MCPServerConfig(
        id="github",
        name="GitHub",
        transport="http",
        url="http://localhost:3000",
    )
    assert config.url == "http://localhost:3000"


def test_proxy_result():
    result = ProxyResult(
        allowed=True,
        policy_result="allow",
        policy_reason="Read action allowed",
        policy_id="servers/github",
    )
    assert result.allowed is True
