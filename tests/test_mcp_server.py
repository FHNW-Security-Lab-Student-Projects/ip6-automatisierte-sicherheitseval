import json
from pathlib import Path
import anyio
import pytest

# anyio is a Python library that provides a unified API for asynchronous programming, allowing you to write code that can run on different asynchronous frameworks (like asyncio, trio, etc.) without modification. In this test file, anyio is used to run asynchronous functions that interact with the MCP server.

from vuln_validator.mcp_server import mcp

FIXTURE_BINARY = Path("tests/fixtures/stack_overflow/gets_local")

pytestmark = pytest.mark.integration


def test_mcp_registration_exposes_expected_tool_and_prompt() -> None:
    """
    This test validates the integration of the MCP server with the vulnerability analysis tool. It checks that the prompt and tool are registered correctly.
    """

    async def _collect():
        tools = await mcp.list_tools()
        return tools

    tools = anyio.run(_collect)

    assert len(tools) == 2
    assert tools[0].name == "start_validation"
    assert tools[1].name == "get_validation_result"
    assert "target_path" in tools[0].inputSchema["properties"]
    assert "vulnerability_type" in tools[0].inputSchema["properties"]


def _payload_from_tool_result(tool_result):
    assert isinstance(tool_result, list)
    assert tool_result
    assert hasattr(tool_result[0], "text")
    return json.loads(tool_result[0].text)


def test_validate_vulnerability_tool_end_to_end(set_config) -> None:
    """
    This test performs an end-to-end validation of the `validate_vulnerability` tool by running it against a known vulnerable binary and checking the results.
    """
    assert FIXTURE_BINARY.exists(), f"Missing fixture binary: {FIXTURE_BINARY}"
    set_config()

    async def _call_tool():
        start_blocks = await mcp.call_tool(
            "start_validation",
            {
                "target_path": str(FIXTURE_BINARY),
                "target_function": "vulnerable_function",
                "vulnerability_type": "stack_overflow",
            },
        )
        start_payload = _payload_from_tool_result(start_blocks)
        job_id = start_payload["job_id"]

        result_blocks = await mcp.call_tool("get_validation_result", {"job_id": job_id})
        return _payload_from_tool_result(result_blocks)

    payload = anyio.run(_call_tool)

    assert payload["status"] == "done"
    result = payload["result"]

    assert result["is_vulnerable"] is True
    assert result["requested_type"] == "stack_overflow"
    assert isinstance(result.get("analyzed_types"), list)
    assert result["analyzed_types"]

    evidence_list = result.get("evidence")
    assert isinstance(evidence_list, list)
    assert evidence_list

    first_item = evidence_list[0]
    assert "state_type" in first_item
    assert "input_hex" in first_item
    assert first_item.get("source_solver") == "stack_overflow"


def test_validate_vulnerability_tool_with_nonexistent_file() -> None:
    """
    This test checks that the `validate_vulnerability` tool handles the case of a non-existent file gracefully, returning an appropriate error message.
    """

    async def _call_tool():
        start_blocks = await mcp.call_tool(
            "start_validation",
            {
                "target_path": "/path/to/nonexistent/file",
                "vulnerability_type": "auto",
            },
        )
        start_payload = _payload_from_tool_result(start_blocks)
        job_id = start_payload["job_id"]

        result_blocks = await mcp.call_tool("get_validation_result", {"job_id": job_id})
        return _payload_from_tool_result(result_blocks)

    payload = anyio.run(_call_tool)

    assert payload["status"] == "error"
    assert payload["error"] == "FileNotFound"


def test_validate_vulnerability_tool_with_source_code_but_no_binary() -> None:
    """
    This test checks that the `validate_vulnerability` tool handles the case of a source code file without a corresponding binary gracefully, returning an appropriate error message.
    """
    source_code_path = Path("tests/fixtures/error_cases/missing_binary.c")
    assert source_code_path.exists(), f"Missing fixture source code: {source_code_path}"

    async def _call_tool():
        start_blocks = await mcp.call_tool(
            "start_validation",
            {
                "target_path": str(source_code_path),
                "vulnerability_type": "auto",
            },
        )
        start_payload = _payload_from_tool_result(start_blocks)
        job_id = start_payload["job_id"]

        result_blocks = await mcp.call_tool("get_validation_result", {"job_id": job_id})
        return _payload_from_tool_result(result_blocks)

    payload = anyio.run(_call_tool)

    assert payload["status"] == "error"
    assert payload["error"] == "FileNotFound"
