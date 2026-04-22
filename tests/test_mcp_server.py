import json
from pathlib import Path

import anyio

# anyio is a Python library that provides a unified API for asynchronous programming, allowing you to write code that can run on different asynchronous frameworks (like asyncio, trio, etc.) without modification. In this test file, anyio is used to run asynchronous functions that interact with the MCP server.

from vuln_validator.mcp_server import mcp

FIXTURE_BINARY = Path("tests/fixtures/stack_overflow/gets_local")


def test_mcp_registration_exposes_expected_tool_and_prompt() -> None:
    """
    This test validates the integration of the MCP server with the vulnerability analysis tool. It checks that the prompt and tool are registered correctly.
    """

    async def _collect():
        tools = await mcp.list_tools()
        prompts = await mcp.list_prompts()
        return tools, prompts

    tools, prompts = anyio.run(_collect)

    assert len(tools) == 1
    assert tools[0].name == "validate_vulnerability"
    assert "target_path" in tools[0].inputSchema["properties"]
    assert "vulnerability_type" in tools[0].inputSchema["properties"]

    assert len(prompts) == 1
    assert prompts[0].name == "find_vulnerability_workflow"


def test_mcp_prompt_renders_target_path() -> None:
    """
    This test checks that the prompt correctly renders the target path and includes instructions to call the validation tool.
    """

    async def _render_prompt():
        rendered = await mcp.get_prompt(
            "find_vulnerability_workflow",
            {"target_path": str(FIXTURE_BINARY)},
        )
        return rendered.messages[0].content.text

    prompt_text = anyio.run(_render_prompt)

    assert str(FIXTURE_BINARY) in prompt_text
    assert "tests/fixtures/stack_overflow/gets_local" in prompt_text


def test_validate_vulnerability_tool_end_to_end() -> None:
    """
    This test performs an end-to-end validation of the `validate_vulnerability` tool by running it against a known vulnerable binary and checking the results.
    """
    assert FIXTURE_BINARY.exists(), f"Missing fixture binary: {FIXTURE_BINARY}"

    async def _call_tool():
        return await mcp.call_tool(
            "validate_vulnerability",
            {
                "target_path": str(FIXTURE_BINARY),
                "target_function": "vulnerable_function",
                "vulnerability_type": "stack_overflow",
            },
        )

    content_blocks = anyio.run(_call_tool)

    assert isinstance(content_blocks, list)
    assert content_blocks, "MCP tool returned no content blocks"
    assert hasattr(content_blocks[0], "text")

    payload = json.loads(content_blocks[0].text)
    assert payload["is_vulnerable"] is True
    assert payload["requested_type"] == "stack_overflow"
    assert isinstance(payload.get("analyzed_types"), list)
    assert payload["analyzed_types"]

    evidence_list = payload.get("evidence")
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
        return await mcp.call_tool(
            "validate_vulnerability",
            {
                "target_path": "/path/to/nonexistent/file",
                "vulnerability_type": "auto",
            },
        )

    content_blocks = anyio.run(_call_tool)

    assert isinstance(content_blocks, list)
    assert content_blocks
    assert hasattr(content_blocks[0], "text")

    payload = json.loads(content_blocks[0].text)
    assert "error" in payload
    assert payload["error"] == "FileNotFound"


def test_validate_vulnerability_tool_with_source_code_but_no_binary() -> None:
    """
    This test checks that the `validate_vulnerability` tool handles the case of a source code file without a corresponding binary gracefully, returning an appropriate error message.
    """
    source_code_path = Path("tests/fixtures/error_cases/missing_binary.c")
    assert source_code_path.exists(), f"Missing fixture source code: {source_code_path}"

    async def _call_tool():
        return await mcp.call_tool(
            "validate_vulnerability",
            {
                "target_path": str(source_code_path),
                "vulnerability_type": "auto",
            },
        )

    content_blocks = anyio.run(_call_tool)

    assert isinstance(content_blocks, list)
    assert content_blocks
    assert hasattr(content_blocks[0], "text")

    payload = json.loads(content_blocks[0].text)
    assert "error" in payload
    assert payload["error"] == "FileNotFound"


# TODO: Mehr Testfälle (spezifisch stack_overflow, heap_overflow, format_string) mit verschiedenen Binärdateien, um die Genauigkeit und Robustheit der Analyse zu überprüfen.
