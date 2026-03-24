import json
from pathlib import Path

import anyio
# anyio is a Python library that provides a unified API for asynchronous programming, allowing you to write code that can run on different asynchronous frameworks (like asyncio, trio, etc.) without modification. In this test file, anyio is used to run asynchronous functions that interact with the MCP server.

from vuln_validator.mcp_server import mcp


FIXTURE_BINARY = Path(__file__).parent / "fixtures" / "2_buffer_overflow"

# This test validates the integration of the MCP server with the vulnerability analysis tool. It checks that the prompt and tool are registered correctly.
def test_mcp_registration_exposes_expected_tool_and_prompt() -> None:
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

# This test checks that the prompt correctly renders the target path and includes instructions to call the validation tool.
def test_mcp_prompt_renders_target_path() -> None:
    async def _render_prompt():
        rendered = await mcp.get_prompt(
            "find_vulnerability_workflow",
            {"target_path": str(FIXTURE_BINARY)},
        )
        return rendered.messages[0].content.text

    prompt_text = anyio.run(_render_prompt)

    assert str(FIXTURE_BINARY) in prompt_text
    assert "MUST call the tool `validate_vulnerability`" in prompt_text

# This test performs an end-to-end validation of the `validate_vulnerability` tool by running it against a known vulnerable binary and checking the results.
def test_validate_vulnerability_tool_end_to_end() -> None:
    assert FIXTURE_BINARY.exists(), f"Missing fixture binary: {FIXTURE_BINARY}"

    async def _call_tool():
        return await mcp.call_tool(
            "validate_vulnerability",
            {
                "target_path": str(FIXTURE_BINARY),
                "vulnerability_type": "auto",
            },
        )

    content_blocks = anyio.run(_call_tool)

    assert isinstance(content_blocks, list)
    assert content_blocks, "MCP tool returned no content blocks"
    assert hasattr(content_blocks[0], "text")

    payload = json.loads(content_blocks[0].text)
    assert payload["is_vulnerable"] is True
    assert payload["type"] in {"stack_overflow", "heap_overflow", "format_string"}
    assert isinstance(payload.get("evidence"), dict)
    assert isinstance(payload.get("message"), str)

# TODO: Mehr Testfälle (spezifisch stack_overflow, heap_overflow, format_string) mit verschiedenen Binärdateien, um die Genauigkeit und Robustheit der Analyse zu überprüfen.
# TODO: Testfälle binaries und source code, um die Fähigkeit der Analyse zu überprüfen, mit verschiedenen Eingabeformaten umzugehen.
# TODO: Testfälle mit nicht-vulnerable binaries, um sicherzustellen, dass die Analyse keine False Positives produziert.
