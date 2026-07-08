import sys
import logging
import asyncio
from pathlib import Path
import json
from typing import List, Any, Dict

from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession

from vuln_validator.utils.logging_config import setup_logging


async def run_analysis_cli(
    binary_path: str,
    target_function: str = None,
    vuln_type: str = "auto",
    function_args: List[Any] = None,
    structs: List[Dict[str, Any]] = None,
):
    logger = logging.getLogger("vuln_validator.mcp_client")
    # Define Server parameters (must match the Claude config)
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "vuln_validator.mcp_server"],
        cwd=str(Path(__file__).parent.parent),  # Project root
    )

    logger.info(f"Connecting to MCP Server for binary path: {binary_path}")

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # 1. Initialize Session
            await session.initialize()
            logger.info("Session initialized.")

            # 2. List Tools
            tools = await session.list_tools()
            tool_names = [t.name for t in tools.tools]
            logger.debug(f"Available tools: {tool_names}")

            if "validate_vulnerability" not in tool_names:
                logger.error("Tool 'validate_vulnerability' not found on server!")
                return

            # 3. Call the Tool
            logger.debug(f"Calling validate_vulnerability for {binary_path}")

            arguments = {
                "target_path": str(Path(binary_path).resolve()),
            }
            if target_function:
                arguments["target_function"] = target_function
            if vuln_type:
                arguments["vulnerability_type"] = vuln_type
            if function_args:
                arguments["function_args"] = function_args
            if structs:
                arguments["structs"] = structs

            result = await session.call_tool("validate_vulnerability", arguments)

            # 4. Process Result
            if result.isError:
                logger.error(
                    "Tool execution failed! Details: session.call_tool returned an error."
                )
                for content in result.content:
                    if hasattr(content, "text"):
                        logger.error(f"Error content: {content.text}")
                return

            # Output parsing
            for content in result.content:
                if hasattr(content, "text"):
                    logger.info("Received tool output:")
                    data = json.loads(content.text)
                    logger.info(json.dumps(data, indent=2))


def main():
    setup_logging()
    logger = logging.getLogger("vuln_validator.run_direct_analysis")
    default_binary_path = "tests/fixtures/stack_overflow/gets_local"
    if len(sys.argv) < 2:
        logger.warning("No code path provided. Using default: %s", default_binary_path)

    binary_path = sys.argv[1] if len(sys.argv) > 1 else default_binary_path
    target_function = sys.argv[2] if len(sys.argv) > 2 else None
    vuln_type = sys.argv[3] if len(sys.argv) > 3 else "auto"
    function_args = json.loads(sys.argv[4]) if len(sys.argv) > 4 else None
    structs = json.loads(sys.argv[5]) if len(sys.argv) > 5 else None

    asyncio.run(
        run_analysis_cli(
            binary_path, target_function, vuln_type, function_args, structs
        )
    )


if __name__ == "__main__":
    main()
