import sys
import time
import logging
import asyncio
from pathlib import Path
import json
from typing import List, Any, Dict

from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession

from vuln_validator.utils.logging_config import setup_logging


async def _call_json(session: ClientSession, name: str, arguments: dict, logger):
    """Ruft ein Tool auf und gibt dessen JSON-Antwort als dict zurück."""
    result = await session.call_tool(name, arguments)
    if result.isError:
        msgs = [c.text for c in result.content if hasattr(c, "text")]
        raise RuntimeError(f"Tool '{name}' failed: {' '.join(msgs) or '(no detail)'}")
    for content in result.content:
        if hasattr(content, "text"):
            return json.loads(content.text)
    raise RuntimeError(f"Tool '{name}' returned no text content.")


async def run_analysis_cli(
    binary_path: str,
    target_function: str = None,
    vuln_type: str = "auto",
    function_args: List[Any] = None,
    structs: List[Dict[str, Any]] = None,
    poll_interval: float = 5.0,  # Seconds between polling attempts (client-side)
    max_wait_seconds: float = 600.0,  # Total time to wait for the analysis result (client-side)
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

            for required in ("start_validation", "get_validation_result"):
                if required not in tool_names:
                    logger.error(f"Tool '{required}' not found on server!")
                    return

            # 3. Phase 1: Start the analysis job
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

            logger.debug(f"Calling start_validation for {binary_path}")
            start = await _call_json(session, "start_validation", arguments, logger)
            job_id = start.get("job_id")
            if not job_id:
                logger.error(f"start_validation returned no job_id: {start}")
                return
            logger.info(f"Job started (job_id={job_id}, status={start.get('status')})")

            # 4. Phase 2: Poll for the result until done or timeout
            deadline = time.monotonic() + max_wait_seconds
            elapsed_start = time.monotonic()
            while True:
                await asyncio.sleep(poll_interval)

                res = await _call_json(
                    session, "get_validation_result", {"job_id": job_id}, logger
                )
                status = res.get("status")

                if status == "running":
                    waited = int(time.monotonic() - elapsed_start)
                    logger.info(f"… still running ({waited}s elapsed)")
                    if time.monotonic() > deadline:
                        logger.error(
                            f"Client deadline of {max_wait_seconds:.0f}s reached, "
                            f"giving up (job {job_id} still running on server)."
                        )
                        return
                    continue

                if status == "done":
                    total = int(time.monotonic() - elapsed_start)
                    logger.info(f"Analysis finished after ~{total}s. Result:")
                    logger.info(json.dumps(res.get("result"), indent=2))
                    return

                if status == "error":
                    logger.error(
                        f"Analysis error [{res.get('error')}]: {res.get('message')}"
                    )
                    return

                if status == "unknown":
                    logger.error(
                        f"Job unknown (server restarted?): {res.get('message')}"
                    )
                    return

                logger.error(f"Unexpected status from server: {res}")
                return


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
