import asyncio
import uuid
from mcp.server.fastmcp import FastMCP
from typing import List, Any, Dict

from vuln_validator.utils.logging_config import setup_logging
from vuln_validator.core.angr_analyzer import AngrAnalyzer

# from vuln_validator.utils.audit_logger import audit_log

mcp = FastMCP("VulnValidator")

# In-Memory-Job-Register (lives as long as the server process is running). Keys are job_ids, values are asyncio.Task objects.
_JOBS: Dict[str, asyncio.Task] = {}


def _run_analysis_blocking(
    target_path, vulnerability_type, target_function, function_args, structs
) -> dict:
    """
    This function is called in a separate thread (via asyncio.to_thread) to avoid blocking the main event loop.
    """
    analyzer = AngrAnalyzer(target_path)
    return analyzer.run_analysis(
        vulnerability_type, target_function, function_args, structs
    )


_ANALYSIS_SEM = asyncio.Semaphore(
    1
)  # 1 = strictly sequential, 2 = 2 parallel analyses, etc. (CPU-heavy, so don't go too high)


async def _run_capped(
    target_path, vulnerability_type, target_function, function_args, structs
) -> dict:
    async with (
        _ANALYSIS_SEM
    ):  # wait for a free slot (if all slots are busy, this will block until one is free)
        return await asyncio.to_thread(
            _run_analysis_blocking,
            target_path,
            vulnerability_type,
            target_function,
            function_args,
            structs,
        )


@mcp.tool()
async def start_validation(
    target_path: str,
    target_function: str = None,
    function_args: List[Any] = None,
    structs: List[Dict[str, Any]] = None,
    vulnerability_type: str = "auto",
) -> dict:
    """
    Starts the symbolic analysis as a background job and returns IMMEDIATELY.
    Return the job_id to get_validation_result to retrieve the result.
    """
    job_id = uuid.uuid4().hex
    task = asyncio.ensure_future(
        _run_capped(
            target_path, vulnerability_type, target_function, function_args, structs
        )
    )
    _JOBS[job_id] = task
    return {"job_id": job_id, "status": "running"}


@mcp.tool()
async def get_validation_result(job_id: str) -> dict:
    """
    Asks for the status/result of a job started with start_validation.
    status: 'running' = not finished yet (poll again later);
            'done'    = 'result' contains the analysis result;
            'error'   = 'message' contains the error;
            'unknown' = job_id not found (e.g. server restarted).
    """
    task = _JOBS.get(job_id)
    if task is None:
        return {
            "status": "unknown",
            "message": f"No job with id {job_id}. Maybe the server restarted and lost all jobs?",
        }
    if not task.done():
        return {"status": "running"}
    try:
        result = task.result()
        _JOBS.pop(job_id, None)
        return {"status": "done", "result": result}
    except FileNotFoundError as e:
        _JOBS.pop(job_id, None)
        return {"status": "error", "error": "FileNotFound", "message": str(e)}
    except Exception as e:
        _JOBS.pop(job_id, None)
        return {"status": "error", "error": "AnalysisError", "message": str(e)}


if __name__ == "__main__":
    setup_logging()
    mcp.run(transport="stdio")
