import asyncio
import uuid
import json
import time
import os
from pathlib import Path
from mcp.server.fastmcp import FastMCP
from typing import List, Any, Dict

from vuln_validator.utils.logging_config import setup_logging
from vuln_validator.core.angr_analyzer import AngrAnalyzer
from vuln_validator.utils.audit_logger import audit_log, log_audit_event

mcp = FastMCP("VulnValidator")


JOBS_DIR = Path(".mcp_jobs")
JOBS_DIR.mkdir(exist_ok=True)

_JOB_QUEUE: asyncio.Queue[str] = asyncio.Queue()
_QUEUE_WORKER_TASK: asyncio.Task | None = None


def _get_job_path(job_id: str) -> Path:
    return JOBS_DIR / f"{job_id}.json"


def _load_job(job_id: str) -> Dict[str, Any] | None:
    path = _get_job_path(job_id)
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def _save_job(job_id: str, data: Dict[str, Any]) -> None:
    path = _get_job_path(job_id)
    tmp_path = path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    tmp_path.replace(path)


def _ensure_queue_worker_started() -> None:
    global _QUEUE_WORKER_TASK
    if _QUEUE_WORKER_TASK is None or _QUEUE_WORKER_TASK.done():
        _QUEUE_WORKER_TASK = asyncio.create_task(_queue_worker())


async def _run_analysis(
    target_path, vulnerability_type, target_function, function_args, structs
) -> dict:
    """
    Run the actual analysis in a worker thread.
    Ordering is handled by the queue worker.
    """
    analyzer = AngrAnalyzer(target_path)
    return await asyncio.to_thread(
        analyzer.run_analysis,
        vulnerability_type,
        target_function,
        function_args,
        structs,
    )


async def _queue_worker() -> None:
    """
    Single background worker that processes jobs strictly in queue order.

    One job is taken from _JOB_QUEUE at a time:
    - mark it running
    - run the analysis
    - store result or error in _JOBS
    - keep the job entry so the same job_id can be queried later
    """
    while True:
        job_id = await _JOB_QUEUE.get()
        job = _load_job(job_id)

        if job is None:
            _JOB_QUEUE.task_done()
            continue

        job["status"] = "running"
        job["updated_at"] = time.time()
        _save_job(job_id, job)

        _log_analysis_event("analysis_started", job_id, job)

        try:
            result = await _run_analysis(
                job["target_path"],
                job["vulnerability_type"],
                job["target_function"],
                job["function_args"],
                job["structs"],
            )
            job["status"] = "done"
            job["result"] = result
            job["error"] = None
            job["updated_at"] = time.time()
            _save_job(job_id, job)
            _log_analysis_event(
                "analysis_completed", job_id, job, status="success", result=result
            )

        except FileNotFoundError as e:
            job["status"] = "error"
            job["error"] = {"error": "FileNotFound", "message": str(e)}
            job["result"] = None
            job["updated_at"] = time.time()
            _save_job(job_id, job)
            _log_analysis_event(
                "analysis_failed", job_id, job, status="error", error_message=str(e)
            )

        except Exception as e:
            job["status"] = "error"
            job["error"] = {"error": "AnalysisError", "message": str(e)}
            job["result"] = None
            job["updated_at"] = time.time()
            _save_job(job_id, job)

            _log_analysis_event(
                "analysis_failed",
                job_id,
                job,
                status="error",
                error_message=str(e),
            )
        finally:
            _JOB_QUEUE.task_done()


@mcp.tool()
@audit_log("validate_vulnerability")
async def start_validation(
    target_path: str,
    target_function: str = None,
    function_args: List[Any] = None,
    structs: List[Dict[str, Any]] = None,
    vulnerability_type: str = "auto",
) -> dict:
    """
    Starts a validation job and returns immediately.
    The job is queued and processed later by the single background worker.
    """
    _ensure_queue_worker_started()

    job_id = uuid.uuid4().hex
    job_data = {
        "job_id": job_id,
        "status": "queued",
        "result": None,
        "error": None,
        "target_path": target_path,
        "target_function": target_function,
        "function_args": function_args,
        "structs": structs,
        "vulnerability_type": vulnerability_type,
        "created_at": time.time(),
        "updated_at": time.time(),
    }

    _save_job(job_id, job_data)

    await _JOB_QUEUE.put(job_id)
    return {"job_id": job_id, "status": "queued"}


@mcp.tool()
async def get_validation_result(job_id: str) -> dict:
    """
    Poll the status/result of a previously started job.

    queued/running -> wait 15 seconds, then return running if still not done
    done           -> return result
    error          -> return error
    unknown        -> job_id not found
    """
    job = _load_job(job_id)

    if job is None:
        await asyncio.sleep(1)
        return {
            "status": "unknown",
            "message": f"No job with id {job_id}. Try again.",
        }

    if job["status"] in ("queued", "running"):
        await asyncio.sleep(15)  # keep LLM from hammering the server
        job = _load_job(job_id)
        if job["status"] in ("queued", "running"):
            return {"status": "running"}

    if job["status"] == "done":
        return {"status": "done", "result": job["result"]}

    if job["status"] == "error":
        return {
            "status": "error",
            "error": job["error"]["error"],
            "message": job["error"]["message"],
        }

    return {
        "status": "unknown",
        "message": f"Unknown state for job {job_id}.",
    }


def _log_analysis_event(
    event: str, job_id: str, job: Dict[str, Any], **extra: Any
) -> None:
    log_audit_event(
        {
            "event": event,
            "tool": "validate_vulnerability",
            "job_id": job_id,
            "server_pid": str(os.getpid()),
            **extra,
        }
    )


if __name__ == "__main__":
    setup_logging()
    mcp.run(transport="stdio")
