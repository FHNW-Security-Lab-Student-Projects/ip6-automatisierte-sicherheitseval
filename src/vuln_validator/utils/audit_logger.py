import json
import logging
import inspect
from functools import wraps
from datetime import datetime
from typing import Callable, Any, Dict
from pathlib import Path

# Create logger for audit events
audit_logger = logging.getLogger("vuln_validator.audit")
audit_logger.setLevel(logging.INFO)
# Disable propagation to avoid duplicate logs in the root logger
audit_logger.propagate = False

# init log file and handler only once to avoid duplicates
if not audit_logger.handlers:
    log_file = Path("logs/audit_log.json")
    log_file.parent.mkdir(exist_ok=True)
    handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    # no formatter needed since we log raw JSON strings
    audit_logger.addHandler(handler)


# Helper function for logging of audit events
def log_audit_event(event_data: Dict[str, Any]) -> None:
    """
    Writes a single JSON audit event to the log file.
    """
    full_event = {"timestamp": datetime.now().isoformat(), **event_data}
    audit_logger.info(json.dumps(full_event, default=str))


# Decorator for async tool functions
def audit_log(tool_name: str) -> Callable:
    """
    Decorator for async tool functions.

    Logs:
    - validation_started with the exact input parameters
    - validation_completed with the returned value
    - validation_failed if the tool raises an exception
    """

    def decorator(func: Callable) -> Callable:
        if not inspect.iscoroutinefunction(func):
            raise TypeError("@audit_log is only supported for async functions")

        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            log_audit_event(
                {"event": "validation_started", "tool": tool_name, "input": kwargs}
            )
            try:
                result = await func(*args, **kwargs)
            except Exception as e:
                log_audit_event(
                    {
                        "event": "validation_failed",
                        "tool": tool_name,
                        "status": "error",
                        "error_message": str(e),
                    }
                )
                raise

            log_audit_event(
                {
                    "event": "validation_enqueued",
                    "tool": tool_name,
                    "status": "success",
                    "result": result,
                }
            )
            return result

        return wrapper

    return decorator
