import json
import logging
from functools import wraps
from datetime import datetime
from typing import Callable, Any, Dict
from pathlib import Path

# Create logger for audit events
audit_logger = logging.getLogger("vuln_validator.audit")
audit_logger.setLevel(logging.INFO)
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
    Writes a single event to the audit log.
    Automatically adds a timestamp.
    """
    full_event = {"timestamp": datetime.now().isoformat(), **event_data}
    audit_logger.info(json.dumps(full_event))


# Decorator for automatic logging of function calls (in MCP server)
def audit_log(tool_name: str) -> Callable:
    """
    A decorator that automatically logs the start, success, and failure of a function.
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Log Start
            log_audit_event(
                {"event": "validation_started", "tool": tool_name, "input": kwargs}
            )

            try:
                result = func(*args, **kwargs)

                log_audit_event(
                    {
                        "event": "validation_completed",
                        "tool": tool_name,
                        "status": "success",
                        "summary": {
                            "is_vulnerable": result.get("is_vulnerable"),
                            "findings_count": len(result.get("findings", [])),
                            "message": result.get("message", ""),
                            "evidence_input_hex": [
                                e.get("input_hex") for e in result.get("evidence", [])
                            ],
                        },
                    }
                )
                return result

            except Exception as e:
                log_audit_event(
                    {
                        "event": "validation_failed",
                        "tool": tool_name,
                        "status": "error",
                        "error_message": str(e),
                    }
                )
                return {"is_vulnerable": False, "error": str(e)}

        return wrapper

    return decorator
