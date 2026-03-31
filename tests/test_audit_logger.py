import pytest
import json
import logging
from datetime import datetime

# import tested components
from src.vuln_validator.utils.audit_logger import (
    log_audit_event,
    audit_log,
    audit_logger,
)


@pytest.fixture
def temp_log_file(tmp_path):
    """
    creates a temporary log file for testing and configures the audit logger to use it.
    makes sure that after the test, no handlers are left (cleanup).
    """
    log_file = tmp_path / "test_audit.json"

    # remove any existing handlers to ensure a clean state for the test
    audit_logger.handlers.clear()

    # create a new handler for the temporary file and add it to the logger
    handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    audit_logger.addHandler(handler)

    yield log_file

    # Cleanup: close the handler and clear handlers to avoid side effects on other tests
    handler.close()
    audit_logger.handlers.clear()


class TestLogAuditEvent:
    """Tests for the manual logging function `log_audit_event`."""

    def test_log_event_writes_json(self, temp_log_file):
        """checks that a single event is correctly written as JSON to the log file."""
        test_data = {
            "event": "validation_started",
            "tool": "test_tool",
            "input": {"path": "/fake/path"},
        }

        log_audit_event(test_data)

        # read the file and check that it contains the logged event as JSON
        content = temp_log_file.read_text(encoding="utf-8")
        assert content.strip()

        lines = content.strip().split("\n")
        assert len(lines) == 1

        logged_entry = json.loads(lines[0])

        # check expected fields and values in the logged entry
        assert "timestamp" in logged_entry
        assert logged_entry["event"] == "validation_started"
        assert logged_entry["tool"] == "test_tool"
        assert logged_entry["input"] == {"path": "/fake/path"}

        # check that the timestamp is in a valid ISO 8601 format (basic check)
        datetime.fromisoformat(logged_entry["timestamp"])

    def test_log_event_multiple_entries(self, temp_log_file):
        """checks that multiple calls to `log_audit_event` result in multiple lines in the log file, each containing valid JSON."""
        log_audit_event({"event": "start"})
        log_audit_event({"event": "end"})

        content = temp_log_file.read_text(encoding="utf-8")
        lines = content.strip().split("\n")

        assert len(lines) == 2
        assert json.loads(lines[0])["event"] == "start"
        assert json.loads(lines[1])["event"] == "end"


class TestAuditLogDecorator:
    """Tests for the `audit_log` decorator"""

    def test_decorator_success_flow(self, temp_log_file):
        """Checks that the decorator logs both the start and successful completion of a decorated function, and that the summary contains expected fields."""

        # define a mock function
        @audit_log(tool_name="mock_solver")
        def mock_func(input_val):
            return {"is_vulnerable": True, "findings": ["find1", "find2"]}

        mock_func(input_val="test_binary")

        content = temp_log_file.read_text(encoding="utf-8")
        lines = content.strip().split("\n")

        assert len(lines) == 2  # Start + Success

        start_entry = json.loads(lines[0])
        success_entry = json.loads(lines[1])

        # check Start-Log
        assert start_entry["event"] == "validation_started"
        assert start_entry["tool"] == "mock_solver"
        assert start_entry["input"] == {"input_val": "test_binary"}

        # check Success-Log
        assert success_entry["event"] == "validation_completed"
        assert success_entry["status"] == "success"
        assert success_entry["summary"]["is_vulnerable"] is True
        assert success_entry["summary"]["findings_count"] == 2

    def test_decorator_error_flow(self, temp_log_file):
        """Checks if exceptions raised in the decorated function are caught and logged as errors, and that the decorator returns a fallback response."""

        @audit_log(tool_name="failing_solver")
        def failing_func():
            raise ValueError("Simulated error")

        result = failing_func()

        # decorator shoud return a fallback dict with error information instead of raising the exception
        assert result["is_vulnerable"] is False
        assert "Simulated error" in result["error"]

        content = temp_log_file.read_text(encoding="utf-8")
        lines = content.strip().split("\n")

        assert len(lines) == 2  # Start + Error

        error_entry = json.loads(lines[1])
        assert error_entry["event"] == "validation_failed"
        assert error_entry["status"] == "error"
        assert error_entry["error_message"] == "Simulated error"

    def test_decorator_preserves_function_metadata(self):
        """Checks that the `audit_log` decorator preserves the original function's name and docstring using `functools.wraps`."""

        @audit_log(tool_name="meta_test")
        def specific_function():
            """This is a test docstring."""
            return {}

        assert specific_function.__name__ == "specific_function"
        assert specific_function.__doc__ == "This is a test docstring."


class TestLoggerConfiguration:
    """Tests for the global logger configuration in `audit_logger` to ensure it is set up with the correct name, level, and handlers."""

    def test_logger_name_and_level(self):
        """Checks that the logger is correctly named and set to INFO level, and that propagation is disabled."""
        assert audit_logger.name == "vuln_validator.audit"
        assert audit_logger.level == logging.INFO
        assert audit_logger.propagate is False
