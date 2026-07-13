import pytest
import angr
import copy

from vuln_validator.utils import config_loader
from vuln_validator.core.solvers.format_string_solver import FormatStringSolver

TEST_CASES = [
    {
        "binary": "tests/fixtures/format_string/printf_user",
        "func": "log_message",
        "args": [{"type": "pointer", "size": 64}],
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/format_string/fprintf",
        "func": "log_error",
        "args": [{"type": "pointer", "size": 64}],
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/format_string/sprintf",
        "func": "create_message",
        "args": [{"type": "pointer", "size": 64}],
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/format_string/snprintf",
        "func": "safe_create_message",
        "args": [{"type": "pointer", "size": 64}],
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/format_string/syslog",
        "func": "log_event",
        "args": [{"type": "pointer", "size": 64}],
        "should_find": True,
    },
    # --- Safe binaries ---
    {
        "binary": "tests/fixtures/format_string/printf_user_safe",
        "func": "log_message",
        "args": [{"type": "pointer", "size": 64}],
        "should_find": False,
    },
    {
        "binary": "tests/fixtures/format_string/fprintf_safe",
        "func": "log_error",
        "args": [{"type": "pointer", "size": 64}],
        "should_find": False,
    },
    {
        "binary": "tests/fixtures/format_string/sprintf_safe",
        "func": "create_message",
        "args": [{"type": "pointer", "size": 64}],
        "should_find": False,
    },
    {
        "binary": "tests/fixtures/format_string/snprintf_safe",
        "func": "safe_create_message",
        "args": [{"type": "pointer", "size": 64}],
        "should_find": False,
    },
    {
        "binary": "tests/fixtures/format_string/syslog_safe",
        "func": "log_event",
        "args": [{"type": "pointer", "size": 64}],
        "should_find": False,
    },
]


def _set_config(monkeypatch, **analyzer_overrides):
    """
    Overrides the analyzer configuration for testing purposes. It allows tests to specify custom configuration values for the analyzer, ensuring that the AngrAnalyzer behaves as expected under different configuration scenarios.
    """
    cfg = copy.deepcopy(config_loader._DEFAULTS)
    cfg["analyzer"].update(analyzer_overrides)
    monkeypatch.setattr(
        config_loader,
        "load_config",
        lambda *args, **kwargs: copy.deepcopy(cfg),
    )


class TestFormatStringSolver:

    @pytest.fixture
    def solver(self):
        """Provides a fresh instance of the FormatStringSolver for each test."""
        return FormatStringSolver()

    @pytest.fixture
    def vuln_project(self):
        """Loads the vulnerable test binary."""
        return angr.Project(
            "tests/fixtures/format_string/gets_local", auto_load_libs=False
        )

    @pytest.mark.parametrize("case", TEST_CASES)
    def test_format_string_patterns(self, monkeypatch, case):
        proj = angr.Project(case["binary"], auto_load_libs=False)
        if not proj.kb.functions:
            proj.analyses.CFGFast()

        solver = FormatStringSolver()
        _set_config(monkeypatch)
        result = solver.solve(
            proj,
            target_function=case["func"],
            function_args=case["args"],
            structs=case.get("structs", []),
        )

        if case["should_find"]:
            assert result["is_vulnerable"] is True
        else:
            assert result["is_vulnerable"] is False
