import pytest
import angr
import copy

from vuln_validator.utils import config_loader
from vuln_validator.core.solvers.heap_solver import HeapOverflowSolver

TEST_CASES = [
    {
        "binary": "tests/fixtures/heap_overflow/first_heap_overflow",
        "func": "main",
        "args": None,
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/heap_overflow/metadata_corruption",
        "func": "vulnerable_function",
        "args": [{"type": "pointer", "size": 64}],
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/heap_overflow/calloc_vuln",
        "func": "main",
        "args": None,
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/heap_overflow/aligned_alloc_heap_overflow",
        "func": "main",
        "args": None,
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/heap_overflow/global_overflow",
        "func": "read_input",
        "args": None,
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/c++/heap_overflow",
        "func": "process_input",
        "args": None,
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/heap_overflow/struct_in_heap",
        "func": "create_user",
        "args": [
            {"type": "pointer", "size": 64},
        ],
        "structs": [
            {
                "type": "struct",
                "name": "u",
                "location": "heap",
                "size": 916,
                "fields": [
                    {
                        "size": 16,
                        "is_input": True,
                    },
                    {
                        "size": 4,
                        "is_critical": True,
                    },
                ],
            }
        ],
        "should_find": True,
    },
    # --- Safe binaries ---
    {
        "binary": "tests/fixtures/common/heap_safe_strict",
        "func": "main",
        "args": None,
        "should_find": False,
    },
    {
        "binary": "tests/fixtures/common/heap_safe_no_write",
        "func": "main",
        "args": None,
        "should_find": False,
    },
    {
        "binary": "tests/fixtures/common/struct_in_heap_safe",
        "func": "create_user",
        "args": [{"type": "pointer", "size": 64, "is_struct": True}],
        "structs": [
            {
                "type": "struct",
                "name": "u",
                "location": "heap",
                "size": 916,
                "fields": [
                    {
                        "size": 16,
                        "is_input": True,
                    },
                    {
                        "size": 4,
                        "is_critical": True,
                    },
                ],
            }
        ],
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


class TestHeapOverflowSolver:

    @pytest.fixture
    def solver(self):
        """Provides a fresh instance of the HeapOverflowSolver for each test."""
        return HeapOverflowSolver()

    @pytest.fixture
    def vuln_project(self):
        """Loads the vulnerable test binary."""
        return angr.Project(
            "tests/fixtures/stack_overflow/gets_local", auto_load_libs=False
        )

    @pytest.mark.parametrize("case", TEST_CASES)
    def test_overflow_patterns(self, monkeypatch, case):
        proj = angr.Project(case["binary"], auto_load_libs=False)
        if not proj.kb.functions:
            proj.analyses.CFGFast()

        solver = HeapOverflowSolver()
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
