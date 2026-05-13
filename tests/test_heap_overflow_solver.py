import pytest
import angr

from vuln_validator.core.solvers.heap_solver import HeapOverflowSolver

TEST_CASES = [
    {
        "binary": "tests/fixtures/heap_overflow/first_heap_overflow",
        "func": "main",
        "args": None,
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/heap_overflow/control_flow_hijack",
        "func": "vulnerable_function",
        "args": [{"type": "symbolic_pointer", "size": 64}],
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/heap_overflow/calloc_vuln",
        "func": "main",
        "args": None,
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
]


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
    def test_overflow_patterns(self, case):
        proj = angr.Project(case["binary"], auto_load_libs=False)
        if not proj.kb.functions:
            proj.analyses.CFGFast()

        solver = HeapOverflowSolver()
        result = solver.solve(
            proj, target_function=case["func"], function_args=case["args"]
        )

        if case["should_find"]:
            assert result["is_vulnerable"] is True
        else:
            assert result["is_vulnerable"] is False
