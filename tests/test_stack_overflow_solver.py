import pytest
import angr

from vuln_validator.core.solvers.stack_solver import StackOverflowSolver

TEST_CASES = [
    {
        "binary": "tests/fixtures/stack_overflow/gets_local",
        "func": "vulnerable_function",
        "args": None,
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/stack_overflow/gets_pointer",
        "func": "vulnerable_function",
        "args": [{"type": "symbolic_pointer", "size": 64}],
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/stack_overflow/strcpy_pointer",
        "func": "copy_input",
        "args": [{"type": "symbolic_pointer", "size": 64}],
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/stack_overflow/mixed_input",
        "func": "process_request",
        "args": [
            {"type": "symbolic_value", "size": 4},  # user_id
            {"type": "symbolic_pointer", "size": 128},  # input_data
            {"type": "symbolic_value", "size": 4},  # log_level
        ],
        "should_find": True,  # should find the overflow in input_data, even with the "noise" of the other symbolic args
    },
    {
        "binary": "tests/fixtures/stack_overflow/two_args",
        "func": "process_data",
        "args": [
            {"type": "symbolic_pointer", "size": 32},  # arg1
            {"type": "symbolic_pointer", "size": 32},  # arg2
        ],
        "should_find": True,
    },
    # --- Safe binaries ---
    {
        "binary": "tests/fixtures/common/safe_binary",
        "func": "safe_func",
        "args": None,
        "should_find": False,
    },
    {
        "name": "safe_strcpy: manual length check",
        "binary": "tests/fixtures/common/safe_strcpy",
        "func": "safe_func",
        "args": [{"type": "symbolic_pointer", "size": 128}],
        "should_find": False,
    },
    {
        "binary": "tests/fixtures/common/safe_strncpy",
        "func": "safe_func",
        "args": [{"type": "symbolic_pointer", "size": 128}],
        "should_find": False,
    },
    {
        "name": "false_positive_trap: complex logic (loop)",
        "binary": "tests/fixtures/common/false_positiv_trap",
        "func": "vulnerable_looking_func",
        "args": [{"type": "symbolic_pointer", "size": 128}],
        "should_find": False,
    },
]


class TestStackOverflowSolver:

    @pytest.fixture
    def solver(self):
        """Provides a fresh instance of the StackOverflowSolver for each test."""
        return StackOverflowSolver()

    @pytest.fixture
    def vuln_project(self):
        """Loads the vulnerable test binary."""
        return angr.Project(
            "tests/fixtures/stack_overflow/gets_local", auto_load_libs=False
        )

    def test_result_structure(self, solver, vuln_project):
        """
        verifies that the result returned by the StackOverflowSolver contains all required keys and has the correct structure, regardless of whether a vulnerability was found or not.
        """
        result = solver.solve(vuln_project, target_function="vulnerable_function")

        required_keys = [
            "is_vulnerable",
            "type",
            "target_function",
            "evidence",
            "message",
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"

        # Check structure of 'evidence' key
        evidence = result.get("evidence", [])
        assert "state_type" in evidence[0]
        assert "input_hex" in evidence[0]
        assert "description" in evidence[0]

    def test_stack_overflow_with_target_function(self, solver, vuln_project):
        """
        Tests if the solver correctly uses the target_function parameter to jump
        directly to the vulnerable function and detect the overflow.
        """
        # We force the solver to start directly in 'vulnerable_function'
        result = solver.solve(vuln_project, target_function="vulnerable_function")

        assert result["is_vulnerable"] is True
        assert result["type"] == "stack_overflow"
        assert "vulnerable_function" in result.get("message", "")

        # Evidence should be present
        evidence = result.get("evidence", [])
        assert "state_type" in evidence[0]

    def test_solver_with_nonexistent_function(self, solver, vuln_project):
        """
        Tests how the solver handles a target_function name that does not exist in the binary.
        Expected: Graceful handling (is_vulnerable == False) and an informative message.
        """
        result = solver.solve(vuln_project, target_function="does_not_exist_123")

        assert result["is_vulnerable"] is False
        assert (
            "target function 'does_not_exist_123' does not exist or has no symbol table entry."
            in result.get("message", "").lower()
        )

    @pytest.mark.parametrize("case", TEST_CASES)
    def test_overflow_patterns(self, case):
        proj = angr.Project(case["binary"], auto_load_libs=False)
        if not proj.kb.functions:
            proj.analyses.CFGFast()

        solver = StackOverflowSolver()
        result = solver.solve(
            proj, target_function=case["func"], function_args=case["args"]
        )

        if case["should_find"]:
            assert result["is_vulnerable"] is True
        else:
            assert result["is_vulnerable"] is False
