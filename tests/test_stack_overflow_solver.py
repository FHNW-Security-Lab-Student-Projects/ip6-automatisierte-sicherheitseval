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
    {
        "binary": "tests/fixtures/stack_overflow/struct_in_stack",
        "func": "create_user",
        "args": [
            {"type": "symbolic_pointer", "size": 64},
        ],
        "structs": [
            {
                "type": "struct",
                "name": "u",
                "location": "stack",
                "size": 20,
                "fields": [
                    {
                        "type": "symbolic_value",
                        "offset": 0,
                        "size": 16,
                        "is_input": True,
                    },
                    {
                        "type": "symbolic_value",
                        "offset": 16,
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
    {
        "binary": "tests/fixtures/common/struct_in_stack_safe",
        "func": "create_user",
        "args": [{"type": "symbolic_pointer", "size": 64}],
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

    @pytest.mark.parametrize("case", TEST_CASES)
    def test_overflow_patterns(self, case):
        proj = angr.Project(case["binary"], auto_load_libs=False)
        if not proj.kb.functions:
            proj.analyses.CFGFast()

        solver = StackOverflowSolver()
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
