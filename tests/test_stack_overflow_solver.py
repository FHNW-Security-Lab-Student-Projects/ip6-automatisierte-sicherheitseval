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
        "args": [{"type": "pointer", "size": 64}],
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/stack_overflow/scanf",
        "func": "vulnerable_login",
        "args": None,
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/stack_overflow/mixed_input_relevant_id",
        "func": "process_request",
        "args": [
            {"type": "variable", "size": 4},  # user_id
            {"type": "pointer", "size": 128},  # input_data
            {"type": "variable", "size": 4},  # log_level
        ],
        "should_find": True,  # should find the overflow in input_data, even with the "noise" of the other symbolic args
    },
    {
        "binary": "tests/fixtures/stack_overflow/two_args_disturb",
        "func": "process_data",
        "args": [
            {"type": "pointer", "size": 32},  # arg1
            {"type": "pointer", "size": 32},  # arg2
        ],
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/c++/stack_overflow",
        "func": "vulnerable_function",
        "args": [
            {"type": "pointer", "size": 64},
        ],
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/stack_overflow/struct_in_stack",
        "func": "create_user",
        "args": [
            {"type": "pointer", "size": 64},
        ],
        "structs": [
            {
                "type": "struct",
                "name": "u",
                "location": "stack",
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
    {
        "binary": "tests/fixtures/stack_overflow/struct_in_pointer",
        "func": "create_user",
        "args": [
            {"type": "pointer", "size": 64},
            {"type": "pointer", "size": 916, "is_struct": True},
        ],
        "structs": [
            {
                "type": "struct",
                "name": "u",
                "location": "arg",
                "arg_index": 1,
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
        "binary": "tests/fixtures/common/safe_binary",
        "func": "safe_func",
        "args": None,
        "should_find": False,
    },
    {
        "name": "safe_strcpy: manual length check",
        "binary": "tests/fixtures/common/safe_strcpy",
        "func": "safe_func",
        "args": [{"type": "pointer", "size": 128}],
        "should_find": False,
    },
    {
        "binary": "tests/fixtures/common/safe_strncpy",
        "func": "safe_func",
        "args": [{"type": "pointer", "size": 128}],
        "should_find": False,
    },
    {
        "binary": "tests/fixtures/common/struct_in_stack_safe",
        "func": "create_user",
        "args": [{"type": "pointer", "size": 64, "is_struct": True}],
        "structs": [
            {
                "type": "struct",
                "name": "u",
                "location": "stack",
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
    {
        "binary": "tests/fixtures/common/struct_in_pointer_safe",
        "func": "create_user",
        "args": [
            {"type": "pointer", "size": 64},
            {"type": "pointer", "size": 916, "is_struct": True},
        ],
        "structs": [
            {
                "type": "struct",
                "name": "u",
                "location": "arg",
                "arg_index": 1,
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
