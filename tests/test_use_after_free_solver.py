import pytest
import angr

from vuln_validator.core.solvers.use_after_free_solver import UseAfterFreeSolver

TEST_CASES = [
    {
        "binary": "tests/fixtures/use_after_free/uaf_simpel",
        "func": "main",
        "args": None,
        "should_find": True,
    },
    {
        "binary": "tests/fixtures/use_after_free/uaf_global_pointer",
        "func": "main",
        "args": None,
        "should_find": True,
    },
    # --- Safe binaries ---
    {
        "binary": "tests/fixtures/use_after_free/uaf_safe",
        "func": "main",
        "args": None,
        "should_find": False,
    },
]


class TestUseAfterFreeSolver:

    @pytest.fixture
    def solver(self):
        """Provides a fresh instance of the UseAfterFreeSolver for each test."""
        return UseAfterFreeSolver()

    @pytest.fixture
    def vuln_project(self):
        """Loads the vulnerable test binary."""
        return angr.Project(
            "tests/fixtures/use_after_free/free_then_use", auto_load_libs=False
        )

    @pytest.mark.parametrize("case", TEST_CASES)
    def test_use_after_free_patterns(self, set_config, case):
        proj = angr.Project(case["binary"], auto_load_libs=False)
        if not proj.kb.functions:
            proj.analyses.CFGFast()

        solver = UseAfterFreeSolver()
        set_config()
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
