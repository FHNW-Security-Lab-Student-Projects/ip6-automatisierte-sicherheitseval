import pytest
import angr

from vuln_validator.core.solvers.stack_solver import StackOverflowSolver


class TestStackOverflowSolver:

    @pytest.fixture
    def solver(self):
        """Provides a fresh instance of the StackOverflowSolver for each test."""
        return StackOverflowSolver()

    @pytest.fixture
    def vuln_project(self):
        """Loads the vulnerable test binary."""
        return angr.Project("tests/fixtures/5_my_vuln", auto_load_libs=False)

    @pytest.fixture
    def safe_project(self):
        """Loads a safe test binary."""
        return angr.Project("tests/fixtures/safe_binary", auto_load_libs=False)

    def test_stack_overflow_detected_stdin(self, solver, vuln_project):
        """
        Tests if the StackOverflowSolver can detect a known stack overflow vulnerability in the vuln_minimal binary when providing symbolic input via stdin.
        Expected: is_vulnerable == True and a payload is generated.
        """
        result = solver.solve(vuln_project)

        # Checks if the vulnerability was detected
        assert result["is_vulnerable"] is True
        assert result["type"] == "stack_overflow"

        # Check if evidence contains a payload
        evidence = result.get("evidence", {})
        assert (
            evidence.get("unconstrained_states", 0) > 0
            or evidence.get("errored_states", 0) > 0
        )

    def test_no_overflow_safe_binary(self, solver, safe_project):
        """
        Tests if the StackOverflowSolver correctly identifies that there is no stack overflow vulnerability in a known safe binary.
        Expected: is_vulnerable == False.
        """
        result = solver.solve(safe_project)

        # checks if no vulnerability was detected
        assert result["is_vulnerable"] is False
        assert result["type"] == "stack_overflow"

        # Message Check
        assert "No stack overflow" in result["message"]

    def test_result_structure(self, solver, vuln_project):
        """
        verifies that the result returned by the StackOverflowSolver contains all required keys and has the correct structure, regardless of whether a vulnerability was found or not.
        """
        result = solver.solve(vuln_project)

        required_keys = ["is_vulnerable", "type", "evidence", "message"]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"

        # Check structure of 'evidence' key
        assert isinstance(result["evidence"], dict)
        assert "errored_states" in result["evidence"]
        assert "unconstrained_states" in result["evidence"]

    # def test_stack_overflow_with_target_function(self, solver, vuln_project):
    #     """
    #     Tests if the solver correctly uses the target_function parameter to jump
    #     directly to the vulnerable function and detect the overflow.
    #     """
    #     # We force the solver to start directly in 'vulnerable_function'
    #     result = solver.solve(vuln_project, target_function="vulnerable_function")

    #     assert result["is_vulnerable"] is True
    #     assert result["type"] == "stack_overflow"
    #     assert "call state" in result.get("message", "").lower() or "vulnerable_function" in result.get("message", "")

    #     # Evidence should be present
    #     evidence = result.get("evidence", {})
    #     assert evidence.get("unconstrained_states", 0) > 0

    def test_solver_with_nonexistent_function(self, solver, vuln_project):
        """
        Tests how the solver handles a target_function name that does not exist in the binary.
        Expected: Graceful handling (is_vulnerable == False) and an informative message.
        """
        result = solver.solve(vuln_project, target_function="does_not_exist_123")

        assert result["is_vulnerable"] is False
        assert (
            "not found" in result.get("message", "").lower()
            or "error" in result.get("message", "").lower()
        )
