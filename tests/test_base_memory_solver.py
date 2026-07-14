import angr
import pytest

from vuln_validator.core.solvers.base_memory_solver import BaseMemorySolver


class DummyMemorySolver(BaseMemorySolver):
    @property
    def vulnerability_type(self):
        return "dummy_overflow"

    def _setup_environment(self, project):
        pass

    def _place_buffers_and_canaries(self, state, project, function_args):
        return []


@pytest.fixture
def solver():
    return DummyMemorySolver()


@pytest.fixture
def vuln_project():
    return angr.Project(
        "tests/fixtures/stack_overflow/gets_local", auto_load_libs=False
    )


def test_result_structure(set_config, solver, vuln_project):
    """
    verifies that the result returned by the StackOverflowSolver contains all required keys and has the correct structure, regardless of whether a vulnerability was found or not.
    """
    set_config()
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
    assert "evidence" in result
    assert isinstance(result["evidence"], list)
    evidence = result.get("evidence", [])
    assert "state_type" in evidence[0]
    assert "input_hex" in evidence[0]
    assert "description" in evidence[0]


def test_dummy_overflow_with_target_function(set_config, solver, vuln_project):
    """
    Tests if the solver correctly uses the target_function parameter to jump
    directly to the vulnerable function and detect the overflow.
    """
    # We force the solver to start directly in 'vulnerable_function'
    set_config()
    result = solver.solve(vuln_project, target_function="vulnerable_function")

    assert result["is_vulnerable"] is True
    assert result["type"] == "dummy_overflow"
    assert "vulnerable_function" in result.get("message", "")

    # Evidence should be present
    evidence = result.get("evidence", [])
    assert "state_type" in evidence[0]


def test_solver_with_nonexistent_function(set_config, solver, vuln_project):
    """
    Tests how the solver handles a target_function name that does not exist in the binary.
    Expected: Graceful handling (is_vulnerable == False) and an informative message.
    """
    set_config()
    result = solver.solve(vuln_project, target_function="does_not_exist_123")

    assert result["is_vulnerable"] is False
    assert (
        "target function 'does_not_exist_123' does not exist or has no symbol table entry."
        in result.get("message", "").lower()
    )
