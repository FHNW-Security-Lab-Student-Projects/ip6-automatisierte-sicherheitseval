from typing import Any, Dict, List, Optional

from vuln_validator.core.angr_analyzer import AngrAnalyzer
from vuln_validator.core.solvers.base_solver import BaseSolver


class DummySolver(BaseSolver):
    """
    A dummy solver for testing purposes. It simulates the behavior of a real solver without performing any actual analysis.
    It can be configured to return a specific result or raise an error, allowing tests to verify the AngrAnalyzer's handling of different solver outcomes.
    """

    def __init__(
        self,
        vuln_type: str,
        calls: List[str],
        result: Optional[Dict[str, Any]] = None,
        error: Optional[Exception] = None,
    ):
        self._vuln_type = vuln_type
        self._calls = calls
        self._result = result or {
            "is_vulnerable": False,
            "type": vuln_type,
            "evidence": {},
            "message": f"No {vuln_type} found.",
        }
        self._error = error

    @property
    def vulnerability_type(self) -> str:
        """
        Returns the vulnerability type that this dummy solver is simulating.
        """
        return self._vuln_type

    def solve(
        self,
        project,
        target_function,
        function_args,
        structs,
        stop_event=None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Simulates the solve method of a real solver. It records the call and either returns a predefined result or raises a predefined error.
        Accepts optional stop_event and extra kwargs to be compatible with real solvers.
        """
        self._calls.append(self._vuln_type)
        self._received_target = target_function
        self._received_args = function_args
        self._received_structs = structs
        if self._error:
            raise self._error
        return self._result


def _analyzer_with_solvers(monkeypatch, solvers: List[BaseSolver]) -> AngrAnalyzer:
    """
    Creates an AngrAnalyzer instance with a mocked project and a list of dummy solvers for testing. It bypasses the actual binary loading and solver registration, allowing tests to focus on the analysis workflow and result aggregation without relying on real binaries or solvers.
    """
    analyzer = AngrAnalyzer("/tmp/fake-binary")
    analyzer.project = (
        object()
    )  # Skip real angr project loading for deterministic tests.
    monkeypatch.setattr(analyzer, "_get_registered_solvers", lambda: solvers)
    return analyzer


def test_run_analysis_auto_runs_all_solvers(monkeypatch, set_config) -> None:
    """
    Tests that when 'auto' is specified as the vulnerability type, the AngrAnalyzer runs all registered solvers in the order they are returned by _get_registered_solvers, collects their results, and correctly aggregates the overall vulnerability status and evidence.
    """
    calls: List[str] = []
    solvers = [
        DummySolver(
            "stack_overflow",
            calls,
            {
                "is_vulnerable": False,
                "type": "stack_overflow",
                "evidence": [],
                "message": "No stack.",
            },
        ),
        DummySolver(
            "heap_overflow",
            calls,
            {
                "is_vulnerable": True,
                "type": "heap_overflow",
                "evidence": [
                    {
                        "state_type": "Unconstrained",
                        "input_hex": "deadbeef",
                        "description": "Heap overflow state detected.",
                    }
                ],
                "message": "Heap found.",
            },
        ),
    ]
    analyzer = _analyzer_with_solvers(monkeypatch, solvers)

    set_config()
    result = analyzer.run_analysis("auto", "main")

    assert calls == ["stack_overflow", "heap_overflow"]
    assert result["requested_type"] == "auto"
    assert result["analyzed_types"] == ["stack_overflow", "heap_overflow"]
    assert result["is_vulnerable"] is True
    evidence = result.get("evidence", [])
    assert len(evidence) == 1
    assert evidence[0]["state_type"] == "Unconstrained"
    assert evidence[0]["input_hex"] == "deadbeef"
    assert evidence[0]["description"] == "Heap overflow state detected."
    assert "Heap found." in result["messages"][1]


def test_run_analysis_specific_type_stops_on_first_matching_positive(
    monkeypatch, set_config
) -> None:
    """
    Tests that if a specific vulnerability type is requested and the first matching solver returns a positive result (vulnerable), the analyzer stops running further solvers in the execution plan, as the requested vulnerability type has already been confirmed, ensuring efficient analysis without unnecessary solver executions.
    """
    calls: List[str] = []
    solvers = [
        DummySolver("stack_overflow", calls),
        DummySolver(
            "heap_overflow",
            calls,
            {
                "is_vulnerable": True,
                "type": "heap_overflow",
                "evidence": [{"state_type": "Unconstrained"}],
                "message": "Heap found.",
            },
        ),
        DummySolver("format_string", calls),
    ]
    analyzer = _analyzer_with_solvers(monkeypatch, solvers)

    set_config()
    result = analyzer.run_analysis("heap_overflow")

    assert result["requested_type"] == "heap_overflow"
    assert result["analyzed_types"] == ["heap_overflow"]
    assert calls == ["heap_overflow"]
    assert result["is_vulnerable"] is True


def test_run_analysis_specific_type_continues_when_first_matching_negative(
    monkeypatch, set_config
) -> None:
    """
    Tests that if a specific vulnerability type is requested and the first matching solver
    returns a negative result, the analyzer doesn't continue to run remaining solvers.
    """
    calls: List[str] = []
    solvers = [
        DummySolver("stack_overflow", calls),
        DummySolver(
            "heap_overflow",
            calls,
            {
                "is_vulnerable": False,
                "type": "heap_overflow",
                "evidence": [],
                "message": "No heap.",
            },
        ),
        DummySolver(
            "format_string",
            calls,
            {
                "is_vulnerable": True,
                "type": "format_string",
                "evidence": [{"state_type": "Errored"}],
                "message": "Fmt found.",
            },
        ),
    ]
    analyzer = _analyzer_with_solvers(monkeypatch, solvers)

    set_config()
    result = analyzer.run_analysis("heap_overflow")

    assert calls == ["heap_overflow"]
    assert result["is_vulnerable"] is False
    assert result["analyzed_types"] == [
        "heap_overflow",
    ]


def test_run_analysis_collects_solver_error_and_continues(
    monkeypatch, set_config
) -> None:
    """
    Tests that if a solver raises an unexpected exception during its solve method, the analyzer catches the error, records it in the messages list, and stops running further solvers, provides feedback about the error encountered.
    """
    calls: List[str] = []
    solvers = [
        DummySolver("stack_overflow", calls, error=RuntimeError("boom")),
        DummySolver("heap_overflow", calls),
    ]
    analyzer = _analyzer_with_solvers(monkeypatch, solvers)

    set_config()
    result = analyzer.run_analysis("auto")

    assert calls == ["stack_overflow"]
    assert result["analyzed_types"] == ["stack_overflow"]
    assert "boom" in result["messages"][0]


def test_run_analysis_unknown_type_falls_back_to_auto(monkeypatch, set_config) -> None:
    """
    Tests that if an unknown vulnerability type is requested, the analyzer falls back to running all registered solvers (auto behavior) instead of failing or returning no results.
    """
    calls: List[str] = []
    solvers = [
        DummySolver("stack_overflow", calls),
        DummySolver("heap_overflow", calls),
    ]
    analyzer = _analyzer_with_solvers(monkeypatch, solvers)

    set_config()
    result = analyzer.run_analysis("totally_unknown_type")

    assert result["requested_type"] == "totally_unknown_type"
    assert calls == ["stack_overflow", "heap_overflow"]
    assert result["analyzed_types"] == ["stack_overflow", "heap_overflow"]


def test_run_analysis_passes_target_function_to_solver(monkeypatch) -> None:
    """
    Tests if the target_function parameter is correctly passed from the AngrAnalyzer to the solver's solve method, allowing solvers to focus their analysis on a specific function when requested.
    """
    calls = []
    solver = DummySolver("stack_overflow", calls)
    analyzer = _analyzer_with_solvers(monkeypatch, [solver])

    analyzer.run_analysis("stack_overflow", target_function="vulnerable_func")

    assert solver._received_target == "vulnerable_func"
    assert calls == ["stack_overflow"]


def test_run_analysis_auto_stops_on_first_positive_when_config_enabled(
    monkeypatch, set_config
) -> None:
    calls: List[str] = []
    solvers = [
        DummySolver(
            "stack_overflow",
            calls,
            {
                "is_vulnerable": True,
                "type": "stack_overflow",
                "evidence": [],
                "message": "Stack found.",
            },
        ),
        DummySolver(
            "heap_overflow",
            calls,
            {
                "is_vulnerable": True,
                "type": "heap_overflow",
                "evidence": [],
                "message": "Heap found.",
            },
        ),
    ]
    analyzer = _analyzer_with_solvers(monkeypatch, solvers)
    set_config(auto_stop_on_first_found=True)

    result = analyzer.run_analysis("auto")

    assert calls == ["stack_overflow"]
    assert result["analyzed_types"] == ["stack_overflow"]
    assert result["is_vulnerable"] is True
