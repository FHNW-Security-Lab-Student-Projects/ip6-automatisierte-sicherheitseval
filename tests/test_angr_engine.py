from typing import Any, Dict, List, Optional

from vuln_validator.core.angr_engine import AngrAnalyzer
from vuln_validator.core.solvers.base_solver import BaseSolver


class DummySolver(BaseSolver):
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
		return self._vuln_type

	def solve(self, project) -> Dict[str, Any]:
		self._calls.append(self._vuln_type)
		if self._error:
			raise self._error
		return self._result


def _analyzer_with_solvers(monkeypatch, solvers: List[BaseSolver]) -> AngrAnalyzer:
	analyzer = AngrAnalyzer("/tmp/fake-binary")
	analyzer.project = object()  # Skip real angr project loading for deterministic tests.
	monkeypatch.setattr(analyzer, "_get_registered_solvers", lambda: solvers)
	return analyzer


def test_run_analysis_auto_runs_all_solvers(monkeypatch) -> None:
	calls: List[str] = []
	solvers = [
		DummySolver("stack_overflow", calls, {"is_vulnerable": False, "type": "stack_overflow", "evidence": {}, "message": "No stack."}),
		DummySolver("heap_overflow", calls, {"is_vulnerable": True, "type": "heap_overflow", "evidence": {"path": "p1"}, "message": "Heap found."}),
	]
	analyzer = _analyzer_with_solvers(monkeypatch, solvers)

	result = analyzer.run_analysis("auto")

	assert calls == ["stack_overflow", "heap_overflow"]
	assert result["requested_type"] == "auto"
	assert result["analyzed_types"] == ["stack_overflow", "heap_overflow"]
	assert result["is_vulnerable"] is True
	assert len(result["findings"]) == 2


def test_run_analysis_specific_type_stops_on_first_matching_positive(monkeypatch) -> None:
	calls: List[str] = []
	solvers = [
		DummySolver("stack_overflow", calls),
		DummySolver("heap_overflow", calls, {"is_vulnerable": True, "type": "heap_overflow", "evidence": {"path": "p2"}, "message": "Heap found."}),
		DummySolver("format_string", calls),
	]
	analyzer = _analyzer_with_solvers(monkeypatch, solvers)

	result = analyzer.run_analysis("heap_overflow")

	assert result["requested_type"] == "heap_overflow"
	assert result["analyzed_types"] == ["heap_overflow"]
	assert calls == ["heap_overflow"]
	assert result["is_vulnerable"] is True
	assert len(result["findings"]) == 1


def test_run_analysis_specific_type_continues_when_first_matching_negative(monkeypatch) -> None:
	calls: List[str] = []
	solvers = [
		DummySolver("stack_overflow", calls),
		DummySolver("heap_overflow", calls, {"is_vulnerable": False, "type": "heap_overflow", "evidence": {}, "message": "No heap."}),
		DummySolver("format_string", calls, {"is_vulnerable": True, "type": "format_string", "evidence": {"offset": 12}, "message": "Fmt found."}),
	]
	analyzer = _analyzer_with_solvers(monkeypatch, solvers)

	result = analyzer.run_analysis("heap_overflow")

	assert calls == ["heap_overflow", "stack_overflow", "format_string"]
	assert result["is_vulnerable"] is True
	assert len(result["findings"]) == 3


def test_run_analysis_collects_solver_error_and_continues(monkeypatch) -> None:
	calls: List[str] = []
	solvers = [
		DummySolver("stack_overflow", calls, error=RuntimeError("boom")),
		DummySolver("heap_overflow", calls),
	]
	analyzer = _analyzer_with_solvers(monkeypatch, solvers)

	result = analyzer.run_analysis("auto")

	assert calls == ["stack_overflow", "heap_overflow"]
	assert result["is_vulnerable"] is False
	assert result["findings"][0]["type"] == "stack_overflow"
	assert "boom" in result["findings"][0]["error"]
	assert result["findings"][1]["type"] == "heap_overflow"


def test_run_analysis_unknown_type_falls_back_to_auto(monkeypatch) -> None:
	calls: List[str] = []
	solvers = [
		DummySolver("stack_overflow", calls),
		DummySolver("heap_overflow", calls),
	]
	analyzer = _analyzer_with_solvers(monkeypatch, solvers)

	result = analyzer.run_analysis("totally_unknown_type")

	assert result["requested_type"] == "totally_unknown_type"
	assert calls == ["stack_overflow", "heap_overflow"]
	assert result["analyzed_types"] == ["stack_overflow", "heap_overflow"]
	assert len(result["findings"]) == 2
