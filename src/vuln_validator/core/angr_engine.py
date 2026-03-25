import angr
import logging
from typing import Dict, Any, List
from .solvers.base_solver import BaseSolver
from .solvers.stack_solver import StackOverflowSolver
# from .solvers.heap_solver import HeapOverflowSolver

logging.getLogger('angr').setLevel(logging.ERROR)

class AngrAnalyzer:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.project = None
        self.results: List[Dict[str, Any]] = []

    def load_binary(self):
        """Loads the binary into an angr project."""
        try:
            self.project = angr.Project(self.binary_path, auto_load_libs=False)
        except Exception as e:
            raise ValueError(f"Failed to load binary: {str(e)}")

    def _get_registered_solvers(self) -> List[BaseSolver]:
        """Registrers all available solvers centrally."""
        solvers: List[BaseSolver] = [StackOverflowSolver()]
        # solvers.append(HeapOverflowSolver())
        return solvers

    def _build_execution_plan(self, vuln_type: str) -> List[BaseSolver]:
        """
        Creates the execution plan based on the requested vulnerability type.
        - auto: all solvers
        - specific type: matching solver first, then fallback with all others
        """
        registered_solvers = self._get_registered_solvers()

        if vuln_type == "auto":
            return registered_solvers

        matching = [s for s in registered_solvers if s.vulnerability_type == vuln_type]
        if not matching:
            available_types = [s.vulnerability_type for s in registered_solvers]
            raise ValueError(
                f"Unknown vulnerability type: {vuln_type}. Available: {available_types + ['auto']}"
            )

        remaining = [s for s in registered_solvers if s.vulnerability_type != vuln_type]
        return matching + remaining

    def run_analysis(self, vuln_type: str = "auto") -> Dict[str, Any]:
        """
        Executes the analysis workflow:
        1. Load binary
        2. Build execution plan based on requested vulnerability type
        3. Run solvers in order, collect results, and determine overall vulnerability status.
        """
        if not self.project:
            self.load_binary()

        execution_plan = self._build_execution_plan(vuln_type)

        master_result = {
            "is_vulnerable": False,
            "findings": [],
            "analyzed_types": [s.vulnerability_type for s in execution_plan],
            "requested_type": vuln_type,
        }

        for index, solver in enumerate(execution_plan):
            try:
                result = solver.solve(self.project)  # open-closed principle (swa)
                master_result["findings"].append(result)
                
                if result.get("is_vulnerable"):
                    master_result["is_vulnerable"] = True

                    # When a specific type is requested, we can stop after the first match. For 'auto', we want to run all solvers to gather comprehensive findings.
                    if vuln_type != "auto" and index == 0 and solver.vulnerability_type == vuln_type:
                        return master_result
            except Exception as e:
                master_result["findings"].append({
                    "type": solver.vulnerability_type,
                    "error": str(e)
                })

        return master_result