import angr
import logging
import time
from pathlib import Path
from typing import Dict, Any, List
from .solvers.base_solver import BaseSolver
from .solvers.stack_solver import StackOverflowSolver
from .solvers.heap_solver import HeapOverflowSolver

logger = logging.getLogger(__name__)


class AngrAnalyzer:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.project = None
        self.results: List[Dict[str, Any]] = []

    def _resolve_binary_path(self, path_str: str) -> str:
        """
        Ensures the path points to a binary file.
        If a source file is given, it attemts to find the corresponding binary by removing the extension.
        """
        path = Path(path_str)

        if not path.exists():
            logger.error(f"Provided path '{path}' does not exist.")
            raise FileNotFoundError(f"Provided path '{path}' does not exist.")

        if path.suffix in [".c", ".cpp"]:  # TODO Erweitern
            binary_candidate = path.with_suffix("")
            if binary_candidate.exists():
                logger.info(
                    f"Resolved source file '{path}' to binary '{binary_candidate}'."
                )
                return str(binary_candidate)
            else:
                logger.warning(
                    f"Source file '{path}' provided but corresponding binary '{binary_candidate}' not found."
                )
                raise FileNotFoundError(
                    f"Source file '{path}' provided but corresponding binary '{binary_candidate}' not found."
                )

        return str(path)

    def load_binary(self):
        """Loads the binary into an angr project."""
        self.binary_path = self._resolve_binary_path(self.binary_path)
        try:
            self.project = angr.Project(self.binary_path, auto_load_libs=False)
        except Exception as e:
            logger.error(f"Failed to load binary at '{self.binary_path}': {str(e)}")
            raise ValueError(f"Failed to load binary: {str(e)}")

    def _get_registered_solvers(self) -> List[BaseSolver]:
        """Registrers all available solvers centrally."""
        solvers: List[BaseSolver] = [StackOverflowSolver(), HeapOverflowSolver()]
        return solvers

    def _build_execution_plan(self, vuln_type: str) -> List[BaseSolver]:
        """
        Creates the execution plan based on the requested vulnerability type.
        - auto: all solvers
        - specific type: matching solver first, then fallback with all others
        - unknown type: fallback to auto behavior (all solvers)
        """
        registered_solvers = self._get_registered_solvers()

        if vuln_type == "auto":
            return registered_solvers

        matching = [s for s in registered_solvers if s.vulnerability_type == vuln_type]
        if not matching:
            return registered_solvers

        remaining = [s for s in registered_solvers if s.vulnerability_type != vuln_type]
        return (
            matching + remaining
        )  # run requested type first, then the rest for comprehensive analysis

    def run_analysis(
        self,
        vuln_type: str = "auto",
        target_function: str = None,
        function_args: List[Any] = None,
    ) -> Dict[str, Any]:
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
            "requested_type": vuln_type,
            "analyzed_types": [],
            "is_vulnerable": False,
            "evidence": [],
            "messages": [],
            "target_function": target_function,
        }

        for index, solver in enumerate(execution_plan):
            master_result["analyzed_types"].append(solver.vulnerability_type)
            try:
                start_time = time.time()
                result = solver.solve(self.project, target_function, function_args)
                end_time = time.time()
                logger.info(
                    f"Solver '{solver.vulnerability_type}' completed in {end_time - start_time:.2f} seconds."
                )

                if result.get("is_vulnerable"):
                    master_result["is_vulnerable"] = True

                solver_evidence = result.get("evidence", [])
                for item in solver_evidence:
                    item["source_solver"] = solver.vulnerability_type
                master_result["evidence"].extend(solver_evidence)

                master_result["messages"].append(result.get("message", ""))

                # When a specific type is requested, we can stop after the first match. For 'auto', we want to run all solvers to gather comprehensive findings.
                if (
                    vuln_type != "auto"
                    and index == 0
                    and result.get("is_vulnerable")
                    and solver.vulnerability_type == vuln_type
                ):
                    logger.info(
                        f"Stopping analysis after first positive match for requested type '{vuln_type}' from solver '{solver.vulnerability_type}'."
                    )
                    break

            except Exception as e:
                logger.error(
                    f"Error during analysis with solver '{solver.vulnerability_type}': {str(e)}"
                )
                master_result["messages"].append(
                    f"Error in {solver.vulnerability_type} solver: {str(e)}"
                )

        return master_result
