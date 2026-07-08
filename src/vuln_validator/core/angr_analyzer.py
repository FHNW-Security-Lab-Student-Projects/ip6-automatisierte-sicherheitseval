import angr
import logging
import time
from pathlib import Path
from typing import Dict, Any, List
from .solvers.base_solver import BaseSolver
from .solvers.stack_solver import StackOverflowSolver
from .solvers.heap_solver import HeapOverflowSolver
from .solvers.format_string_solver import FormatStringSolver
from ..utils.config_loader import get_analyzer_config

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

        if path.suffix in [".c", ".cpp"]:
            if path.with_suffix("").exists():
                binary_candidate = path.with_suffix("")
            elif path.with_suffix(".out").exists():
                binary_candidate = path.with_suffix(".out")
            else:
                warning_msg = (
                    f"Source file '{path}' provided but no corresponding binary found."
                )
                logger.warning(warning_msg)
                raise FileNotFoundError(warning_msg)

            logger.debug(
                f"Resolved source file '{path}' to binary '{binary_candidate}'."
            )
            return str(binary_candidate)

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
        solvers: List[BaseSolver] = [
            StackOverflowSolver(),
            HeapOverflowSolver(),
            FormatStringSolver(),
        ]
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

        # run requested type first, then the rest for comprehensive analysis
        return matching + remaining

    def run_analysis(
        self,
        vuln_type: str = "auto",
        target_function: str = None,
        function_args: List[Any] = None,
        structs: List[Dict[str, Any]] = None,
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

        analyzer_cfg = get_analyzer_config()
        auto_stop_on_first_found = analyzer_cfg["auto_stop_on_first_found"]
        specific_stop_on_first_found = analyzer_cfg["specific_stop_on_first_found"]
        specific_continue_on_no_find = analyzer_cfg["specific_continue_on_no_find"]

        is_auto_mode = vuln_type == "auto" or not any(
            s.vulnerability_type == vuln_type for s in execution_plan
        )

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
            start_time = time.time()
            try:
                result = solver.solve(
                    self.project, target_function, function_args, structs
                )
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

                # Stopping logic driven by config
                if is_auto_mode:
                    if result.get("is_vulnerable") and auto_stop_on_first_found:
                        logger.info(
                            "Stopping analysis after first positive match in auto mode."
                        )
                        break
                else:
                    if index == 0 and solver.vulnerability_type == vuln_type:
                        if result.get("is_vulnerable") and specific_stop_on_first_found:
                            logger.info(
                                "Stopping analysis after positive match for requested type '%s'.",
                                vuln_type,
                            )
                            break
                        if (not result.get("is_vulnerable")) and (
                            not specific_continue_on_no_find
                        ):
                            logger.info(
                                "Stopping analysis after no match for requested type '%s'.",
                                vuln_type,
                            )
                            break

            except Exception as e:
                logger.error(
                    f"Error during analysis with solver '{solver.vulnerability_type}': {str(e)}"
                )
                end_time = time.time()
                logger.info(
                    "Solver '%s' failed after %.2f seconds.",
                    solver.vulnerability_type,
                    end_time - start_time,
                )
                master_result["messages"].append(
                    f"Error in {solver.vulnerability_type} solver: {str(e)}"
                )

        return master_result
