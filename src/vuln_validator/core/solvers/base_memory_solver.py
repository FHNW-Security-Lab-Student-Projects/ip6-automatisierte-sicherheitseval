from .base_solver import BaseSolver
from abc import abstractmethod
import angr
import claripy
from itertools import chain
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class BaseMemorySolver(BaseSolver):
    """
    Base class for memory-related vulnerability solvers.
    Provides common utilities for handling symbolic pointers and memory state.
    """

    def solve(
        self,
        project: angr.Project,
        target_function: str = None,
        function_args: List[Any] = None,
    ) -> Dict[str, Any]:
        logger.info("Running %s solver...", self.vulnerability_type)

        if not target_function:
            return self._build_result(False, None, [], "No target function specified.")

        if not project.kb.functions:
            project.analyses.CFGFast()

        # 1. Environment Setup
        self._setup_environment(project)

        # 1. Function Address Resolution
        try:
            symbol = project.loader.main_object.get_symbol(target_function)
            if symbol is None:
                raise KeyError
            addr = project.kb.functions[symbol.rebased_addr].addr
            logger.debug(
                "Target function '%s' found at address: 0x%x", target_function, addr
            )
        except KeyError:
            logger.error("Target function '%s' not found in binary.", target_function)
            return self._build_result(
                False,
                target_function,
                [],
                f"Analysis aborted: Target function '{target_function}' does not exist or has no symbol table entry.",
            )

        # 2. Initial State Setup
        symbolic_stdin = claripy.BVS("my_input", 512 * 8)
        state = project.factory.call_state(addr, stdin=symbolic_stdin)
        logger.info(
            "Initial state created for function '%s' at address 0x%x",
            target_function,
            addr,
        )

        # 3. Specific setup delegation (The child solver does the magic)
        symbolic_args = self._place_buffers_and_canaries(state, project, function_args)

        if symbolic_args is None:  # Error during buffer/canary setup
            return self._build_result(
                False, target_function, [], "Failed to setup buffers."
            )

        # 4. Simulation Loop
        simgr = project.factory.simulation_manager(state)
        step_count = 0
        max_steps = 500
        step_size = 1

        while len(simgr.active) > 0 and step_count < max_steps:
            if len(simgr.unconstrained) > 0 or len(simgr.errored) > 0:
                logger.info(
                    "Found %d unconstrained and %d errored states at step %d. Stopping early.",
                    len(simgr.unconstrained),
                    len(simgr.errored),
                    step_count,
                )
                break
            simgr.step(n=step_size)
            step_count += step_size

        if len(simgr.errored) > 0:
            logger.warning(
                "Ignoring %d errored states (not inspectable here).",
                len(simgr.errored),
            )
            for err in simgr.errored:
                logger.warning("Errored state reason: %s", err.error)

        # 5. Collect canaries from all states (heap/stack)
        canaries = self._collect_canaries(simgr)

        # 6. Evaluation of results
        return self._evaluate_results(
            simgr, canaries, symbolic_args, symbolic_stdin, target_function
        )

    @abstractmethod
    def _place_buffers_and_canaries(self, state, project, function_args):
        """
        Has to be implemented by the child solver.
        Return: (symbolic_args)
        """
        pass

    def _collect_canaries(self, simgr):
        canaries = []
        for state in chain(simgr.active, simgr.deadended, simgr.unconstrained):
            if "canary_list" in state.globals:
                for chunk in state.globals["canary_list"]:
                    canaries.append(chunk)
        return canaries

    def _evaluate_results(
        self, simgr, canaries, symbolic_args, symbolic_stdin, target_function
    ):
        found_vuln = False
        evidence_list = []
        canary_hit = False

        # Check 1: Symbolic RIP (Control Flow Hijack)
        for state in simgr.unconstrained:
            if state.solver.symbolic(state.regs.rip):
                vuln_data = self._get_cause(state, symbolic_args, symbolic_stdin)
                vuln_data["state_type"] = "unconstrained"
                vuln_data["description"] = (
                    "Unconstrained state with symbolic RIP detected."
                )
                evidence_list.append(vuln_data)
                found_vuln = True

        # Check 2: Canaries (Data Corruption)
        for state in chain(simgr.active, simgr.deadended, simgr.unconstrained):
            if canary_hit:
                break
            for c in canaries:
                try:
                    current_value = state.memory.load(
                        c["addr"],
                        c["padding_size"],
                        endness=state.project.arch.memory_endness,
                    )
                    is_hit = False
                    reason = ""

                    if state.solver.symbolic(current_value):
                        is_hit = True
                        reason = "symbolic"
                    else:
                        concrete_value = state.solver.eval(current_value)
                        if concrete_value != c["expected"]:
                            is_hit = True
                            reason = f"modified to {hex(concrete_value)}"

                    if is_hit:
                        canary_hit = True
                        vuln_data = self._get_cause(
                            state, symbolic_args, symbolic_stdin
                        )
                        vuln_data["state_type"] = "canary_hit"
                        vuln_data["description"] = (
                            f"Canary at 0x{c['addr']:x} {reason}. Indicates overflow."
                        )
                        evidence_list.append(vuln_data)
                        break
                except Exception as e:
                    logger.warning(
                        "Failed to check canary at address 0x%x: %s", c["addr"], e
                    )
                    continue

            if canary_hit:
                found_vuln = True
                break

        if found_vuln:
            msg = f"{self.vulnerability_type.replace('_', ' ').title()} confirmed in '{target_function}'."
        else:
            msg = f"No {self.vulnerability_type.replace('_', ' ').title()} found in '{target_function}'."

        return self._build_result(found_vuln, target_function, evidence_list, msg)

    def _get_cause(
        self,
        state,
        symbolic_args: List[Any],
        symbolic_stdin: Any,
    ) -> Dict[str, Any]:  # state_type is either "errored" or "unconstrained"
        details = {
            "input_hex": {},
        }
        if symbolic_args:
            for idx, sym_arg in enumerate(symbolic_args):
                try:
                    val = state.solver.eval(sym_arg, cast_to=bytes)
                    details["input_hex"][f"arg_{idx}"] = val.hex()
                except Exception as e:
                    logger.warning(
                        "Failed to extract arg %d from %s state: %s",
                        idx,
                        e,
                    )
                    details["input_hex"][f"arg_{idx}"] = "Extraction failed"
        else:
            try:
                poc = state.solver.eval(symbolic_stdin, cast_to=bytes)
                details["input_hex"]["stdin"] = poc.hex()
            except Exception as e:
                logger.warning(
                    "Failed to extract stdin from %s state: %s",
                    e,
                )
                details["input_hex"]["stdin"] = "Extraction failed"

        logger.debug("Extracted details for %s state: %s", state, details)
        return details

    def _build_result(
        self,
        is_vulnerable: bool = False,
        target_function: str = None,
        evidence: List[Dict] = [],
        message: str = "",
    ) -> Dict[str, Any]:
        return {
            "is_vulnerable": is_vulnerable,
            "type": self.vulnerability_type,
            "target_function": target_function,
            "evidence": evidence,
            "message": message,
        }
