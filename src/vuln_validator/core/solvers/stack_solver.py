from .base_solver import BaseSolver
import angr
import claripy
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class StackOverflowSolver(BaseSolver):

    @property
    def vulnerability_type(self) -> str:
        return "stack_overflow"

    def solve(
        self, project: angr.Project, target_function: str = None
    ) -> Dict[str, Any]:
        logger.info("Running %s solver...", self.vulnerability_type)

        sym_input = claripy.BVS("my_input", 256 * 8)

        if not project.kb.functions:
            project.analyses.CFGFast()

        if target_function:
            try:
                symbol = project.loader.main_object.get_symbol(target_function)
                if symbol is None:
                    raise KeyError
                addr = project.kb.functions[symbol.rebased_addr].addr
                logger.debug(
                    "Target function '%s' found at address: 0x%x", target_function, addr
                )
            except KeyError:
                logger.error(
                    "Target function '%s' not found in binary.", target_function
                )
                return self._build_result(
                    is_vulnerable=False,
                    target_function=target_function,
                    evidence=[],
                    message=f"Stack overflow analysis aborted: Target function '{target_function}' does not exist or has no symbol table entry.",
                )
            state = project.factory.call_state(addr, stdin=sym_input)
            logger.info("Created call state for function: %s", target_function)
        else:
            state = project.factory.entry_state(stdin=sym_input)
            logger.info("Creating entry state for the binary.")

        simgr = project.factory.simulation_manager(state)

        simgr.run(n=200)

        found_vuln = False
        evidence_list = []

        def extract_details(state, state_type):
            details = {
                "state_type": state_type,
                "input_hex": None,
                "description": f"{state_type.capitalize()} state with symbolic RIP detected.",
            }
            try:
                poc = state.solver.eval(sym_input, cast_to=bytes)
                details["input_hex"] = poc.hex()
            except Exception as e:
                logger.warning(
                    "Failed to extract input from %s state: %s", state_type, str(e)
                )
                details["input_hex"] = "Extraction failed"

            logger.debug("Extracted details from %s state: %s", state_type, details)
            return details

        states_to_check = [
            (simgr.errored, "errored"),
            (simgr.unconstrained, "unconstrained"),
        ]

        for state_list, state_type in states_to_check:
            for state in state_list:
                if state.solver.symbolic(state.regs.rip):
                    vuln_data = extract_details(state, state_type)
                    evidence_list.append(vuln_data)
                    found_vuln = True
                    logger.info(
                        "%s state with symbolic RIP detected: %s",
                        state_type.capitalize(),
                        vuln_data,
                    )

        if found_vuln:
            message = (
                f"Stack Overflow confirmed in {'function ' + target_function if target_function else 'binary'}."
                f" Control flow hijack possible via symbolic RIP. "
            )
        else:
            message = (
                f"No stack overflow found in {'function ' + target_function if target_function else 'binary'}."
                f" States terminated normally or crashed with concrete RIP."
            )

        return self._build_result(found_vuln, target_function, evidence_list, message)

    def _build_result(
        self,
        is_vulnerable: bool,
        target_function: str,
        evidence: List[Dict],
        message: str,
    ) -> Dict[str, Any]:
        return {
            "is_vulnerable": is_vulnerable,
            "type": self.vulnerability_type,
            "target_function": target_function,
            "evidence": evidence,
            "message": message,
        }
