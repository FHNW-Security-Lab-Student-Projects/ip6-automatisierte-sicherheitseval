from .base_solver import BaseSolver
import angr
import claripy
from typing import Dict, Any
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
        analysis_mode = "targeted" if target_function else "full_binary"

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
                return {
                    "is_vulnerable": False,
                    "type": self.vulnerability_type,
                    "mode": analysis_mode,
                    "evidence": {
                        "error": f"Symbol '{target_function}' not found in binary."
                    },
                    "message": f"Analysis aborted: Target function '{target_function}' does not exist or has no symbol table entry.",
                }
            state = project.factory.call_state(addr, stdin=sym_input)
            logger.info("Created call state for function: %s", target_function)
        else:
            state = project.factory.entry_state(stdin=sym_input)
            logger.info("Creating entry state for the binary.")

        simgr = project.factory.simulation_manager(state)

        simgr.run(n=200)

        found_vuln = False
        vulnerabilities = []

        def extract_details(state, state_type):
            details = {"state_type": state_type, "input": None}
            try:
                poc = state.solver.eval(sym_input, cast_to=bytes)
                details["input"] = poc.hex()
            except Exception as e:
                logger.warning(
                    "Failed to extract input from %s state: %s", state_type, str(e)
                )
                details["input"] = "Extraction failed"

            logger.debug("Extracted details from %s state: %s", state_type, details)
            return details

        for err_state in simgr.errored:
            if err_state.solver.symbolic(err_state.regs.rip):
                vuln_data = extract_details(err_state, "errored")
                vulnerabilities.append(vuln_data)
                found_vuln = True
                logger.info("Errored state with symbolic RIP detected: %s", vuln_data)

        for u_state in simgr.unconstrained:
            if u_state.solver.symbolic(u_state.regs.rip):
                vuln_data = extract_details(u_state, "unconstrained")
                vulnerabilities.append(vuln_data)
                found_vuln = True
                logger.info(
                    "Unconstrained state with symbolic RIP detected: %s", vuln_data
                )

        logger.info(vulnerabilities)

        if found_vuln:
            return {
                "is_vulnerable": True,
                "type": self.vulnerability_type,
                "mode": analysis_mode,
                "target_function": target_function,
                "evidence": {
                    "count": len(vulnerabilities),
                    "findings": vulnerabilities,
                    "payload_hex": (
                        vulnerabilities[0]["input"] if vulnerabilities else None
                    ),
                },
                "message": (
                    f"Stack Overflow confirmed in {'function ' + target_function if target_function else 'binary'}."
                    f" Control flow hijack possible via symbolic RIP. "
                ),
            }
        else:
            return {
                "is_vulnerable": False,
                "type": self.vulnerability_type,
                "mode": analysis_mode,
                "target_function": target_function,
                "evidence": {
                    "count": 0,
                    "findings": [],
                    "errored_states": len(simgr.errored),
                    "unconstrained_states": len(simgr.unconstrained),
                },
                "message": (
                    f"No stack overflow found in {'function ' + target_function if target_function else 'binary'}."
                    f" States terminated normally or crashed with concrete RIP."
                ),
            }
