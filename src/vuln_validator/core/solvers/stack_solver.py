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

        if not project.kb.functions:
            project.analyses.CFGFast()

        if target_function:
            try:
                symbol = project.loader.main_object.get_symbol(target_function)
                if symbol is None:
                    raise KeyError
                addr = project.kb.functions[symbol.rebased_addr].addr
            except KeyError:
                logger.error(
                    "Target function '%s' not found in binary.", target_function
                )
                return {
                    "is_vulnerable": False,
                    "type": self.vulnerability_type,
                    "evidence": {},
                    "message": f"Target function '{target_function}' not found in binary.",
                }
            logger.info("Creating call state for function: %s", target_function)
            state = project.factory.call_state(addr, stdin=sym_input)
        else:
            logger.info("Creating entry state for the binary.")
            state = project.factory.entry_state(stdin=sym_input)

        simgr = project.factory.simulation_manager(state)

        simgr.run(n=200)

        found_vuln = False

        if len(simgr.errored) > 0:
            logger.info("Potential stack overflow detected!")
            for errored_state in simgr.errored:
                if state.solver.symbolic(errored_state.regs.rip):
                    poc = errored_state.solver.eval(sym_input, cast_to=bytes)
                    logger.info(
                        "Proof of Concept (input that causes overflow): %s", poc
                    )
                    found_vuln = True

        if len(simgr.unconstrained) > 0:
            logger.info(
                "%s unconstrained states found. Checking for symbolic RIP...",
                len(simgr.unconstrained),
            )
            for u_state in simgr.unconstrained:
                if u_state.solver.symbolic(u_state.regs.rip):
                    logger.info(
                        "RIP is symbolic in unconstrained state (Control Flow Hijack)!"
                    )
                    poc = u_state.solver.eval(sym_input, cast_to=bytes)
                    logger.info("Proof of Concept (Hex): %s", poc.hex())
                    logger.debug("Proof of Concept (Raw): %s", poc)
                    found_vuln = True

        if not found_vuln:
            logger.info("No stack overflow detected.")

        return {
            "is_vulnerable": found_vuln,
            "type": self.vulnerability_type,
            "evidence": {
                "errored_states": len(simgr.errored),
                "unconstrained_states": len(simgr.unconstrained),
            },
            "message": (
                "Stack overflow vulnerability detected."
                if found_vuln
                else "No stack overflow vulnerability detected."
            ),
        }
