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
        self,
        project: angr.Project,
        target_function: str = None,
        function_args: List[Any] = None,
    ) -> Dict[str, Any]:
        logger.info("Running %s solver...", self.vulnerability_type)

        if not target_function:
            return {
                "is_vulnerable": False,
                "target_function": None,
                "evidence": [],
                "message": "Stack overflow analysis aborted: No target function specified.",
            }

        # Generate CFG if not already available, for function resolution and analysis
        if not project.kb.functions:
            project.analyses.CFGFast()

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
                target_function=target_function,
                message=f"Stack overflow analysis aborted: Target function '{target_function}' does not exist or has no symbol table entry.",
            )

        symbolic_stdin = claripy.BVS("my_input", 512 * 8)
        symbolic_args = []
        current_offset = 0x80

        regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

        state = project.factory.call_state(addr, stdin=symbolic_stdin)
        logger.info("Created call state for function: %s", target_function)

        if function_args:
            logger.info(
                "Function arguments provided for '%s': %s",
                target_function,
                function_args,
            )
            for i, arg in enumerate(function_args):
                logger.debug("Processing argument %d: %s", i, arg)
                if isinstance(arg, dict):
                    if arg.get("type") == "concrete":
                        value = arg.get("value", 0)
                        self._write_to_register(regs, state, i, value)
                    else:
                        # Create a symbolic variable for this argument
                        sym_var = claripy.BVS(
                            f"arg_{i}", arg.get("size", 64) * 8
                        )  # Default to 64-bit symbolic variable
                        symbolic_args.append(sym_var)
                        if arg.get("type") == "symbolic_pointer":
                            # Increment offset for argument
                            current_offset += arg.get("size", 64)
                            # TODO Bereich schaffen welcher danach überprüft wird ob unconstrained
                            buffer_addr = (
                                state.solver.eval(state.regs.rsp) - current_offset
                            )
                            logger.info(
                                "Storing symbolic argument %d at address: 0x%x",
                                i,
                                buffer_addr,
                            )
                            state.memory.store(buffer_addr, sym_var)

                            self._write_to_register(regs, state, i, buffer_addr)
                else:
                    # Treat as concrete value (Fallback)
                    self._write_to_register(regs, state, i, arg)

            logger.info(
                "Created call state for function '%s' with symbolic arguments: %s",
                target_function,
                symbolic_args,
            )

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

        found_vuln = False
        evidence_list = []

        states_to_check = [
            (simgr.errored, "errored"),
            (simgr.unconstrained, "unconstrained"),
        ]

        for state_list, state_type in states_to_check:
            for state in state_list:
                if state.solver.symbolic(state.regs.rip):
                    vuln_data = self._extract_details(
                        state,
                        state_type,
                        symbolic_args,
                        symbolic_stdin,
                    )
                    evidence_list.append(vuln_data)
                    found_vuln = True

        if found_vuln:
            message = (
                f"Stack Overflow confirmed in {target_function}."
                f" Control flow hijack possible via symbolic RIP. "
            )
        else:
            message = (
                f"No stack overflow found in {target_function} after exploring {step_count} steps. "
                f" States terminated normally or crashed with concrete RIP."
            )

        return self._build_result(found_vuln, target_function, evidence_list, message)

    def _write_to_register(self, regs, state, i, buffer_addr):
        if i < len(regs):
            setattr(state.regs, regs[i], buffer_addr)
        else:
            logger.warning(
                "More than 6 arguments provided. Additional arguments beyond the 6th are not supported in this implementation."
            )

    def _extract_details(
        self,
        state,
        state_type,
        symbolic_args: List[Any],
        symbolic_stdin: Any,
    ) -> Dict[str, Any]:  # state_type is either "errored" or "unconstrained"
        details = {
            "state_type": state_type,
            "input_hex": {},
            "description": f"{state_type.capitalize()} state with symbolic RIP detected.",
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
                        state_type,
                        e,
                    )
                    details["input_hex"][f"arg_{idx}"] = "Extraction failed"
        else:
            try:
                poc = state.solver.eval(symbolic_stdin, cast_to=bytes)
                details["input_hex"]["stdin"] = poc.hex()
            except Exception as e:
                logger.warning(
                    "Failed to extract input from %s state: %s", state_type, str(e)
                )
                details["input_hex"]["stdin"] = "Extraction failed"

        logger.info("Extracted details from %s state: %s", state_type, details)
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
