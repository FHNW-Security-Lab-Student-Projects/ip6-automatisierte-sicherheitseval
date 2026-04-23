from .base_solver import BaseSolver
import angr
import claripy
from typing import List, Dict, Any
import logging
from itertools import chain

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
        current_offset = 0x80  # in bytes (128 bytes)
        padding_size = 0x4  # in bytes (4 bytes for canary)
        regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        canaries = []

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
                    arg_type = arg.get("type")
                    if arg_type == "concrete":
                        value = arg.get("value", 0)
                        self._write_to_register(regs, state, i, value)
                    else:
                        size = arg.get(
                            "size", 64
                        )  # Default to 64-bit symbolic variable
                        # Create a symbolic variable for this argument
                        sym_var = claripy.BVS(f"arg_{i}", size * 8)
                        symbolic_args.append(sym_var)
                        if arg_type == "symbolic_pointer":
                            # Increment offset for argument
                            current_offset += (
                                size + padding_size
                            )  # space for argument + overflow canary
                            buffer_addr = (
                                state.solver.eval(state.regs.rsp) - current_offset
                            )
                            current_offset += padding_size  # space for underflow canary
                            logger.debug(
                                "Storing symbolic argument %d at address: 0x%x",
                                i,
                                buffer_addr,
                            )
                            state.memory.store(buffer_addr, sym_var)

                            canary_addr = buffer_addr + size
                            canary_addr_underflow = buffer_addr - padding_size
                            canary_value = 0x41414141  # 'AAAA' in hex (4 bytes)

                            # claripy.BVV(value, size_in_bits)
                            state.memory.store(
                                canary_addr,
                                claripy.BVV(canary_value, padding_size * 8),
                                endness=project.arch.memory_endness,
                            )
                            canaries.append(
                                {
                                    "addr": canary_addr,
                                    "expected": canary_value,
                                    "arg_idx": i,
                                    "padding_size": padding_size,
                                }
                            )
                            logger.debug(
                                "Placed overflow canary for argument %d at address: 0x%x with expected value: 0x%x",
                                i,
                                canary_addr,
                                canary_value,
                            )
                            state.memory.store(
                                canary_addr_underflow,
                                claripy.BVV(canary_value, padding_size * 8),
                                endness=project.arch.memory_endness,
                            )
                            canaries.append(
                                {
                                    "addr": canary_addr_underflow,
                                    "expected": canary_value,
                                    "arg_idx": i,
                                    "padding_size": padding_size,
                                }
                            )
                            logger.debug(
                                "Placed underflow canary for argument %d at address: 0x%x with expected value: 0x%x",
                                i,
                                canary_addr_underflow,
                                canary_value,
                            )

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

        canary_hit = False

        for state in chain(simgr.errored, simgr.unconstrained):
            if state.solver.symbolic(state.regs.rip):
                state_type = "errored" if state in simgr.errored else "unconstrained"

                vuln_data = self._get_cause(
                    state,
                    symbolic_args,
                    symbolic_stdin,
                )
                vuln_data["state_type"] = state_type
                vuln_data["description"] = (
                    f"{state_type.capitalize()} state with symbolic RIP detected"
                )
                evidence_list.append(vuln_data)
                found_vuln = True

        for state in chain(
            simgr.active, simgr.deadended, simgr.unconstrained, simgr.errored
        ):
            for c in canaries:
                try:
                    current_value = state.memory.load(
                        c["addr"],
                        c["padding_size"],
                        endness=project.arch.memory_endness,
                    )
                    if state.solver.symbolic(current_value):
                        canary_hit = True
                        vuln_data = self._get_cause(
                            state,
                            symbolic_args,
                            symbolic_stdin,
                        )
                        vuln_data["state_type"] = "canary_symbolic"
                        vuln_data["description"] = (
                            f"Canary at address 0x{c['addr']:x} is symbolic, indicating potential overflow and control over canary value."
                        )
                        evidence_list.append(vuln_data)
                        break
                    else:
                        concrete_value = state.solver.eval(current_value)
                        logger.info(f"concrete value of canary: {hex(concrete_value)}")
                        if concrete_value != c["expected"]:
                            canary_hit = True
                            vuln_data = self._get_cause(
                                state,
                                symbolic_args,
                                symbolic_stdin,
                            )
                            vuln_data["state_type"] = "canary_modified"
                            vuln_data["description"] = (
                                f"Canary at address 0x{c['addr']:x} modified from expected value 0x{c['expected']:x} to {hex(concrete_value)}, indicating potential overflow that overwrote the canary."
                            )
                            evidence_list.append(vuln_data)
                            break
                except Exception as e:
                    logger.warning(
                        "Failed to check canary at address 0x%x: %s", c["addr"], e
                    )
            if canary_hit:
                found_vuln = True
                break

        if found_vuln or canary_hit:
            message = f"Stack Overflow confirmed in {target_function}."
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
