from .base_solver import BaseSolver
from ._evaluation import evaluate_results
from .dwarf_analyzer import DwarfAnalyzer
from abc import abstractmethod
import angr
import claripy
from itertools import chain
from typing import List, Dict, Any
import logging
from ...utils.config_loader import get_base_memory_solver_config

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
        structs: List[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        logger.info("Running %s solver...", self.vulnerability_type)

        structs = structs or []

        if not target_function:
            return self._build_result(False, None, [], "No target function specified.")

        if not project.kb.functions:
            project.analyses.CFGFast()

        # 1. Environment Setup
        self._setup_environment(project)

        # Load solver config
        solver_cfg = get_base_memory_solver_config()
        symbolic_stdin_bytes = solver_cfg["symbolic_stdin_bytes"]

        # 2. Function Address Resolution
        try:
            symbol = project.loader.main_object.get_symbol(target_function)
            if symbol is None:
                logger.debug(
                    "Try for C++ name mangling for function '%s'", target_function
                )
                for sym in project.loader.main_object.symbols:
                    if target_function in sym.name:
                        symbol = sym
                if symbol is None:
                    logger.error(
                        "Target function '%s' not found in binary.", target_function
                    )
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

        # 3. Initial State Setup
        symbolic_stdin = claripy.BVS("my_input", symbolic_stdin_bytes * 8)
        state = project.factory.call_state(addr, stdin=symbolic_stdin)
        logger.info(
            "Initial state created for function '%s' at address 0x%x",
            target_function,
            addr,
        )

        old_rsp = state.solver.eval(state.regs.rsp)
        logger.debug("Initial RSP: 0x%x", old_rsp)

        # Advance past prologue to find stable RSP for stack-based solvers
        state = self._advance_past_prologue(project, state)

        dwarf_analyzer = DwarfAnalyzer(project)

        # struct_addresses = self._resolve_struct_addresses(
        #     state, project, addr, structs, dwarf_analyzer, old_rsp
        # )

        # adjust dynamic libc limits from stack locals
        dwarf_analyzer.adjust_libc_limits(state, addr)

        # 4. Specific setup delegation (The child solver does the magic)
        symbolic_args = self._place_buffers_and_canaries(state, project, function_args)

        struct_addresses = self._resolve_struct_addresses(
            state, project, addr, structs, dwarf_analyzer, old_rsp
        )

        if symbolic_args is None:  # Error during buffer/canary setup
            return self._build_result(
                False, target_function, [], "Failed to setup buffers."
            )

        # 5. Simulation Loop
        simgr = project.factory.simulation_manager(state)
        step_count = 0
        max_steps = solver_cfg["max_steps"]
        step_size = solver_cfg["step_size"]
        logger.debug(
            "Config: max_steps=%d, step_size=%d",
            max_steps,
            step_size,
        )

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

        # 6. Collect canaries from all states (heap/stack)
        canaries = self._collect_canaries(simgr)

        # 7. Evaluation of results
        return evaluate_results(
            simgr,
            canaries,
            symbolic_args,
            symbolic_stdin,
            target_function,
            structs,
            struct_addresses,
            self.vulnerability_type,
            self._build_result,
        )

    @abstractmethod
    def _place_buffers_and_canaries(self, state, project, function_args):
        """
        Has to be implemented by the child solver.
        Return: (symbolic_args)
        """
        pass

    def _place_symbolic_args(
        self,
        state,
        project,
        function_args,
        *,
        base_offset: int = 0x80,  # because of redzone
        buffer_padding: int = 0x0,
    ):
        symbolic_args = []
        buffer_infos = []
        current_offset = base_offset
        regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        has_pointer = False
        max_size = 0

        if function_args:
            logger.info(
                "Placing buffers for function arguments: %s",
                function_args,
            )
            rsp = state.solver.eval(state.regs.rsp)
            logger.debug("Initial RSP value: 0x%x", rsp)

            for i, arg in enumerate(function_args):
                logger.debug("Processing argument %d: %s", i, arg)
                if isinstance(arg, dict):
                    arg_type = arg.get("type")
                    if arg_type == "concrete":
                        value = arg.get("value", 0)
                        self._write_to_register(regs, state, i, value)
                    else:
                        size = arg.get("size", 64)
                        sym_var = claripy.BVS(f"arg_{i}", size * 8)
                        symbolic_args.append(sym_var)

                        if arg_type == "struct_pointer" or arg_type == "struct_value":
                            sym_var = claripy.BVV(0, size * 8)

                        if (
                            arg_type == "symbolic_pointer"
                            or arg_type == "struct_pointer"
                        ):
                            has_pointer = True
                            max_size = max(max_size, size)

                            pad = buffer_padding
                            current_offset += size + pad
                            buffer_addr = rsp - current_offset
                            if pad:
                                current_offset += pad

                            logger.debug(
                                "Storing symbolic argument %d at address: 0x%x",
                                i,
                                buffer_addr,
                            )
                            state.memory.store(buffer_addr, sym_var)

                            buffer_infos.append(
                                {"addr": buffer_addr, "size": size, "arg_idx": i}
                            )

                            self._write_to_register(regs, state, i, buffer_addr)
                else:
                    self._write_to_register(regs, state, i, arg)

            # Because _max_local_size_from_dwarf doesn't know about the actual argument sizes (only pointer size)
            if has_pointer and hasattr(state, "libc"):
                bound = max_size + 1
                state.libc.max_str_len = max(state.libc.max_str_len, bound)
                state.libc.buf_symbolic_bytes = max(
                    state.libc.buf_symbolic_bytes, bound
                )

        return symbolic_args, buffer_infos

    def _write_to_register(self, regs, state, i, buffer_addr):
        if i < len(regs):
            setattr(state.regs, regs[i], buffer_addr)
        else:
            logger.warning(
                "More than 6 arguments provided. Additional arguments beyond the 6th are not supported in this implementation."
            )

    def _collect_canaries(self, simgr):
        canaries = []
        for state in chain(simgr.active, simgr.deadended, simgr.unconstrained):
            if "canary_list" in state.globals:
                for chunk in state.globals["canary_list"]:
                    canaries.append(chunk)
        return canaries

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

    def _advance_past_prologue(self, project, state, max_inst: int = 32):
        prev_rsp = state.solver.eval(state.regs.rsp)
        logger.info(
            "Advancing past function prologue to find stable RSP. Initial RSP: 0x%x",
            prev_rsp,
        )

        for _ in range(max_inst):
            succ = project.factory.successors(state, num_inst=1)
            if len(succ.successors) != 1:
                break

            state = succ.successors[0]
            rsp = state.solver.eval(state.regs.rsp)
            logger.debug("Current RSP: 0x%x", rsp)

            if rsp + 0x8 < prev_rsp:
                break

        return state

    def _resolve_struct_addresses(
        self, state, project, func_addr, structs, dwarf_analyzer, old_rsp
    ):
        """Resolves runtime stack addresses of local variables via DWARF."""
        if not structs:
            return []

        all_struct_addresses = []
        current_rbp = state.solver.eval(state.regs.rbp)
        logger.debug("Current RBP: 0x%x", current_rbp)

        for struct in structs:
            if isinstance(struct, dict):
                struct_location = struct.get("location")
                struct_name = struct.get("name")
                if struct_location == "stack":
                    struct_offset = dwarf_analyzer.get_struct_stack_addr(
                        func_addr, struct_name, state
                    )
                    if struct_offset is not None:
                        retaddr_size = state.arch.bytes
                        cfa = old_rsp + retaddr_size
                        logger.debug(
                            f"Calculated CFA (Canonical Frame Address) for struct '{struct_name}': 0x{cfa:x} (old RSP: 0x{old_rsp:x} + retaddr size: 0x{retaddr_size:x})"
                        )
                        struct_addr = cfa + struct_offset  # struct_offset is negative!
                        logger.debug(
                            f"Resolved struct '{struct_name}' address: 0x{struct_addr:x} with rbp: 0x{current_rbp:x}"
                        )
                        all_struct_addresses.append(
                            struct_addr
                        )  # TODO: don't append but put at correct index
                    else:
                        logger.debug(
                            f"Could not resolve address for struct '{struct_name}' via DWARF"
                        )
                elif struct_location == "heap":
                    logger.warning(
                        f"Heap-based struct '{struct_name}' resolution not implemented. Skipping."
                    )
                elif struct_location == "arg":
                    regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
                    struct_arg_idx = struct.get("arg_index")
                    struct_addr = state.solver.eval(
                        getattr(state.regs, regs[struct_arg_idx])
                    )
                    logger.debug(
                        f"Resolved struct '{struct_name}' address from argument {struct_arg_idx}: 0x{struct_addr:x}"
                    )
                    all_struct_addresses.append(struct_addr)
                else:
                    logger.warning(
                        f"Unsupported struct location '{struct_location}' for struct '{struct_name}'. Skipping."
                    )
            else:
                logger.warning(
                    f"Invalid struct format: {struct}. Expected a dict with 'name' and 'location'. Skipping."
                )

        return all_struct_addresses
