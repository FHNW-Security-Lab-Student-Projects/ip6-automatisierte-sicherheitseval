from .base_solver import BaseSolver
from ._evaluation import evaluate_results
from .dwarf_analyzer import DwarfAnalyzer
from abc import abstractmethod
import angr
import claripy
import threading
from itertools import chain
from typing import List, Dict, Any
import logging
from ...utils.config_loader import get_config
from .hooks.scanf_hooks import ScanfHook

logger = logging.getLogger(__name__)


class BaseMemorySolver(BaseSolver):
    """
    Base class for memory-related vulnerability solvers.
    Provides common utilities for handling symbolic pointers and memory state.
    """

    def _install_generic_input_hooks(self, project):
        for sym_name in ("scanf", "__isoc99_scanf", "__isoc99_scanf_chk"):
            if project.loader.find_symbol(sym_name) is not None:
                project.hook_symbol(sym_name, ScanfHook())
                logger.debug("Hooked scanf to avoid symbolic parsing errors.")

    def solve(
        self,
        project: angr.Project,
        target_function: str = None,
        function_args: List[Any] = None,
        structs: List[Dict[str, Any]] = None,
        stop_event: threading.Event = None,
    ) -> Dict[str, Any]:
        logger.info("Running %s solver...", self.vulnerability_type)

        structs = structs or []

        if not target_function:
            return self._build_result(False, None, [], "No target function specified.")

        # Ensure CFG is available for function resolution
        if not project.kb.functions:
            project.analyses.CFGFast()

        # 1. Environment Setup
        self._setup_environment(project)
        self._install_generic_input_hooks(project)

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

        # 3. Initial State Creation
        # Load solver config
        cfg = get_config()
        symbolic_stdin_bytes = cfg["solver"]["base_memory"]["input"][
            "symbolic_stdin_bytes"
        ]

        # Create symbolic content for stdin and put it into a SimFile
        symbolic_content = claripy.BVS("my_input", symbolic_stdin_bytes * 8)
        stdin_file = angr.SimFile("stdin", content=symbolic_content)

        # Create a symbolic argc for the entry state
        sym_argc = claripy.BVS("argc", 32)
        state = project.factory.entry_state(stdin=stdin_file, argc=sym_argc)
        logger.info(
            "Initial entry state created with symbolic stdin of %d bytes and symbolic argc.",
            symbolic_stdin_bytes,
        )

        # Create a simulation manager to explore the binary and find the target function. Reason: so global mallocs are initialized
        simgr = project.factory.simulation_manager(state)
        simgr.explore(find=addr, num_find=1)

        # If the target function is found, use the found state; otherwise, create a new call state for the target function (backup in case target function is not reachable from entry)
        if len(simgr.found) > 0:
            state = project.factory.call_state(
                addr, stdin=stdin_file, base_state=simgr.found[0]
            )
            logger.info(
                "Target function '%s' found during exploration. Using the found state.",
                target_function,
            )
        else:
            state = project.factory.call_state(addr, stdin=stdin_file)
            logger.warning(
                "Target function '%s' not reachable from entry. Created a new call state for the function. Globals may not be initialized properly.",
                target_function,
            )
        symbolic_stdin = state.posix.stdin.load(0, symbolic_stdin_bytes)

        # Old RSP value for stack-based struct address calculations
        old_rsp = state.solver.eval(state.regs.rsp)
        logger.debug("Initial RSP: 0x%x", old_rsp)

        # Advance past prologue to find stable RSP for stack-based solvers
        state = self._advance_past_prologue(project, state)

        dwarf_analyzer = DwarfAnalyzer(project)

        # adjust dynamic libc limits from stack locals
        dwarf_analyzer.adjust_libc_limits(state, addr)

        # 4. Specific setup delegation (The child solver does the magic)
        symbolic_args = self._place_buffers_and_canaries(state, project, function_args)

        if symbolic_args is None:  # Error during buffer/canary setup
            return self._build_result(
                False, target_function, [], "Failed to setup buffers."
            )

        # get struct addresses for struct in stored in stack und structs passed as arguments
        struct_addresses = self._resolve_struct_addresses(
            state, project, addr, structs, dwarf_analyzer, old_rsp, None
        )

        # 5. Simulation Loop
        simulation_cfg = get_config()["solver"]["base_memory"]["simulation"]
        simgr = project.factory.simulation_manager(state)

        # Loop bound for LocalLoopSeer to prevent infinite loops during symbolic execution
        loop_bound = simulation_cfg.get("loop_bound", 10)
        local_loop_seer = angr.exploration_techniques.LocalLoopSeer(bound=loop_bound)
        simgr.use_technique(local_loop_seer)

        step_count = 0
        max_steps = simulation_cfg["max_steps"]
        step_size = simulation_cfg["step_size"]
        logger.debug(
            "Config: max_steps=%d, step_size=%d",
            max_steps,
            step_size,
        )
        max_simngr_active = 0
        while len(simgr.active) > 0 and step_count < max_steps:
            if stop_event and stop_event.is_set():
                logger.warning(
                    f"Solver '{self.vulnerability_type}' received stop signal. Aborting gracefully."
                )
                break
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
            max_simngr_active = max(max_simngr_active, len(simgr.active))
        logger.info("simgr max active states: %d", max_simngr_active)

        msg = None
        if step_count >= max_steps:
            logger.warning(
                "Reached maximum simulation steps (%d) without finding unconstrained or errored states.",
                max_steps,
            )
            msg = f"Reached maximum simulation steps ({max_steps}) with active states remaining and no unconstrained or errored states found. The analysis may be incomplete. Consider increasing the max_steps in the config."

        if len(simgr.errored) > 0:
            logger.warning(
                "Ignoring %d errored states (not inspectable here).",
                len(simgr.errored),
            )
            for err in simgr.errored:
                logger.warning("Errored state reason: %s", err.error)

        # 6. Collect canaries from all states (heap/stack)
        canaries = self._collect_canaries(simgr)

        struct_addresses = self._resolve_struct_addresses(
            state, project, addr, structs, dwarf_analyzer, old_rsp, simgr
        )

        # 7. Evaluation of results
        return evaluate_results(
            simgr,
            canaries,
            symbolic_args,
            symbolic_stdin,
            target_function,
            structs,
            struct_addresses,
            msg,
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
        buffer_padding: int = 0x0,
    ):
        """
        Places arguments in registers and/or memory as needed, and returns a list of symbolic variables for the arguments.
        Supports both concrete and symbolic arguments, as well as struct arguments (which are treated as symbolic buffers).
        """
        symbolic_args = []
        buffer_infos = []
        regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        has_pointer = False
        max_size = 0

        cfg = get_config()
        arg_start = cfg["solver"]["memory_layout"]["arg_start"]
        current_offset = 0
        # safety net of zeros to the memory region starting from arg_start to prevent angr from reading uninitialized memory
        safety_net = 0x4000
        state.memory.store(
            arg_start,
            claripy.BVV(0, safety_net * 8),
            endness=project.arch.memory_endness,
        )

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
                        is_struct = arg.get("is_struct", False)
                        if is_struct:
                            var = claripy.BVV(0, size * 8)
                        else:
                            var = claripy.BVS(f"arg_{i}", size * 8)
                            symbolic_args.append(var)

                        if arg_type == "pointer":
                            has_pointer = True
                            max_size = max(max_size, size)

                            pad = buffer_padding
                            current_offset += size + pad
                            buffer_addr = arg_start - current_offset
                            current_offset += pad

                            logger.debug(
                                "Storing symbolic argument %d at address: 0x%x",
                                i,
                                buffer_addr,
                            )
                            state.memory.store(buffer_addr, var)

                            buffer_infos.append(
                                {"addr": buffer_addr, "size": size, "arg_idx": i}
                            )

                            self._write_to_register(regs, state, i, buffer_addr)
                        elif arg_type == "variable":
                            self._write_to_register(regs, state, i, var)
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
        """Writes the given buffer address to the appropriate register based on the argument index."""
        if i < len(regs):
            setattr(state.regs, regs[i], buffer_addr)
        else:
            logger.warning(
                "More than 6 arguments provided. Additional arguments beyond the 6th are not yet supported in this implementation."
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
        """
        Advances the state past the function prologue to find a stable RSP value for stack-based solvers.
        This is necessary because the initial call state may have an RSP that is not yet adjusted by the function prologue, which can cause issues for solvers that rely on stack-based memory layouts
        """
        prev_rsp = state.solver.eval(state.regs.rsp)
        logger.debug(
            "Advancing past function prologue to find stable RSP. Initial RSP: 0x%x",
            prev_rsp,
        )

        for _ in range(max_inst):
            succ = project.factory.successors(state, num_inst=1)
            if len(succ.successors) != 1:
                break

            state = succ.successors[0]
            rsp = state.solver.eval(state.regs.rsp)

            # Once we see a significant decrease in RSP, we can assume we've passed the prologue (which typically pushes the old RSP and sets up the new stack frame)
            if rsp + 0x8 < prev_rsp:
                break

        return state

    def _resolve_struct_addresses(
        self, state, project, func_addr, structs, dwarf_analyzer, old_rsp, simgr=None
    ):
        """
        Resolves addresses for structs based on their specified location (stack, heap, or argument).
        For stack structs, it uses DWARF information to calculate the address based on the current RSP and the struct's offset from the stack frame.
        For heap structs, it looks for allocations recorded in the state globals (which should have been populated by the heap hooks).
        For argument structs, it reads the address directly from the appropriate register based on the argument index.
        """
        if not structs:
            return []

        struct_addresses = {}
        # Get current RBP for stack-based struct address calculations (CFA calculations)
        current_rbp = state.solver.eval(state.regs.rbp)
        logger.debug("Current RBP: 0x%x", current_rbp)

        for struct in structs:
            if isinstance(struct, dict):
                struct_location = struct.get("location")
                struct_name = struct.get("name")
                if struct_addresses.get(struct_name):
                    logger.debug(
                        f"Struct '{struct_name}' already resolved at address 0x{struct_addresses[struct_name]:x}."
                    )
                    continue
                if struct_location == "stack":
                    struct_offset = dwarf_analyzer.get_struct_stack_addr(
                        func_addr, struct_name, state
                    )
                    if struct_offset is not None:
                        retaddr_size = state.arch.bytes
                        # cfa is rsp value at function entry, but with call_state we start after the call instruction, so we need to add the size of the return address to get the original CFA
                        cfa = old_rsp + retaddr_size
                        logger.debug(
                            f"Calculated CFA (Canonical Frame Address) for struct '{struct_name}': 0x{cfa:x} (old RSP: 0x{old_rsp:x} + retaddr size: 0x{retaddr_size:x})"
                        )
                        struct_addr = cfa + struct_offset  # struct_offset is negative!
                        logger.debug(
                            f"Resolved struct '{struct_name}' address: 0x{struct_addr:x} with rbp: 0x{current_rbp:x}"
                        )
                        struct_addresses[struct_name] = struct_addr
                    else:
                        logger.debug(
                            f"Could not resolve address for struct '{struct_name}' via DWARF"
                        )
                elif struct_location == "heap":
                    if simgr is None:
                        continue
                    for state in simgr.deadended:
                        list = state.globals.get("allocations", None)
                        if list is None:
                            continue
                        for item in list:
                            addr = item.get("addr")
                            if addr in struct_addresses.values():
                                list.remove(item)
                                continue
                            else:
                                break

                        content = item["addr"]
                        struct_addresses[struct_name] = content

                elif struct_location == "arg":
                    regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
                    struct_arg_idx = struct.get("arg_index")
                    struct_addr = state.solver.eval(
                        getattr(state.regs, regs[struct_arg_idx])
                    )
                    logger.debug(
                        f"Resolved struct '{struct_name}' address from argument {struct_arg_idx}: 0x{struct_addr:x}"
                    )
                    struct_addresses[struct_name] = struct_addr
                else:
                    logger.warning(
                        f"Unsupported struct location '{struct_location}' for struct '{struct_name}'. Skipping."
                    )
            else:
                logger.warning(
                    f"Invalid struct format: {struct}. Expected a dict with 'name' and 'location'. Skipping."
                )

        return struct_addresses
