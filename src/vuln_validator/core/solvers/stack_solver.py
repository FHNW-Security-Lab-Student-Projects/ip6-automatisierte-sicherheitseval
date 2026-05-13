from .base_memory_solver import BaseMemorySolver
import claripy
import logging

logger = logging.getLogger(__name__)


class StackOverflowSolver(BaseMemorySolver):

    @property
    def vulnerability_type(self) -> str:
        return "stack_overflow"

    def _setup_environment(self, project):
        pass

    def _place_buffers_and_canaries(self, state, project, function_args):

        symbolic_args = []
        current_offset = 0x80  # in bytes (128 bytes)
        padding_size = 0x4  # in bytes (4 bytes for canary)
        regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        has_pointer = False
        max_size = 0

        if "canary_list" not in state.globals:
            state.globals["canary_list"] = []

        if function_args:
            logger.info(
                "Placing buffers and canaries for function arguments: %s", function_args
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
                        size = arg.get(
                            "size", 64
                        )  # Default to 64-bit symbolic variable
                        # Create a symbolic variable for this argument
                        sym_var = claripy.BVS(f"arg_{i}", size * 8)
                        symbolic_args.append(sym_var)
                        if arg_type == "symbolic_pointer":
                            has_pointer = True
                            max_size = max(max_size, size)
                            # Increment offset for argument
                            current_offset += (
                                size + padding_size
                            )  # space for argument + overflow canary
                            buffer_addr = rsp - current_offset
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

                            for addr, kind in (
                                (canary_addr, "overflow"),
                                (canary_addr_underflow, "underflow"),
                            ):
                                state.memory.store(
                                    addr,
                                    claripy.BVV(canary_value, padding_size * 8),
                                    endness=project.arch.memory_endness,
                                )
                                state.globals["canary_list"].append(
                                    {
                                        "addr": addr,
                                        "expected": canary_value,
                                        "arg_idx": i,
                                        "padding_size": padding_size,
                                    }
                                )
                                logger.debug(
                                    "Placed %s canary for argument %d at address: 0x%x with expected value: 0x%x",
                                    kind,
                                    i,
                                    addr,
                                    canary_value,
                                )

                            self._write_to_register(regs, state, i, buffer_addr)
                else:
                    # Treat as concrete value (Fallback)
                    self._write_to_register(regs, state, i, arg)

            if has_pointer:
                # Ensure the libc plugin is aware of the maximum symbolic buffer size to prevent it from optimizing away symbolic memory accesses
                if hasattr(state, "libc"):
                    bound = max_size + 1
                    state.libc.max_str_len = max(state.libc.max_str_len, bound)
                    # This is a bit of a hack to ensure that the symbolic buffers we place are not optimized away by the libc plugin. By setting buf_symbolic_bytes to a value larger than any symbolic buffer we create, we can prevent the plugin from treating those buffers as concrete.
                    state.libc.buf_symbolic_bytes = max(
                        state.libc.buf_symbolic_bytes, bound
                    )

        return symbolic_args

    def _write_to_register(self, regs, state, i, buffer_addr):
        if i < len(regs):
            setattr(state.regs, regs[i], buffer_addr)
        else:
            logger.warning(
                "More than 6 arguments provided. Additional arguments beyond the 6th are not supported in this implementation."
            )
