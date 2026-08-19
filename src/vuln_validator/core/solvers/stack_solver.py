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
        bv_args, buffers = self._place_args(
            state, project, function_args, buffer_padding=0x4
        )
        self._place_stack_canaries(state, project, buffers, padding_size=0x4)
        return bv_args

    def _place_stack_canaries(self, state, project, buffers, padding_size: int = 0x4):
        """
        For each buffer, places canaries both before and after the buffer to detect underflows and overflows.
        """
        if "canary_list" not in state.globals:
            state.globals["canary_list"] = []

        for buf in buffers:
            buffer_addr = buf["addr"]
            size = buf["size"]
            arg_idx = buf["arg_idx"]

            canary_addr = buffer_addr + size
            canary_addr_underflow = buffer_addr - padding_size
            canary_value = 0xDEADBEEF

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
                        "arg_idx": arg_idx,
                        "padding_size": padding_size,
                    }
                )
                logger.debug(
                    "Placed %s canary for argument %d at address: 0x%x with expected value: 0x%x",
                    kind,
                    arg_idx,
                    addr,
                    canary_value,
                )
