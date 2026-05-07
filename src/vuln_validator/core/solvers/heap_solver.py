from .base_memory_solver import BaseMemorySolver
import claripy
import logging
import angr

logger = logging.getLogger(__name__)


class MyFakeMalloc(angr.SimProcedure):
    HEAP_START = claripy.BVV(0x600000, 64)

    def run(self, size):
        if "heap_ptr" not in self.state.globals:
            self.state.globals["heap_ptr"] = self.HEAP_START
            self.state.globals["heap_canary_list"] = []

        ret_addr = self.state.globals["heap_ptr"]

        canary_addr = ret_addr + size
        self.state.memory.store(
            canary_addr,
            claripy.BVV(0xDEADBEEF, 32),
            endness=self.state.arch.memory_endness,
        )
        self.state.globals["heap_canary_list"].append(
            {
                "addr": self.state.solver.eval(canary_addr),
                "expected": 0xDEADBEEF,
                "padding_size": 4,  # Default für Heap Canary
                "source": "malloc_hook",
            }
        )

        self.state.globals["heap_ptr"] = canary_addr + 0x4

        return ret_addr


class HeapOverflowSolver(BaseMemorySolver):

    @property
    def vulnerability_type(self) -> str:
        return "heap_overflow"

    def _setup_environment(self, project):
        project.hook_symbol("malloc", MyFakeMalloc())

    def _place_buffers_and_canaries(self, state, project, function_args):
        return [], []
