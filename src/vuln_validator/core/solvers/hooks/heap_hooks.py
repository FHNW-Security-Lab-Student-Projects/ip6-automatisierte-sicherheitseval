import angr
import claripy
import logging

logger = logging.getLogger(__name__)


class MyFakeMalloc(angr.SimProcedure):
    HEAP_START = claripy.BVV(0x600000, 64)

    def run(self, size):
        if "heap_ptr" not in self.state.globals:
            self.state.globals["heap_ptr"] = self.HEAP_START
            self.state.globals["canary_list"] = []

        canary_addr_underflow = self.state.globals["heap_ptr"]
        ret_addr = canary_addr_underflow + 0x4  # space for canary
        canary_addr = ret_addr + size

        for addr, kind in (
            (canary_addr, "overflow"),
            (canary_addr_underflow, "underflow"),
        ):
            self.state.memory.store(
                addr,
                claripy.BVV(0xDEADBEEF, 32),
                endness=self.state.arch.memory_endness,
            )
            self.state.globals["canary_list"].append(
                {
                    "addr": self.state.solver.eval(addr),
                    "expected": 0xDEADBEEF,
                    "padding_size": 4,  # Default für Heap Canary
                    "source": "malloc_hook",
                }
            )
            logger.debug(
                "Placed %s canary at address: 0x%x with expected value: 0x%x",
                kind,
                addr,
                0xDEADBEEF,
            )

        self.state.globals["heap_ptr"] = canary_addr + 0x4

        return ret_addr
