from .base_memory_solver import BaseMemorySolver
from .hooks.heap_hooks import MyFakeMalloc
import logging

logger = logging.getLogger(__name__)


class HeapOverflowSolver(BaseMemorySolver):

    @property
    def vulnerability_type(self) -> str:
        return "heap_overflow"

    def _setup_environment(self, project):
        sym = project.loader.find_symbol("malloc")
        if sym is not None:
            project.hook_symbol("malloc", MyFakeMalloc())
            return

        plt_addr = project.loader.main_object.plt.get("malloc")
        if plt_addr is not None:
            project.hook(plt_addr, MyFakeMalloc())
            return

        logger.debug("No malloc symbol/PLT found. Skipping malloc hook.")

    def _place_buffers_and_canaries(self, state, project, function_args):
        return []
