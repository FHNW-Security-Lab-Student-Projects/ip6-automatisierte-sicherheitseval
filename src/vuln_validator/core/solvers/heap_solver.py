from .base_memory_solver import BaseMemorySolver
from .hooks.heap_hooks import MyFakeMalloc
import logging

logger = logging.getLogger(__name__)


class HeapOverflowSolver(BaseMemorySolver):

    @property
    def vulnerability_type(self) -> str:
        return "heap_overflow"

    def _setup_environment(self, project):
        project.hook_symbol("malloc", MyFakeMalloc())

    def _place_buffers_and_canaries(self, state, project, function_args):
        return []
