from .base_memory_solver import BaseMemorySolver
from .hooks.heap_hooks import MyFakeMalloc, MyFakeCalloc, MyFakeAlignedAlloc
import logging

logger = logging.getLogger(__name__)


class HeapOverflowSolver(BaseMemorySolver):

    @property
    def vulnerability_type(self) -> str:
        return "heap_overflow"

    def _setup_environment(self, project):
        """
        Hooks memory allocation functions (malloc, calloc, etc.).
        Tries to hook via symbol table.
        """
        self._install_alloc_hooks(project)

    def _install_alloc_hooks(self, project):
        """
        Helper method to install standard allocation hooks.
        """
        # Mapping of function names to their corresponding hook classes
        hooks_to_install = {
            "malloc": MyFakeMalloc,
            "calloc": MyFakeCalloc,
            "aligned_alloc": MyFakeAlignedAlloc,
            "_Znwm": MyFakeMalloc,  # operator new
            "_Znam": MyFakeMalloc,  # operator new[]
        }

        for func_name, hook_class in hooks_to_install.items():

            # Try to hook via symbol table
            sym = project.loader.find_symbol(func_name)
            if sym is not None:
                project.hook_symbol(func_name, hook_class())
                logger.debug(f"Hooked {func_name} via symbol table.")
            else:
                logger.debug(
                    f"Could not find {func_name} (symbol or PLT). Hook skipped."
                )

    def _place_buffers_and_canaries(self, state, project, function_args):
        symbolic_args, _ = self._place_symbolic_args(state, project, function_args)
        return symbolic_args
