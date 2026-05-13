from .base_memory_solver import BaseMemorySolver
from .hooks.heap_hooks import MyFakeMalloc
from .hooks.heap_hooks import MyFakeCalloc
import logging

logger = logging.getLogger(__name__)


class HeapOverflowSolver(BaseMemorySolver):

    @property
    def vulnerability_type(self) -> str:
        return "heap_overflow"

    def _setup_environment(self, project):
        """
        Hooks memory allocation functions (malloc, calloc, etc.).
        Tries symbol table first, then falls back to PLT.
        """
        # Mapping of function names to their corresponding hook classes
        hooks_to_install = {
            "malloc": MyFakeMalloc,
            "calloc": MyFakeCalloc,
        }

        for func_name, hook_class in hooks_to_install.items():
            installed = False

            # Try 1: Hook via symbol table
            sym = project.loader.find_symbol(func_name)
            if sym is not None:
                project.hook_symbol(func_name, hook_class())
                installed = True
                logger.debug(f"Hooked {func_name} via symbol table.")

            # Try 2: Hook via PLT
            if not installed:
                plt_addr = project.loader.main_object.plt.get(func_name)
                if plt_addr is not None:
                    project.hook(plt_addr, hook_class())
                    installed = True
                    logger.debug(f"Hooked {func_name} via PLT at 0x{plt_addr:x}.")

            if not installed:
                logger.debug(
                    f"Could not find {func_name} (symbol or PLT). Hook skipped."
                )

    def _place_buffers_and_canaries(self, state, project, function_args):
        symbolic_args, _ = self._place_symbolic_args(state, project, function_args)
        return symbolic_args
