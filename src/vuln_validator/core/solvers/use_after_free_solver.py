from .base_memory_solver import BaseMemorySolver
from .hooks.heap_hooks import MyFakeMalloc, MyFakeCalloc, MyFakeAlignedAlloc, MyFakeFree
import logging

logger = logging.getLogger(__name__)


class UseAfterFreeSolver(BaseMemorySolver):

    @property
    def vulnerability_type(self) -> str:
        return "use_after_free"

    def _setup_environment(self, project):
        """
        Hooks memory allocation AND deallocation functions.
        Crucially adds the 'free' hook to poison memory upon deallocation.
        """
        # 1. Install Alloc Hooks (same as HeapOverflow)
        hooks_to_install = {
            "malloc": MyFakeMalloc,
            "calloc": MyFakeCalloc,
            "aligned_alloc": MyFakeAlignedAlloc,
            "_Znwm": MyFakeMalloc,  # operator new
            "_Znam": MyFakeMalloc,  # operator new[]
        }

        for func_name, hook_class in hooks_to_install.items():
            sym = project.loader.find_symbol(func_name)
            if sym is not None:
                project.hook_symbol(func_name, hook_class())
                logger.debug(f"Hooked {func_name} for UAF setup.")
            else:
                logger.debug(f"Could not find {func_name}. Hook skipped.")

        # 2. Install Free Hook (The UAF Specific Part)
        free_symbols = ["free", "_ZdlPv", "_ZdaPv"]  # C free, C++ delete, C++ delete[]
        for func_name in free_symbols:
            sym = project.loader.find_symbol(func_name)
            if sym is not None:
                project.hook_symbol(func_name, MyFakeFree())
                logger.debug(f"Hooked {func_name} for UAF poisoning.")
            else:
                logger.debug(f"Could not find {func_name}. Free hook skipped.")

    def _place_buffers_and_canaries(self, state, project, function_args):
        """
        Sets up symbolic arguments.
        For UAF, the critical 'symbolic' data is injected by the Free-Hook itself.
        However, we still need to set up the initial environment (stdin, args) correctly.
        """
        symbolic_args, _ = self._place_symbolic_args(state, project, function_args)
        return symbolic_args
