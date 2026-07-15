from .heap_solver import HeapOverflowSolver
from .hooks.heap_hooks import MyFakeFree
import logging

logger = logging.getLogger(__name__)


class UseAfterFreeSolver(HeapOverflowSolver):

    @property
    def vulnerability_type(self) -> str:
        return "use_after_free"

    def _setup_environment(self, project):
        """
        Sets up the environment for UAF detection:
        1. Installs standard allocation hooks (via parent class).
        2. Installs the specific 'free' hook to poison memory.
        """
        # 1. Reuse malloc/calloc hooks from parent
        super()._setup_environment(project)

        # 2. Install Free Hook (The UAF Specific Part)
        self._install_free_hook(project)

    def _install_free_hook(self, project):
        """
        Installs hooks for free/delete to enable memory poisoning.
        """
        free_symbols = ["free", "_ZdlPv", "_ZdaPv"]  # C free, C++ delete, C++ delete[]

        for func_name in free_symbols:
            sym = project.loader.find_symbol(func_name)
            if sym is not None:
                project.hook_symbol(func_name, MyFakeFree())
                logger.debug(f"Hooked {func_name} for UAF poisoning.")
            else:
                logger.debug(f"Could not find {func_name}. Free hook skipped.")
