from .base_memory_solver import BaseMemorySolver
from .hooks.format_string_hooks import FormatStringPrintfHook
import logging

logger = logging.getLogger(__name__)


class FormatStringSolver(BaseMemorySolver):

    @property
    def vulnerability_type(self) -> str:
        return "format_string"

    def _setup_environment(self, project):
        """
        Hooks printf and similar functions to detect format string attacks.
        """
        hooks_to_install = {
            "printf": FormatStringPrintfHook,
            "fprintf": FormatStringPrintfHook,
            "sprintf": FormatStringPrintfHook,
            "syslog": FormatStringPrintfHook,
            "snprintf": FormatStringPrintfHook,
        }

        for func_name, hook_class in hooks_to_install.items():
            # Try to hook via PLT first
            sym = project.loader.find_symbol(func_name)
            if sym is not None:
                project.hook_symbol(func_name, hook_class())
                logger.debug(f"Hooked {func_name} for Format-String analysis.")
            else:
                logger.debug(
                    f"Could not find {func_name} (symbol or PLT). Hook skipped."
                )

    def _place_buffers_and_canaries(self, state, project, function_args):
        """
        Placement of symbolic arguments.
        """
        symbolic_args, _ = self._place_symbolic_args(state, project, function_args)
        return symbolic_args
