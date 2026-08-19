from .base_memory_solver import BaseMemorySolver
from .hooks.format_string_hooks import FormatStringHook
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
            "printf": FormatStringHook,
            "fprintf": FormatStringHook,
            "sprintf": FormatStringHook,
            "syslog": FormatStringHook,
            "snprintf": FormatStringHook,
        }
        hooks_to_install = {
            "printf": (0),  # 1. Arg (rdi)
            "fprintf": (1),  # 2. Arg (rsi)
            "sprintf": (1),  # 2. Arg (rsi)
            "snprintf": (2),  # 3. Arg (rdx)
            "syslog": (1),  # 2. Arg (rsi)
        }

        for func_name, arg_index in hooks_to_install.items():
            # Try to hook via PLT first
            sym = project.loader.find_symbol(func_name)
            if sym is not None:
                project.hook_symbol(
                    func_name, FormatStringHook(fmt_arg_index=arg_index)
                )
                logger.debug(f"Hooked {func_name} for Format-String analysis.")
            else:
                logger.debug(
                    f"Could not find {func_name} (symbol or PLT). Hook skipped."
                )

    def _place_buffers_and_canaries(self, state, project, function_args):
        """
        Placement of symbolic arguments.
        """
        bv_args, _ = self._place_args(state, project, function_args)
        return bv_args
