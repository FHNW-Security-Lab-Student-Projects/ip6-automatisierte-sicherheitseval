import angr
import logging

logger = logging.getLogger(__name__)


class FormatStringHook(angr.SimProcedure):
    """
    SimProcedure Hook for (printf, fprintf, etc.).
    Detects if the format string is symbolic (user-controlled).
    """

    def __init__(self, fmt_arg_index=0):
        """
        Args: Index of the format string argument.
        """
        super().__init__()
        self.fmt_arg_index = fmt_arg_index

    def run(self):
        regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

        fmt_reg_name = regs[self.fmt_arg_index]
        fmt_addr = getattr(self.state.regs, fmt_reg_name)

        if self.state.solver.symbolic(fmt_addr):
            # Do nothing, because Overflow-Solvers will handle this case.
            return 0

        # Check 2 if the format string content is symbolic
        # This is the normal case for printf(user_input).
        try:
            fmt_data = self.state.memory.load(fmt_addr, 64)
        except Exception as e:
            logger.warning(
                f"Failed to load format string from address 0x{fmt_addr:x}: {e}"
            )
            return 0

        # Check if the format string content is symbolic
        if self.state.solver.symbolic(fmt_data):
            self._mark_vulnerable(
                "format_string_content_symbolic",
                "Content of format string is symbolic (user-controlled). This allows reading (leak) and writing (%n).",
            )

        return 0

    def _mark_vulnerable(self, vuln_type: str, desc: str):
        """
        Marks the current state as vulnerable via globals.
        These will be read later in _evaluation.py.
        """
        self.state.globals["fmt_vulnerable"] = True
        self.state.globals["fmt_vuln_type"] = vuln_type
        self.state.globals["fmt_vuln_desc"] = desc
        logger.warning(f"FORMAT STRING VULNERABILITY DETECTED: {desc}")
