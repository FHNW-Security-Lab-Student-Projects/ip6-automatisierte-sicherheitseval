import angr
import logging

logger = logging.getLogger(__name__)


class FormatStringPrintfHook(angr.SimProcedure):
    """
    SimProcedure Hook for (printf, fprintf, etc.).
    Detects if the format string is symbolic (user-controlled).
    """

    def run(self):
        # x86_64 Calling Convention:
        # 1. Arg (Format-String) is in RDI
        fmt_addr = self.state.regs.rdi

        # Check 1 if the format string address is symbolic
        if self.state.solver.symbolic(fmt_addr):
            self._mark_vulnerable(
                "format_string_pointer_symbolic",
                "Adress of format string is symbolic (user-controlled).",
            )
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
