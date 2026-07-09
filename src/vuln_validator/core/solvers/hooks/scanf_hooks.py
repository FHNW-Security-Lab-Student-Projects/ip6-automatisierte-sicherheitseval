import angr
import claripy
import logging

logger = logging.getLogger(__name__)


class ScanfHook(angr.SimProcedure):
    """
    Hook for scanf. Parses format string to determine input size (%d=4, %s=256, etc.)
    and writes a new symbolic variable to the destination pointer.
    """

    def run(self, fmt_ptr):
        # 1. Resolve Format String Address (rdi)
        if self.state.solver.symbolic(fmt_ptr):
            logger.warning(
                "scanf called with symbolic format string. Cannot determine type. Skipping."
            )
            return 0

        fmt_addr = self.state.solver.eval(fmt_ptr)

        # 2. Resolve Destination Address (rsi)
        dest_addr = self.state.regs.rsi
        if self.state.solver.symbolic(dest_addr):
            logger.warning("scanf called with symbolic destination address. Skipping.")
            return 0

        concrete_dest = self.state.solver.eval(dest_addr)

        # 3. Parse Format String to find specifier
        fmt_bytes = self.state.memory.load(fmt_addr, 10)
        fmt_str = self.state.solver.eval(fmt_bytes, cast_to=bytes)

        input_size = 8

        if b"%" in fmt_str:
            idx = fmt_str.find(b"%")
            # Check next 3 chars for specifier
            snippet = fmt_str[idx : idx + 3]

            if (
                b"d" in snippet
                or b"i" in snippet
                or b"u" in snippet
                or b"x" in snippet
                or b"p" in snippet
                or b"n" in snippet
            ):
                input_size = 4
            elif b"l" in snippet:
                input_size = 8
            elif b"s" in snippet:
                input_size = 512
            elif (
                b"f" in snippet or b"F" in snippet or b"e" in snippet or b"g" in snippet
            ):
                input_size = 8
            elif b"c" in snippet:
                input_size = 1
            else:
                logger.warning(
                    "Unknown format specifier in scanf: %s. Defaulting to 8 bytes.",
                    snippet,
                )

        # 4. Create and Store Symbolic Variable
        var_name = f"scanf_{input_size}B_{self.state.history.depth}"
        symbolic_data = claripy.BVS(var_name, input_size * 8)

        self.state.memory.store(concrete_dest, symbolic_data)

        if "scanf_inputs" not in self.state.globals:
            self.state.globals["scanf_inputs"] = []
        self.state.globals["scanf_inputs"].append(
            {
                "var_name": var_name,
                "addr": concrete_dest,
                "size": input_size,
                "symbol": symbolic_data,
            }
        )

        return 1
