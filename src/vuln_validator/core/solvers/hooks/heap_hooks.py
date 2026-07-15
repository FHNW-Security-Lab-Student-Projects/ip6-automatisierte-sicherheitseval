import angr
import claripy
import logging
from ....utils.config_loader import get_config

logger = logging.getLogger(__name__)

_HEAP_CFG = get_config()["solver"]["memory_layout"]
_HEAP_START_VALUE = _HEAP_CFG["heap_start"]
FALLBACK_SIZE = 256
FALLBACK_ALIGNMENT = 16


class BaseFakeHeapAlloc(angr.SimProcedure):
    """
    Base class for heap allocation hooks (malloc, calloc, aligned_alloc).
    Handles: Size calculation, Optional Alignment, Canary placement,
    Memory initialization, and Heap pointer management.
    """

    HEAP_START = claripy.BVV(_HEAP_START_VALUE, 64)
    CANARY_VALUE = 0xDEADBEEF
    CANARY_SIZE = 0x4

    def _get_allocation_size(self, *args):
        """Calculate total allocation size based on arguments."""
        raise NotImplementedError("Child classes must implement _get_allocation_size")

    def _initialize_memory(self, addr, size):
        """Child classes can override to initialize allocated memory (e.g., zero for calloc)."""
        pass

    def _get_alignment(self, *args):
        """
        Override this method to return a specific alignment value.
        Default is 1 (no special alignment).
        For aligned_alloc, child class returns args[0].
        """
        return 1

    def run(self, *args):
        """
        Handles the allocation logic
        """
        logger.debug(f"{self.__class__.__name__} called with args: {args}")
        # 1. Calculate size
        total_size = self._get_allocation_size(*args)
        # Fallback for symbolic sizes to ensure concrete address calculation
        if self.state.solver.symbolic(total_size):
            logger.warning(
                f"{self.__class__.__name__} called with symbolic size. Using fallback {FALLBACK_SIZE}."
            )
            concrete_size = FALLBACK_SIZE
        else:
            concrete_size = self.state.solver.eval(total_size)

        # 2. Calculate alignment
        raw_alignment = self._get_alignment(*args)
        # Fallback for symbolic alignment to ensure concrete address calculation
        if self.state.solver.symbolic(raw_alignment):
            logger.warning(
                f"{self.__class__.__name__} called with symbolic alignment. Using fallback {FALLBACK_ALIGNMENT}."
            )
            alignment = FALLBACK_ALIGNMENT
        else:
            alignment = self.state.solver.eval(raw_alignment)

        # 3. Initialize Globals if needed
        if "heap_ptr" not in self.state.globals:
            self.state.globals["heap_ptr"] = self.HEAP_START
            self.state.globals["canary_list"] = []
            self.state.globals["allocations"] = []

        # 4. Calculate Addresses with Optional Alignment
        # Start after underflow canary
        raw_addr = self.state.globals["heap_ptr"] + self.CANARY_SIZE
        concrete_raw = self.state.solver.eval(raw_addr)

        if alignment > 1:
            if concrete_raw % alignment == 0:
                concrete_ret_addr = concrete_raw
            else:
                concrete_ret_addr = ((concrete_raw // alignment) + 1) * alignment
            # Gap is implicitly handled by jumping to concrete_ret_addr
        else:
            concrete_ret_addr = concrete_raw

        ret_addr = claripy.BVV(concrete_ret_addr, 64)

        # Store allocated memory as BVV to ensure it's concrete and not symbolic
        var = claripy.BVV(0, concrete_size * 8)
        self.state.memory.store(ret_addr, var, endness=self.state.arch.memory_endness)

        # 5. Place Canaries
        # Layout: [Underflow Canary] [User Data] [Overflow Canary]
        canary_addr_underflow = ret_addr - self.CANARY_SIZE
        canary_addr_overflow = ret_addr + concrete_size

        for addr, kind in (
            (canary_addr_overflow, "overflow"),
            (canary_addr_underflow, "underflow"),
        ):
            self.state.memory.store(
                addr,
                claripy.BVV(self.CANARY_VALUE, self.CANARY_SIZE * 8),
                endness=self.state.arch.memory_endness,
            )

            concrete_addr = self.state.solver.eval(addr)
            self.state.globals["canary_list"].append(
                {
                    "addr": concrete_addr,
                    "expected": self.CANARY_VALUE,
                    "padding_size": self.CANARY_SIZE,
                    "source": f"{self.__class__.__name__}_hook",
                    "kind": kind,
                }
            )

            logger.debug(
                "%s: Placed %s canary at 0x%x",
                self.__class__.__name__,
                kind,
                concrete_addr,
            )

        self.state.globals["allocations"].append(
            {
                "addr": concrete_ret_addr,
                "size": concrete_size,
                "source": f"{self.__class__.__name__}_hook",
            }
        )

        # 6. Initialize Memory
        self._initialize_memory(ret_addr, concrete_size)

        # 7. Advance Heap Pointer
        self.state.globals["heap_ptr"] = canary_addr_overflow + self.CANARY_SIZE

        return ret_addr


class MyFakeMalloc(BaseFakeHeapAlloc):
    """Hook for malloc(size)."""

    def _get_allocation_size(self, *args):
        return args[0] if args else 0

    def run(self, size):
        return super().run(size)


class MyFakeCalloc(BaseFakeHeapAlloc):
    """Hook for calloc(nmemb, size). Zero-initializes memory."""

    def _get_allocation_size(self, *args):
        if len(args) < 2:
            return 0
        nmemb, size = args[0], args[1]
        return nmemb * size

    def _initialize_memory(self, addr, size):
        self.state.memory.store(
            addr, claripy.BVV(0, size * 8), endness=self.state.arch.memory_endness
        )

    def run(self, nmemb, size):
        return super().run(nmemb, size)


class MyFakeAlignedAlloc(BaseFakeHeapAlloc):
    """Hook for aligned_alloc(alignment, size). Enforces alignment."""

    def _get_allocation_size(self, *args):
        return args[1] if len(args) >= 2 else 0

    def _get_alignment(self, *args):
        return args[0] if len(args) >= 2 else 1

    def run(self, alignment, size):
        return super().run(alignment, size)


class MyFakeFree(angr.SimProcedure):
    """
    Hook for free(ptr).
    Strategy:
    1. Identify the chunk in our tracked allocations.
    2. Overwrite the user-data region with symbolic variables ("poisoning").
       This ensures that any subsequent read (Use-After-Free) loads symbolic data,
       which will taint registers/memory and potentially lead to an unconstrained RIP.
    3. Remove from active allocations and add to freed list.
    """

    def run(self, ptr):
        # Handle NULL free (safe no-op)
        if self.state.solver.eval(ptr) == 0:
            logger.debug("free(0) called, ignoring.")
            return

        # Resolve concrete address for lookup.
        if self.state.solver.symbolic(ptr):
            logger.warning(
                "free() called with symbolic pointer. UAF tracking may be inaccurate for this call."
            )
            try:
                concrete_ptr = self.state.solver.eval(ptr)
            except Exception:
                return  # Cannot track symbolic free
        else:
            concrete_ptr = self.state.solver.eval(ptr)

        logger.debug(f"MyFakeFree: Attempting to free address 0x{concrete_ptr:x}")

        # Initialize globals if missing (safety net)
        if "allocations" not in self.state.globals:
            self.state.globals["allocations"] = []
        if "freed_addresses" not in self.state.globals:
            self.state.globals["freed_addresses"] = []

        # Find the allocation record
        target_chunk = None
        chunk_index = -1

        for i, chunk in enumerate(self.state.globals["allocations"]):
            if chunk["addr"] == concrete_ptr:
                target_chunk = chunk
                chunk_index = i
                break

        if target_chunk is None:
            logger.warning(
                f"MyFakeFree: Address 0x{concrete_ptr:x} not found in active allocations. Double free or invalid free?"
            )
            return

        size = target_chunk["size"]
        logger.info(f"MyFakeFree: Freeing chunk at 0x{concrete_ptr:x} with size {size}")

        # Poison the memory region with symbolic variables to simulate UAF
        poison_var = claripy.BVS(f"uaf_poison_{concrete_ptr:x}", size * 8)

        # Store the symbolic poison into the memory region
        self.state.memory.store(
            concrete_ptr, poison_var, endness=self.state.arch.memory_endness
        )
        logger.debug(
            f"MyFakeFree: Poisoned memory at 0x{concrete_ptr:x} with symbolic data ({size} bytes)"
        )

        # Remove from active allocations
        del self.state.globals["allocations"][chunk_index]

        # Add to freed list (for evaluation/verification later)
        self.state.globals["freed_addresses"].append(
            {
                "addr": concrete_ptr,
                "size": size,
                "source": target_chunk.get("source", "unknown"),
                "poisoned": True,
            }
        )

        return
