import angr
import claripy
import logging

logger = logging.getLogger(__name__)


class BaseFakeHeapAlloc(angr.SimProcedure):
    """
    Base class for heap allocation hooks (malloc, calloc, etc.).
    Handles common logic: Canary placement (underflow/overflow),
    heap pointer management, and global state initialization.
    """

    HEAP_START = claripy.BVV(0x600000, 64)
    CANARY_VALUE = 0xDEADBEEF
    CANARY_SIZE = 0x4

    # Must be overridden by child classes:
    # Should return the concrete total size of the allocation
    def _get_allocation_size(self, *args):
        raise NotImplementedError("Child classes must implement _get_allocation_size")

    # Override to initialize memory (e.g., calloc sets to 0)
    def _initialize_memory(self, addr, size):
        pass

    def run(self, *args):
        # 1. Calculate size
        total_size = self._get_allocation_size(*args)

        # Fallback for symbolic sizes to ensure concrete address calculation
        if self.state.solver.symbolic(total_size):
            logger.warning(
                f"{self.__class__.__name__} called with symbolic size. Using fallback 256."
            )
            concrete_size = 256
        else:
            concrete_size = self.state.solver.eval(total_size)

        # 2. Initialize Globals if needed
        if "heap_ptr" not in self.state.globals:
            self.state.globals["heap_ptr"] = self.HEAP_START
            self.state.globals["canary_list"] = []

        # 3. Calculate Addresses
        # Layout: [Underflow Canary] [User Data] [Overflow Canary]
        canary_addr_underflow = self.state.globals["heap_ptr"]
        ret_addr = canary_addr_underflow + self.CANARY_SIZE
        canary_addr_overflow = ret_addr + concrete_size

        # 4. Place Canaries (Underflow and Overflow)
        for addr, kind in (
            (canary_addr_overflow, "overflow"),
            (canary_addr_underflow, "underflow"),
        ):
            self.state.memory.store(
                addr,
                claripy.BVV(self.CANARY_VALUE, self.CANARY_SIZE * 8),
                endness=self.state.arch.memory_endness,
            )

            # Store concrete address in tracking list
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

        # 5. Initialize Memory (Specific to allocator type, e.g., calloc)
        self._initialize_memory(ret_addr, concrete_size)

        # 6. Advance Heap Pointer
        self.state.globals["heap_ptr"] = canary_addr_overflow + self.CANARY_SIZE

        return ret_addr


class MyFakeMalloc(BaseFakeHeapAlloc):
    """
    Hook for malloc(size).
    """

    def _get_allocation_size(self, *args):
        # malloc takes one argument: size
        if not args:
            return 0
        return args[0]

    def _initialize_memory(self, addr, size):
        # malloc does not zero-initialize
        pass

    def run(self, size):
        return super().run(size)


class MyFakeAlignedAlloc(BaseFakeHeapAlloc):
    """
    Hook for aligned_alloc(alignment, size).
    Ensures the returned address is aligned to the specified boundary.
    """

    def _get_allocation_size(self, *args):
        # aligned_alloc takes two arguments: alignment, size
        if len(args) < 2:
            return 0

        # alignment = args[0], size = args[1]
        return args[1]

    def run(self, alignment, size):
        # 1. Handle symbolic arguments (similar to calloc)
        if self.state.solver.symbolic(alignment) or self.state.solver.symbolic(size):
            logger.warning("aligned_alloc called with symbolic args. Using fallbacks.")
            concrete_alignment = 16
            concrete_size = 256
        else:
            concrete_alignment = self.state.solver.eval(alignment)
            concrete_size = self.state.solver.eval(size)

        # 2. Initialize Globals
        if "heap_ptr" not in self.state.globals:
            self.state.globals["heap_ptr"] = self.HEAP_START
            self.state.globals["canary_list"] = []

        # 3. Calculate Raw Address
        raw_addr = (
            self.state.globals["heap_ptr"] + self.CANARY_SIZE
        )  # Start after underflow canary

        # 4. ALIGNMENT LOGIC: Round up raw_addr to the next multiple of alignment
        concrete_raw = self.state.solver.eval(raw_addr)

        if concrete_raw % concrete_alignment == 0:
            concrete_ret_addr = concrete_raw
        else:
            concrete_ret_addr = (
                (concrete_raw // concrete_alignment) + 1
            ) * concrete_alignment

        ret_addr = claripy.BVV(concrete_ret_addr, 64)

        # 5. Calculate Canary Addresses based on the ALIGNED address
        # Layout: [Gap/Unused] [Underflow Canary] [User Data] [Overflow Canary]
        canary_addr_underflow = ret_addr - self.CANARY_SIZE  # Directly before user data
        canary_addr_overflow = ret_addr + concrete_size

        # 6. Place Canaries (Manual implementation to handle the specific layout)
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
                    "source": "aligned_alloc_hook",
                    "kind": kind,
                }
            )
            logger.debug("aligned_alloc: Placed %s canary at 0x%x", kind, concrete_addr)

        # 7. Advance Heap Pointer
        next_ptr = canary_addr_overflow + self.CANARY_SIZE
        self.state.globals["heap_ptr"] = next_ptr

        return ret_addr


class MyFakeCalloc(BaseFakeHeapAlloc):
    """
    Hook for calloc(nmemb, size).
    Initializes memory to zero.
    """

    def _get_allocation_size(self, *args):
        # calloc takes two arguments: nmemb, size
        if len(args) < 2:
            return 0

        nmemb = args[0]  # Number of elements
        size = args[1]

        # Handle symbolic arguments gracefully
        if self.state.solver.symbolic(nmemb) or self.state.solver.symbolic(size):
            logger.warning(
                "calloc called with symbolic arguments. Using fallback total size 256."
            )
            return 256

        return nmemb * size

    def _initialize_memory(self, addr, size):
        # calloc zero-initializes the allocated block
        self.state.memory.store(
            addr, claripy.BVV(0, size * 8), endness=self.state.arch.memory_endness
        )

    def run(self, nmemb, size):
        return super().run(nmemb, size)
