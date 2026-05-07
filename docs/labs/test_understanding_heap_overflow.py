import angr
import claripy


def test_heap_layout_basic():
    proj = angr.Project(
        "tests/fixtures/heap_overflow/first_heap_overflow", auto_load_libs=False
    )

    if not proj.kb.functions:
        proj.analyses.CFGFast()

    vuln_func_addr = proj.kb.functions["main"].addr
    addr_of_gets = proj.kb.functions["gets"].addr

    sym_input = claripy.BVS("input", 64 * 8)
    overflow_input = claripy.BVV(
        b"A" * 50
    )  # 40 bytes to overflow the 32-byte buffer and overwrite access_level

    state = proj.factory.entry_state(addr=vuln_func_addr, stdin=sym_input)

    simgr = proj.factory.simulation_manager(state)

    simgr.explore(find=addr_of_gets)
    assert simgr.found, "Failed to find the gets function in the execution paths."

    found_state = simgr.found[0]
    addr_data1 = found_state.solver.eval(found_state.regs.rdi)
    assert (
        addr_data1 is not None
    ), "Failed to determine the address of data1 on the heap."

    found_state.memory.store(addr_data1, overflow_input)

    val = found_state.memory.load(
        addr_data1 + 36, 4
    )  # 32 bytes for buffer + 4 bytes to reach access_level
    assert (
        found_state.solver.eval(val) == 0x41414141
    ), "Heap overflow did not overwrite access_level as expected."

    assert len(simgr.active) == 0
    assert len(simgr.errored) == 0
    assert len(simgr.unconstrained) == 0


def test_heap_overflow_with_hooks_and_canaries():
    class MyFakeMalloc(angr.SimProcedure):
        current_addr = 0x600000

        def run(self, size):
            ret_addr = self.current_addr
            self.current_addr += 0x100

            return ret_addr

    proj = angr.Project(
        "tests/fixtures/heap_overflow/first_heap_overflow", auto_load_libs=False
    )

    if not proj.kb.functions:
        proj.analyses.CFGFast()

    vuln_func_addr = proj.kb.functions["main"].addr
    addr_of_gets = proj.kb.functions["gets"].addr

    proj.hook_symbol("malloc", MyFakeMalloc())

    sym_input = claripy.BVS("input", 64 * 8)
    overflow_input = claripy.BVV(
        b"A" * 50
    )  # 40 bytes to overflow the 32-byte buffer and overwrite access_level

    state = proj.factory.entry_state(addr=vuln_func_addr, stdin=sym_input)

    simgr = proj.factory.simulation_manager(state)

    simgr.explore(find=addr_of_gets)
    assert simgr.found, "Failed to find the gets function in the execution paths."

    found_state = simgr.found[0]
    addr_data1 = found_state.solver.eval(found_state.regs.rdi)
    assert (
        addr_data1 is not None
    ), "Failed to determine the address of data1 on the heap."

    found_state.memory.store(addr_data1, overflow_input)

    val = found_state.memory.load(
        addr_data1 + 36, 4
    )  # 32 bytes for buffer + 4 bytes to reach access_level
    assert (
        found_state.solver.eval(val) == 0x41414141
    ), "Heap overflow did not overwrite access_level as expected."


def test_heap_overflow_safe_canaries():
    class MyFakeMalloc(angr.SimProcedure):
        HEAP_START = claripy.BVV(0x600000, 64)

        def run(self, size):
            print(f"malloc called with size: {size}")
            if "heap_ptr" not in self.state.globals:
                self.state.globals["heap_ptr"] = self.HEAP_START
                self.state.globals["canary_list"] = []

            ret_addr = self.state.globals["heap_ptr"]

            canary_addr = ret_addr + size
            print(f"Placing canary at: {canary_addr}")
            self.state.memory.store(canary_addr, claripy.BVV(0xDEADBEEF, 32))
            self.state.globals["canary_list"].append(canary_addr)
            print(self.state.memory.load(0x600000, 256))

            self.state.globals["heap_ptr"] = canary_addr + 0x4

            return ret_addr

    proj = angr.Project(
        "tests/fixtures/heap_overflow/first_heap_overflow", auto_load_libs=False
    )

    if not proj.kb.functions:
        proj.analyses.CFGFast()

    vuln_func_addr = proj.kb.functions["main"].addr

    proj.hook_symbol("malloc", MyFakeMalloc())

    # sym_input = claripy.BVS("input", 64 * 8)
    overflow_input = claripy.BVV(b"B" * 40 + b"\n")

    state = proj.factory.call_state(addr=vuln_func_addr, stdin=overflow_input)

    simgr = proj.factory.simulation_manager(state)

    simgr.run()

    assert (
        len(simgr.active) == 0
    ), "There should be no active states left after exploration."
    assert len(simgr.errored) == 0
    assert (
        len(simgr.deadended) > 0
    ), "Expected to find deadended states due to normal execution paths."

    canary = simgr.deadended[0].memory.load(0x600024, 4)
    canary2 = simgr.deadended[0].memory.load(0x60004C, 4)

    canary_val = simgr.deadended[0].solver.eval(canary)
    canary2_val = simgr.deadended[0].solver.eval(canary2)

    assert canary_val != 0xDEADBEEF
    assert canary2_val == 0xDEADBEEF
