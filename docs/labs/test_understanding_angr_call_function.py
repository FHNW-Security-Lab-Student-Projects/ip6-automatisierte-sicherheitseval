import angr
import claripy


def test_call_state_approach():
    proj = angr.Project(
        "tests/fixtures/stack_overflow/gets_local/bin", auto_load_libs=False
    )

    if not proj.kb.functions:
        proj.analyses.CFGFast()

    vulnerable_func = proj.kb.functions[
        "vulnerable_function"
    ].addr  # Get the address of the vulnerable function from the CFG.

    sym_input = claripy.BVS("input", 256 * 8)

    state = proj.factory.call_state(vulnerable_func, stdin=sym_input)

    simgr = proj.factory.simulation_manager(state)
    simgr.run(n=50)

    assert len(simgr.active) == 0
    assert len(simgr.errored) == 0
    assert len(simgr.unconstrained) > 0


def test_entry_state_addr_approach():
    proj = angr.Project(
        "tests/fixtures/stack_overflow/gets_local/bin", auto_load_libs=False
    )

    if not proj.kb.functions:
        cfg = proj.analyses.CFGFast()

    vuln_func_addr = proj.kb.functions[
        "vulnerable_function"
    ].addr  # Get the address of the vulnerable function from the CFG.
    value_betreuer = cfg.kb.functions[
        proj.loader.main_object.get_symbol("vulnerable_function").rebased_addr
    ].addr  # Get the address of the vulnerable function from the symbol table.

    sym_input = claripy.BVS("input", 256 * 8)

    state = proj.factory.entry_state(addr=vuln_func_addr, stdin=sym_input)

    simgr = proj.factory.simulation_manager(state)
    simgr.run(n=50)

    assert value_betreuer == vuln_func_addr
    assert len(simgr.active) == 0
    assert len(simgr.errored) == 0
    assert len(simgr.unconstrained) > 0


def test_strcpy_with_valid_pointer():
    proj = angr.Project(
        "tests/fixtures/stack_overflow/strcpy_pointer/bin", auto_load_libs=False
    )
    if not proj.kb.functions:
        proj.analyses.CFGFast()

    vuln_addr = proj.kb.functions["copy_input"].addr

    sym_content = claripy.BVS("input_content", 64 * 8)

    state = proj.factory.call_state(vuln_addr)

    buffer_addr = state.solver.eval(state.regs.rsp) - 0x200

    state.memory.store(buffer_addr, sym_content)

    state.regs.rdi = buffer_addr

    simgr = proj.factory.simulation_manager(state)
    simgr.run(n=50)

    assert len(simgr.active) == 0
    assert len(simgr.errored) == 0
    assert len(simgr.unconstrained) > 0
