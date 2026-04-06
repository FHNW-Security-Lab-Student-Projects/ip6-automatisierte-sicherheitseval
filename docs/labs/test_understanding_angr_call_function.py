import angr
import claripy


def test_call_state_approach():
    proj = angr.Project("tests/fixtures/5_my_vuln", auto_load_libs=False)

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
    proj = angr.Project("tests/fixtures/5_my_vuln", auto_load_libs=False)

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
