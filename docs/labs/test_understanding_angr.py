import angr
import claripy


def test_einfache_loesung():

    proj = angr.Project(
        "tests/fixtures/legacy_scripts/2_buffer_overflow", auto_load_libs=False
    )

    assert proj is not None
    assert proj.arch.name == "AMD64"


def test_initial_state_rip():
    proj = angr.Project(
        "tests/fixtures/legacy_scripts/2_buffer_overflow", auto_load_libs=False
    )

    state = proj.factory.entry_state()

    assert state is not None
    assert state.regs.rip is not None
    assert state.solver.eval(state.regs.rip) == proj.entry


def test_symbolic_register():
    proj = angr.Project(
        "tests/fixtures/legacy_scripts/2_buffer_overflow", auto_load_libs=False
    )

    sym_input = claripy.BVS("my_var", 64)
    state = proj.factory.entry_state()

    state.regs.rax = sym_input

    assert state.solver.symbolic(state.regs.rax) is True
    assert state.solver.eval(state.regs.rax) == 0


def test_constraint_logic():
    proj = angr.Project(
        "tests/fixtures/legacy_scripts/2_buffer_overflow", auto_load_libs=False
    )

    sym_input = claripy.BVS("my_var", 64)
    state = proj.factory.entry_state()

    state.regs.rax = sym_input

    state.solver.add(state.regs.rax > 100)

    assert state.solver.symbolic(state.regs.rax) is True
    assert state.solver.eval(state.regs.rax) > 100

    state.solver.add(state.regs.rax == 200)

    assert state.solver.eval(state.regs.rax) == 200


def test_symbolic_memory_operation():
    proj = angr.Project(
        "tests/fixtures/legacy_scripts/2_buffer_overflow", auto_load_libs=False
    )

    state = proj.factory.entry_state()

    sym_val = claripy.BVS("my_var", 64)
    state.memory.store(0x700000, sym_val)

    read_val = state.memory.load(0x700000, 8)

    assert state.solver.symbolic(read_val) is True

    result = read_val + 10
    state.memory.store(0x700008, result)

    result_val = state.memory.load(0x700008, 8)

    s = claripy.Solver()
    s.add(result_val == 110)

    assert s.satisfiable() is True
    assert s.eval(sym_val, 1)[0] == 100


def test_single_step_execution():
    proj = angr.Project(
        "tests/fixtures/legacy_scripts/2_buffer_overflow", auto_load_libs=False
    )
    state = proj.factory.entry_state()

    sym_val = claripy.BVS("my_var", 64)
    state.regs.rax = sym_val  # Setze RAX auf einen symbolischen Wert

    start_addr = state.addr
    successor_state = state.step()[0]

    # print(proj.factory.block(start_addr).disassembly) # Optional: Zeige die erste Instruktion an

    assert successor_state is not None
    assert successor_state.addr != start_addr
    assert successor_state.addr > start_addr
    assert successor_state.solver.symbolic(successor_state.regs.rax) is True


def test_simulation_manager_run():
    proj = angr.Project(
        "tests/fixtures/legacy_scripts/2_buffer_overflow", auto_load_libs=False
    )
    state = proj.factory.entry_state()

    simgr = proj.factory.simulation_manager(state)

    start_addr = state.addr

    simgr.run(n=5)  # Führe einen Schritt aus

    assert len(simgr.active) > 0
    assert simgr.active[0].addr != start_addr
    assert simgr.active[0].addr > start_addr
    assert len(simgr.deadended) == 0  # noch keine Pfade terminiert
    assert len(simgr.errored) == 0  # noch keine Fehler aufgetreten
    # Anstatt selber while-Schleifen zu schreiben, können wir simgr.run() oder simgr.step() nutzen


def test_crash_detection():
    proj = angr.Project(
        "tests/fixtures/legacy_scripts/2_buffer_overflow", auto_load_libs=False
    )
    state = proj.factory.entry_state()

    simgr = proj.factory.simulation_manager(state)

    state.regs.rip = (
        0xDEADBEEF  # Setze die Instruction Pointer auf eine ungültige Adresse
    )
    simgr.step()

    assert len(simgr.active) == 0
    assert len(simgr.errored) == 1
    assert state.solver.eval(state.regs.rip) == 0xDEADBEEF


def test_symbolic_rip_detection():
    proj = angr.Project(
        "tests/fixtures/legacy_scripts/2_buffer_overflow", auto_load_libs=False
    )
    state = proj.factory.entry_state()

    simgr = proj.factory.simulation_manager(state)

    sym_rip = claripy.BVS("sym_rip", 64)
    state.regs.rip = sym_rip
    simgr.step()

    assert len(simgr.active) == 0
    assert len(simgr.errored) == 1
    assert state.solver.symbolic(state.regs.rip) is True


def test_stdin_injection():
    proj = angr.Project(
        "tests/fixtures/legacy_scripts/2_buffer_overflow", auto_load_libs=False
    )

    symbolic_input = claripy.BVS("symbolic_input", 64 * 8)

    state = proj.factory.entry_state(stdin=symbolic_input)

    simgr = proj.factory.simulation_manager(state)

    simgr.run(n=1)

    assert len(simgr.active) > 0
    assert (
        simgr.active[0].solver.eval(symbolic_input) >= 0
    )  # Überprüfen, dass der symbolische Input einen gültigen Wert hat (z.B. nicht negativ)


def test_limited_run():
    proj = angr.Project(
        "tests/fixtures/legacy_scripts/2_buffer_overflow", auto_load_libs=False
    )
    state = proj.factory.entry_state()

    simgr = proj.factory.simulation_manager(state)

    simgr.run(n=10)

    assert len(simgr.active) > 0
    assert len(simgr.errored) == 0
