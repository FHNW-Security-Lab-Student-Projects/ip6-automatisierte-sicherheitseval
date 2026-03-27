import angr
import claripy


def test_einfache_loesung():

    proj = angr.Project("tests/fixtures/2_buffer_overflow", auto_load_libs=False)

    assert proj is not None
    assert proj.arch.name == "AMD64"


def test_initial_state_rip():
    proj = angr.Project("tests/fixtures/2_buffer_overflow", auto_load_libs=False)

    state = proj.factory.entry_state()

    assert state is not None
    assert state.regs.rip is not None
    assert state.solver.eval(state.regs.rip) == proj.entry


def test_symbolic_register():
    proj = angr.Project("tests/fixtures/2_buffer_overflow", auto_load_libs=False)

    sym_input = claripy.BVS("my_var", 64)
    state = proj.factory.entry_state()

    state.regs.rax = sym_input

    assert state.solver.symbolic(state.regs.rax) is True
    assert state.solver.eval(state.regs.rax) == 0


def test_constraint_logic():
    proj = angr.Project("tests/fixtures/2_buffer_overflow", auto_load_libs=False)

    sym_input = claripy.BVS("my_var", 64)
    state = proj.factory.entry_state()

    state.regs.rax = sym_input

    state.solver.add(state.regs.rax > 100)

    assert state.solver.symbolic(state.regs.rax) is True
    assert state.solver.eval(state.regs.rax) > 100
    assert (
        state.solver.eval(state.regs.rax) == 101
    )  # könnte auch 102, 103, ... sein, aber 101 ist die kleinste mögliche Lösung

    state.solver.add(state.regs.rax == 200)

    assert state.solver.eval(state.regs.rax) == 200
