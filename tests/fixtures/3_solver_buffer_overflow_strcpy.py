import angr
import claripy
import logging

logging.getLogger("angr.procedures.libc.gets").setLevel(logging.ERROR)

def is_successful(state):
    return b"you have correctly got the variable to the right value" in state.posix.dumps(1)

def should_abort(state):
    return b"Try again, you got" in state.posix.dumps(1)

proj = angr.Project("tests/3_buffer_overflow_strcpy", auto_load_libs=False, use_sim_procedures=True)

# symbolisches Argument
arg = claripy.BVS("arg", 200 * 8)

init_state = proj.factory.full_init_state(
    args=["tests/3_buffer_overflow_strcpy", arg]
)

simulation = proj.factory.simulation_manager(init_state)
simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
    solution_state = simulation.found[0]
    solution = solution_state.solver.eval(arg, cast_to=bytes)
    print("flag:", solution)

    import subprocess
    result = subprocess.run(["./tests/3_buffer_overflow_strcpy"], input=solution, capture_output=True)
    print("Antwort:", result.stdout.decode())
else:
    print("no flag")