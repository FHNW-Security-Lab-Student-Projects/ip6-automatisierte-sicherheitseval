import angr
import logging
logging.getLogger("angr.procedures.libc.gets").setLevel(logging.ERROR)

def is_successful(state):
    return b"you have correctly got the variable to the right value\n" in state.posix.dumps(1)

def should_abort(state):
    return b"Try again, you got" in state.posix.dumps(1)

proj = angr.Project("tests/3_buffer_overflow_strcpy_copy", auto_load_libs=False)
init_state = proj.factory.entry_state()
simulation = proj.factory.simulation_manager(init_state)
simulation.explore(find=is_successful, avoid=should_abort)
                   
if simulation.found:
    solution_state = simulation.found[0]
    solution = solution_state.posix.dumps(0)
    print(len(solution))
    print("flag: ", solution)
    import subprocess
    result = subprocess.run(["./tests/3_buffer_overflow_strcpy_copy"], input=solution, capture_output=True)
    print(f"[] Antwort des Programms: {result.stdout.decode()}")
else:
    print("no flag")
