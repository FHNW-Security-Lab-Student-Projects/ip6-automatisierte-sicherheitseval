import angr
import logging
logging.getLogger("angr.procedures.libc.gets").setLevel(logging.ERROR)

def is_successful(state):
    return b"Access granted!\n" in state.posix.dumps(1)

def should_abort(state):
    return b"Access denied!\n" in state.posix.dumps(1)

proj = angr.Project("tests/2_buffer_overflow", auto_load_libs=False)
init_state = proj.factory.entry_state()
simulation = proj.factory.simulation_manager(init_state)
simulation.explore(find=is_successful, avoid=should_abort)
                   
if simulation.found:
    solution_state = simulation.found[0]
    solution = solution_state.posix.dumps(0)
    print("flag: ", solution)
    import subprocess
    result = subprocess.run(["./tests/2_buffer_overflow"], input=solution, capture_output=True)
    print(f"[] Antwort des Programms: {result.stdout.decode()}")
else:
    print("no flag")
