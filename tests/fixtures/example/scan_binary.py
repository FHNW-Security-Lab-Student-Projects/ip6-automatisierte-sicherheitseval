import angr ,sys

def is_successful(state):
    return b"Good Job" in state.posix.dumps (1)

def should_abort(state):
    return b"Try again" in state.posix.dumps (1)

proj = angr.Project("tests/example/binary")
init_state = proj.factory. entry_state ()
simulation = proj.factory.simgr(init_state)
simulation.explore(find=is_successful, avoid= should_abort)

if simulation.found:
    solution = simulation.found [0]
    print("flag: ", solution.posix.dumps (0))
else:
    print("no flag")