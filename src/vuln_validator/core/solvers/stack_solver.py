from .base_solver import BaseSolver
import angr
from typing import Dict, Any


class StackOverflowSolver(BaseSolver):

    @property
    def vulnerability_type(self) -> str:
        return "stack_overflow"

    def solve(self, project: angr.Project) -> Dict[str, Any]:

        init_state = project.factory.full_init_state(
            stdin=angr.SimFileStream("stdin", size=80)
        )
        # init_state = proj.factory.entry_state() # creates an initial state for the program, which represents the state of the program at the entry point (main function) with default values for registers and memory.
        simulation = project.factory.simulation_manager(
            init_state
        )  # creates a simulation manager, which is responsible for managing the execution of the program and exploring different paths through the program. The simulation manager will keep track of the active states (the states that are currently being explored) and the found states (the states that have reached a successful condition). The explore method is used to specify the conditions for finding successful states and avoiding unsuccessful states. In this case, we want to find states that print "Access granted!" and avoid states that print "Access denied!".
        simulation.explore(
            find=is_successful, avoid=should_abort
        )  # explores the program by executing it and checking the output of each state. If a state produces output that contains "Access granted!", it is added to the found states. If a state produces output that contains "Access denied!", it is avoided and not explored further. The simulation will continue until all active states have been explored or a successful state has been found.

        if simulation.found:
            solution_state = simulation.found[0]
            solution = solution_state.posix.dumps(0)
            return {
                "is_vulnerable": True,
                "type": "stack_overflow",
                "evidence": {"input": solution.hex()},
                "message": "Stack-Overflow found!",
                "code_location": hex(solution_state.addr),
            }
        else:
            return {
                "is_vulnerable": False,
                "type": "stack_overflow",
                "evidence": {},
                "message": "No Stack-Overflow found.",
            }


def is_successful(state):
    return b"Access granted!\n" in state.posix.dumps(1)


def should_abort(state):
    return b"Access denied!\n" in state.posix.dumps(1)
