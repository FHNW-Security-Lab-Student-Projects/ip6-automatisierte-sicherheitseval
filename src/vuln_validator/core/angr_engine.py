import angr
import logging
from .solvers import stack_solver

logging.getLogger('angr').setLevel(logging.ERROR)

def run_analysis(target_path: str, vuln_type: str) -> str:
    """
    Main function called by MCP.
    Loads the binary and delegates to the appropriate solver.
    """
    try:
        # TODO: check if binary or source code, handle accordingly
        proj = angr.Project(target_path, auto_load_libs=False)
        
        return stack_solver.solve(proj)
    
        # if vuln_type == "stack_overflow":
        #     return stack_solver.solve(proj)
        # elif vuln_type == "heap_overflow":
        #     return "Heap-Analyse noch nicht implementiert."
        # else:
        #     return "Unbekannter Vulnerabilitätstyp."
            
    except Exception as e:
        return f"Fehler bei der Analyse: {str(e)}"