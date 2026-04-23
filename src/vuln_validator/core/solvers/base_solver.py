from abc import ABC, abstractmethod
import angr
from typing import Dict, Any


class BaseSolver(ABC):
    """
    Base-Interface for all vulnerability solvers.
    Each new solver (Stack, Heap, FormatString, ...) must inherit from this class.
    """

    @property
    @abstractmethod
    def vulnerability_type(self) -> str:
        """Returns the name of the vulnerability type (e.g., 'stack_overflow')."""
        pass

    @abstractmethod
    def solve(
        self, project: angr.Project, target_function: str = None
    ) -> Dict[str, Any]:
        """
        Analyzes the given angr project for the specific vulnerability type and returns the results.

        Args:
            project: The loaded angr.Project representing the binary to analyze.
            target_function: Optional name of the function to focus the analysis on. If None, analyzes the entire binary.

        Returns:
            A dictionary with: # TODO
            - 'is_vulnerable': bool
            - 'type': str (vulnerability type)
            - 'target_function': str (the function analyzed)
            - 'evidence': dict (details about the vulnerability)
            - 'message': str (Readable summary)
        """
        pass
