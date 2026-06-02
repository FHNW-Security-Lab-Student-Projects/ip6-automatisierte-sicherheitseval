from mcp.server.fastmcp import FastMCP
from typing import List, Any, Dict

from vuln_validator.utils.logging_config import setup_logging

from vuln_validator.core.angr_analyzer import AngrAnalyzer
from vuln_validator.utils.audit_logger import audit_log

mcp = FastMCP("VulnValidator")


@mcp.tool()
@audit_log("validate_vulnerability")
def validate_vulnerability(
    target_path: str,
    target_function: str = None,
    function_args: List[Any] = None,
    structs: List[Dict[str, Any]] = None,
    vulnerability_type: str = "auto",
) -> dict:
    """
    Validates a vulnerability hypothesis using symbolic execution (angr).
    If 'auto' is selected, the tool automatically detects the vulnerability type
    and runs all relevant solvers. Use this if you are unsure about the specific vulnerability class.
    Currently available specific vulnerability classes are: "stack_overflow", "heap_overflow", "format_string".

    Args:
        target_path: Full path to the binary/source on the host system.
        target_function: Optional specific function to analyze. If not provided, analysis starts from the entry point.
        function_args: Optional dictionary of function arguments with their types and sizes.
        structs: list of struct definitions used in the target function.
        vulnerability_type: The type of vulnerability to check for.

    Returns:
        A JSON object with analysis results.
    """
    try:
        angr_analyzer = AngrAnalyzer(target_path)
        result = angr_analyzer.run_analysis(
            vulnerability_type, target_function, function_args, structs
        )

        return result

    except FileNotFoundError as e:
        return {
            "error": "FileNotFound",
            "message": str(e),
            "suggestion": "Notify the user that the provided path is invalid.",
        }
    except Exception as e:
        return {
            "error": "AnalysisError",
            "message": str(e),
            "suggestion": "An error occurred during analysis. Check the error message for details. Notify the user that the analysis failed.",
        }


if __name__ == "__main__":
    setup_logging()
    mcp.run(transport="stdio")
