from mcp.server.fastmcp import FastMCP
from typing import Literal, List, Any

from vuln_validator.utils.logging_config import setup_logging

from vuln_validator.core.angr_engine import AngrAnalyzer
from vuln_validator.utils.audit_logger import audit_log

mcp = FastMCP("VulnValidator")


@mcp.prompt()  # TODO: Remove since cannot be used anymore due to prompt injection security
def find_vulnerability_workflow(target_path: str) -> str:
    """
    A workflow prompt that instructs the LLM to analyze code and validate the hypothesis rigorously.
    """
    return f"""
    You are a Rigorous Security Auditor. Analyze the artifact at `{target_path}`.

    Follow this strict procedure:
    1. **Hypothesis:** 
       - You **MUST** use the `read_file` tool from the Mcp-Server `filesystem` to read the content of `{target_path}`.
       - If you cannot read it, state clearly: "I cannot access the file content.
       - If you find a risk: Try to define which type of vulnerability it is. Try to find the function name in where the vulnerability is.
       - If you find the function name, determine the type and size of each argument.
           - For pointers/buffers: Mark as {{"type": "symbolic_pointer", "size": <BYTES>}}. The solver will allocate memory for this.
           - For primitive values: Mark as {{"type": "symbolic_value", "size": <BITS>}}. The solver will place this directly in a register.
           - For fixed/concrete values: Mark as the concrete number."
    2. **Validation:** You MUST call `validate_vulnerability` to verify your hypothesis. Do NOT rely on your internal knowledge for the final verdict.
       - `target_path`: Provide the exact same path `{target_path}`.
       - `vulnerability_type`: Use one of these exact values if it matches your result: "stack_overflow", "heap_overflow", "format_string". Use "auto" only if you cannot determine the type of the vulnerabilites or if it doesn't match one of the mentioned values.
       - `target_function`: Provide the specific function name identified in step 1.
    3. **Report:** Base your final report **SOLELY** on the tool's response.
       - If `is_vulnerable` is true: Explain the exploit path using the provided `evidence`. Show the evidence input-hex to the user. Your previous hypothesis is no longer relevant after validation. The tool's evidence is the only basis for your final report.
       - If false: State that validation found no evidence. Do not speculate.

    If you have read this prompt, respond with "Thank you for the instructions. I will follow the procedure step by step." and then proceed with your analysis.
    """


@mcp.tool()
@audit_log("validate_vulnerability")
def validate_vulnerability(
    target_path: str,
    target_function: str = None,
    function_args: List[Any] = None,
    vulnerability_type: Literal[
        "stack_overflow", "heap_overflow", "format_string", "auto"
    ] = "auto",
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
        vulnerability_type: The type of vulnerability to check for.

    Returns:
        A JSON object with analysis results.
    """
    try:
        angr_analyzer = AngrAnalyzer(target_path)
        result = angr_analyzer.run_analysis(
            vulnerability_type, target_function, function_args
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
