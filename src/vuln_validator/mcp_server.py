from mcp.server.fastmcp import FastMCP
from typing import Literal

from vuln_validator.core.angr_engine import AngrAnalyzer

mcp = FastMCP("VulnValidator")


@mcp.prompt()
def find_vulnerability_workflow(target_path: str) -> str:
    """
    A workflow prompt that instructs the LLM to analyze code and validate the hypothesis rigorously.
    """
    return f"""
    You are a rigorous Security Auditor. Your task is to analyze the source code or binary at `{target_path}`.
    
    Follow this strict procedure:
    1. **Analyze**: Read the file at `{target_path}` (if source code) or inspect its properties. Formulate a hypothesis: "I suspect a [TYPE] vulnerability because..."
    2. **Validate**: You MUST call the tool `validate_vulnerability` with the path and your suspected type to verify your hypothesis.
       - Do NOT rely on your internal knowledge for the final verdict.
    3. **Report**: Describe the results based on the tool's evidence and provide a detailed report. Your previous hypothesis is no longer relevant after validation. The tool's evidence is the only basis for your final report.
       - If the tool is inconclusive: state clearly that automated validation failed. Do not guess. Just report the uncertainty.
    """
    # TODO: Nächster Schritt: LLM soll target_path und function_name zur Validierung mitgeben


@mcp.tool()
def validate_vulnerability(
    target_path: str,
    vulnerability_type: Literal[
        "stack_overflow", "heap_overflow", "format_string", "auto"
    ] = "auto",
) -> dict:
    """
    Validates a vulnerability hypothesis using symbolic execution (angr).
    If 'auto' is selected, the tool automatically detects the vulnerability type
    and runs all relevant solvers. Use this if you are unsure about the specific vulnerability class.

    Args:
        target_path: Full path to the binary/source on the host system.
        vulnerability_type: The type of vulnerability to check for.

    Returns:
        A JSON object with analysis results.
    """
    angr_analyzer = AngrAnalyzer(target_path)
    result = angr_analyzer.run_analysis(vulnerability_type)

    if isinstance(result, str):
        # Fallback: If the result is a string, we assume it's an error message or inconclusive result.
        return {"error": result}

    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")
