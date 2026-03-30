import json
import sys
import logging

from vuln_validator.logging_config import setup_logging

from vuln_validator.core.angr_engine import AngrAnalyzer


def main() -> None:
    setup_logging()
    logger = logging.getLogger("vuln_validator.run_direct_analysis")

    default_binary_path = "tests/fixtures/5_my_vuln"
    args = sys.argv[1:]

    if args:
        binary_path = args[0]
    else:
        logger.info(f"Usage: uv run python {sys.argv[0]} <path_to_binary>")
        logger.info(f"No binary path provided. Using default: {default_binary_path}")
        binary_path = default_binary_path

    logger.info(f"Starting analysis for binary: {binary_path}")

    angr_analyzer = AngrAnalyzer(binary_path)
    result = angr_analyzer.run_analysis("auto")

    logger.info(f"Analysis completed. Result: {json.dumps(result, indent=2)}")


if __name__ == "__main__":
    main()
