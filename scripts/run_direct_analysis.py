import json
import sys

from vuln_validator.core.angr_engine import AngrAnalyzer


def main() -> None:
    default_binary_path = "tests/fixtures/2_buffer_overflow"
    args = sys.argv[1:]

    if args:
        binary_path = args[0]
    else:
        print("Usage: uv run python scripts/run_direct_analysis.py <path_to_binary>")
        binary_path = default_binary_path
        print(f"No binary path provided. Using default: {binary_path}")

    print(f"Start analysis for: {binary_path}")

    angr_analyzer = AngrAnalyzer(binary_path)
    result = angr_analyzer.run_analysis("auto")

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
