import json
import sys
import logging
from pathlib import Path

from vuln_validator.utils.logging_config import setup_logging
from vuln_validator.utils.audit_logger import log_audit_event
from vuln_validator.core.angr_engine import AngrAnalyzer


def main() -> None:
    setup_logging()
    logger = logging.getLogger("vuln_validator.run_direct_analysis")

    default_binary_path = "tests/fixtures/5_my_vuln"
    args = sys.argv[1:]
    binary_path = args[0] if args else default_binary_path
    target_function = args[1] if len(args) > 1 else None

    if not Path(binary_path).exists():
        logger.error(f"Binary not found: {binary_path}")
        # Write error to audit log as well, since this is a critical failure that prevents any analysis
        log_audit_event(
            {
                "event": "validation_failed",
                "source": "run_direct_analysis.py",
                "status": "error",
                "error_message": f"File not found: {binary_path}",
            }
        )
        sys.exit(1)

    log_audit_event(
        {
            "event": "validation_started",
            "source": "run_direct_analysis.py",
            "tool": "validate_vulnerability",
            "input": {
                "target_path": str(Path(binary_path).resolve()),
                "vulnerability_type": "auto",
            },
        }
    )

    logger.info(f"Starting analysis for binary: {binary_path}")

    result = {}
    try:
        # execute analysis with auto-detection of vulnerability type
        angr_analyzer = AngrAnalyzer(binary_path)
        result = angr_analyzer.run_analysis("auto", target_function)

        # developer logging for debugging and insight into results
        logger.info("Analysis completed.")
        logger.info(result)
        logger.debug(json.dumps(result, indent=2))

        # audit log with structured summary of results for later review and metrics
        log_audit_event(
            {
                "event": "validation_completed",
                "source": "run_direct_analysis.py",
                "status": "success",
                "summary": {
                    "is_vulnerable": result.get("is_vulnerable"),
                    "analyzed_types": result.get("analyzed_types"),
                    "message": result.get("messages", []),
                },
            }
        )

    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)

        # audit log entry for failure, capturing the error message for post-mortem analysis
        log_audit_event(
            {
                "event": "validation_failed",
                "source": "run_direct_analysis.py",
                "status": "error",
                "error_message": str(e),
            }
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
