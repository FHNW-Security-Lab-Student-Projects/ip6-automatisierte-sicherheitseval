import logging


class _ShortLoggerNameFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.shortname = record.name.rsplit(".", 1)[-1]
        return True


def setup_logging() -> None:
    """Configure application logging for CLI and MCP entry points."""
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)-7s - %(shortname)-25s - %(message)s"
    )
    short_name_filter = _ShortLoggerNameFilter()

    app_handler = logging.StreamHandler()
    app_handler.setFormatter(formatter)
    app_handler.addFilter(short_name_filter)

    app_logger = logging.getLogger("vuln_validator")
    app_logger.handlers.clear()
    app_logger.addHandler(app_handler)
    app_logger.setLevel(logging.INFO)
    app_logger.propagate = False

    logging.getLogger("cle").setLevel(logging.ERROR)
    logging.getLogger("angr").setLevel(logging.ERROR)
