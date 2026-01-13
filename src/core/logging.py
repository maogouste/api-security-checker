"""Logging configuration for API Security Checker."""

import logging
import sys
from typing import Optional

from rich.logging import RichHandler


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    verbose: bool = False,
) -> logging.Logger:
    """
    Configure logging for the application.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path to write logs
        verbose: Enable verbose output (sets level to DEBUG)

    Returns:
        Configured logger instance
    """
    if verbose:
        level = "DEBUG"

    # Create logger
    logger = logging.getLogger("apisec")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()

    # Console handler with Rich formatting
    console_handler = RichHandler(
        rich_tracebacks=True,
        show_time=False,
        show_path=False,
        markup=True,
    )
    console_handler.setLevel(logging.WARNING if not verbose else logging.DEBUG)
    console_format = logging.Formatter("%(message)s")
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "apisec") -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name (will be prefixed with 'apisec.')

    Returns:
        Logger instance
    """
    if name == "apisec":
        return logging.getLogger(name)
    return logging.getLogger(f"apisec.{name}")
