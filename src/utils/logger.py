"""Logging utilities with automatic PII redaction."""

import re
import sys
from typing import Optional
from loguru import logger
from src.models import get_settings


class PIIRedactor:
    """Redacts PII from log messages."""

    # Patterns for common PII types
    PATTERNS = {
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "iban": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b",
    }

    @classmethod
    def redact(cls, message: str) -> str:
        """
        Redact PII from a message.

        Args:
            message: Log message to redact

        Returns:
            Message with PII replaced with [REDACTED_{TYPE}]
        """
        redacted = message

        for pii_type, pattern in cls.PATTERNS.items():
            redacted = re.sub(pattern, f"[REDACTED_{pii_type.upper()}]", redacted, flags=re.IGNORECASE)

        return redacted


def redaction_filter(record: dict) -> bool:
    """
    Filter function for loguru that redacts PII.

    Args:
        record: Log record dictionary

    Returns:
        True (always log, but modify the record)
    """
    try:
        settings = get_settings()
        if settings.enable_pii_redaction:
            # Redact the message
            record["message"] = PIIRedactor.redact(record["message"])

            # Redact any exception text
            if record["exception"]:
                exc_text = record["exception"].get("value", "")
                if exc_text:
                    record["exception"]["value"] = PIIRedactor.redact(str(exc_text))
    except Exception:
        # Don't fail logging if redaction fails
        pass

    return True


def setup_logging(log_file: Optional[str] = None, log_level: Optional[str] = None) -> None:
    """
    Configure logging with PII redaction.

    Args:
        log_file: Path to log file (optional)
        log_level: Log level (default: INFO)
    """
    try:
        settings = get_settings()
        log_level = log_level or settings.log_level
        log_file = log_file or settings.log_file
    except Exception:
        log_level = log_level or "INFO"
        log_file = log_file or "privacy_analyzer.log"

    # Remove default handler
    logger.remove()

    # Console handler with colors and redaction
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=log_level,
        colorize=True,
        filter=redaction_filter,
    )

    # File handler with redaction
    logger.add(
        log_file,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level=log_level,
        rotation="10 MB",
        retention="30 days",
        compression="zip",
        filter=redaction_filter,
    )

    logger.info("Logging initialized with PII redaction enabled")


def get_logger(name: str):
    """
    Get a logger instance.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Configured logger instance
    """
    return logger.bind(name=name)


# Initialize on import
try:
    setup_logging()
except Exception as e:
    # Fallback basic logging
    logger.add(sys.stderr, level="INFO")
    logger.warning(f"Failed to initialize full logging: {e}")
