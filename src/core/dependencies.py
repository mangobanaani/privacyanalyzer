"""Dependency provider functions."""

from typing import Optional
from functools import lru_cache

from src.core.container import get_container
from src.detectors.pii_detector import PIIDetector
from src.detectors.gdpr_engine import GDPREngine
from src.anonymizers import AnonymizationEngine
from src.utils import AuditLogger
from src.models import Settings


def get_settings() -> Settings:
    """
    Get application settings.

    Returns:
        Settings instance
    """
    return get_container().resolve("Settings")


def get_pii_detector(confidence_threshold: Optional[float] = None) -> PIIDetector:
    """
    Get PII detector instance.

    Args:
        confidence_threshold: Optional confidence threshold override

    Returns:
        PIIDetector instance
    """
    detector = get_container().resolve("PIIDetector")

    if confidence_threshold is not None:
        detector.confidence_threshold = confidence_threshold

    return detector


def get_gdpr_engine() -> GDPREngine:
    """
    Get GDPR engine instance.

    Returns:
        GDPREngine instance
    """
    return get_container().resolve("GDPREngine")


def get_anonymization_engine() -> AnonymizationEngine:
    """
    Get anonymization engine instance.

    Returns:
        AnonymizationEngine instance
    """
    return get_container().resolve("AnonymizationEngine")


def get_audit_logger() -> AuditLogger:
    """
    Get audit logger instance.

    Returns:
        AuditLogger instance
    """
    return get_container().resolve("AuditLogger")


# FastAPI dependency injection helpers
def inject_pii_detector() -> PIIDetector:
    """FastAPI dependency for PII detector."""
    return get_pii_detector()


def inject_gdpr_engine() -> GDPREngine:
    """FastAPI dependency for GDPR engine."""
    return get_gdpr_engine()


def inject_anonymization_engine() -> AnonymizationEngine:
    """FastAPI dependency for anonymization engine."""
    return get_anonymization_engine()


def inject_audit_logger() -> AuditLogger:
    """FastAPI dependency for audit logger."""
    return get_audit_logger()
