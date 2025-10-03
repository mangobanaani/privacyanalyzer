"""Core dependency injection and container."""

from .container import Container, get_container
from .dependencies import get_pii_detector, get_gdpr_engine, get_audit_logger

__all__ = ["Container", "get_container", "get_pii_detector", "get_gdpr_engine", "get_audit_logger"]
