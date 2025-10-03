"""Event definitions."""

from enum import Enum
from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class EventType(str, Enum):
    """Event types."""

    # Scan events
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_PROGRESS = "scan.progress"

    # Detection events
    PII_DETECTED = "pii.detected"
    PII_BATCH_DETECTED = "pii.batch_detected"

    # Anonymization events
    ANONYMIZATION_STARTED = "anonymization.started"
    ANONYMIZATION_COMPLETED = "anonymization.completed"

    # Compliance events
    COMPLIANCE_CHECK_STARTED = "compliance.check_started"
    COMPLIANCE_CHECK_COMPLETED = "compliance.check_completed"
    VIOLATION_DETECTED = "compliance.violation_detected"

    # Export events
    EXPORT_STARTED = "export.started"
    EXPORT_COMPLETED = "export.completed"

    # System events
    PLUGIN_LOADED = "system.plugin_loaded"
    PLUGIN_UNLOADED = "system.plugin_unloaded"
    CONFIG_CHANGED = "system.config_changed"


class Event(BaseModel):
    """Base event class."""

    event_type: EventType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str = "system"
    data: Dict[str, Any] = Field(default_factory=dict)
    correlation_id: Optional[str] = None

    class Config:
        """Pydantic config."""

        use_enum_values = True


class ScanStartedEvent(Event):
    """Event fired when a scan starts."""

    event_type: EventType = EventType.SCAN_STARTED

    def __init__(self, scan_id: str, source: str, source_type: str, **kwargs):
        """Initialize scan started event."""
        super().__init__(
            data={
                "scan_id": scan_id,
                "source": source,
                "source_type": source_type,
            },
            **kwargs
        )


class ScanCompletedEvent(Event):
    """Event fired when a scan completes."""

    event_type: EventType = EventType.SCAN_COMPLETED

    def __init__(
        self,
        scan_id: str,
        total_findings: int,
        duration_seconds: float,
        **kwargs
    ):
        """Initialize scan completed event."""
        super().__init__(
            data={
                "scan_id": scan_id,
                "total_findings": total_findings,
                "duration_seconds": duration_seconds,
            },
            **kwargs
        )


class PIIDetectedEvent(Event):
    """Event fired when PII is detected."""

    event_type: EventType = EventType.PII_DETECTED

    def __init__(
        self,
        scan_id: str,
        pii_type: str,
        location: str,
        severity: str,
        confidence: float,
        **kwargs
    ):
        """Initialize PII detected event."""
        super().__init__(
            data={
                "scan_id": scan_id,
                "pii_type": pii_type,
                "location": location,
                "severity": severity,
                "confidence": confidence,
            },
            **kwargs
        )


class ComplianceViolationEvent(Event):
    """Event fired when a compliance violation is detected."""

    event_type: EventType = EventType.VIOLATION_DETECTED

    def __init__(
        self,
        scan_id: str,
        rule_id: str,
        article: str,
        severity: str,
        description: str,
        **kwargs
    ):
        """Initialize compliance violation event."""
        super().__init__(
            data={
                "scan_id": scan_id,
                "rule_id": rule_id,
                "article": article,
                "severity": severity,
                "description": description,
            },
            **kwargs
        )
