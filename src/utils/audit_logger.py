"""Audit logging for Privacy Analyzer operations."""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any
from enum import Enum

from src.utils import get_logger

logger = get_logger(__name__)


class AuditEvent(str, Enum):
    """Audit event types."""

    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    PII_DETECTED = "pii_detected"
    ANONYMIZATION = "anonymization"
    EXPORT = "export"
    COMPLIANCE_CHECK = "compliance_check"
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    CONFIG_CHANGED = "config_changed"


class AuditLogger:
    """Logger for audit trails and compliance tracking."""

    def __init__(self, audit_file: Optional[str] = None, enable_console: bool = False):
        """
        Initialize audit logger.

        Args:
            audit_file: Path to audit log file (JSON lines format)
            enable_console: Whether to also log to console
        """
        self.audit_file = Path(audit_file) if audit_file else Path("audit.log")
        self.enable_console = enable_console

        # Ensure audit file directory exists
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        event: AuditEvent,
        user: str = "system",
        resource: Optional[str] = None,
        action: Optional[str] = None,
        result: str = "success",
        details: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> None:
        """
        Log an audit event.

        Args:
            event: Type of event
            user: User performing the action
            resource: Resource being accessed/modified
            action: Specific action taken
            result: Result of the action (success, failure, denied)
            details: Additional details
            **kwargs: Additional fields to include in audit log
        """
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event": event,
            "user": user,
            "resource": resource,
            "action": action,
            "result": result,
            "details": details or {},
            **kwargs,
        }

        # Write to audit file
        self._write_audit_entry(audit_entry)

        # Optionally log to console
        if self.enable_console:
            logger.info(f"AUDIT: {event} - {user} - {resource} - {result}")

    def log_scan_started(
        self,
        scan_id: str,
        source: str,
        source_type: str,
        user: str = "system",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log when a scan starts.

        Args:
            scan_id: Scan identifier
            source: Source being scanned
            source_type: Type of source
            user: User initiating scan
            details: Additional details
        """
        self.log(
            event=AuditEvent.SCAN_STARTED,
            user=user,
            resource=source,
            action="scan",
            result="started",
            details={
                "scan_id": scan_id,
                "source_type": source_type,
                **(details or {}),
            },
        )

    def log_scan_completed(
        self,
        scan_id: str,
        source: str,
        total_findings: int,
        duration_seconds: float,
        user: str = "system",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log when a scan completes.

        Args:
            scan_id: Scan identifier
            source: Source scanned
            total_findings: Number of findings
            duration_seconds: Scan duration
            user: User who initiated scan
            details: Additional details
        """
        self.log(
            event=AuditEvent.SCAN_COMPLETED,
            user=user,
            resource=source,
            action="scan",
            result="success",
            details={
                "scan_id": scan_id,
                "total_findings": total_findings,
                "duration_seconds": duration_seconds,
                **(details or {}),
            },
        )

    def log_pii_detected(
        self,
        scan_id: str,
        pii_type: str,
        location: str,
        severity: str,
        user: str = "system",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log when PII is detected.

        Args:
            scan_id: Scan identifier
            pii_type: Type of PII detected
            location: Location of PII
            severity: Severity level
            user: User
            details: Additional details
        """
        self.log(
            event=AuditEvent.PII_DETECTED,
            user=user,
            resource=location,
            action="detect",
            result="success",
            details={
                "scan_id": scan_id,
                "pii_type": pii_type,
                "severity": severity,
                **(details or {}),
            },
        )

    def log_anonymization(
        self,
        scan_id: str,
        strategy: str,
        pii_count: int,
        user: str = "system",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log anonymization operation.

        Args:
            scan_id: Scan identifier
            strategy: Anonymization strategy used
            pii_count: Number of PII instances anonymized
            user: User performing anonymization
            details: Additional details
        """
        self.log(
            event=AuditEvent.ANONYMIZATION,
            user=user,
            resource=scan_id,
            action="anonymize",
            result="success",
            details={
                "strategy": strategy,
                "pii_count": pii_count,
                **(details or {}),
            },
        )

    def log_export(
        self,
        scan_id: str,
        export_format: str,
        destination: str,
        user: str = "system",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log data export operation.

        Args:
            scan_id: Scan identifier
            export_format: Export format
            destination: Destination file/path
            user: User performing export
            details: Additional details
        """
        self.log(
            event=AuditEvent.EXPORT,
            user=user,
            resource=scan_id,
            action="export",
            result="success",
            details={
                "format": export_format,
                "destination": destination,
                **(details or {}),
            },
        )

    def log_compliance_check(
        self,
        scan_id: str,
        compliance_score: float,
        total_violations: int,
        user: str = "system",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log GDPR compliance check.

        Args:
            scan_id: Scan identifier
            compliance_score: Compliance score
            total_violations: Number of violations
            user: User
            details: Additional details
        """
        self.log(
            event=AuditEvent.COMPLIANCE_CHECK,
            user=user,
            resource=scan_id,
            action="compliance_check",
            result="success",
            details={
                "compliance_score": compliance_score,
                "total_violations": total_violations,
                **(details or {}),
            },
        )

    def log_access_granted(
        self,
        user: str,
        resource: str,
        action: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log successful access grant.

        Args:
            user: User granted access
            resource: Resource accessed
            action: Action performed
            details: Additional details
        """
        self.log(
            event=AuditEvent.ACCESS_GRANTED,
            user=user,
            resource=resource,
            action=action,
            result="granted",
            details=details,
        )

    def log_access_denied(
        self,
        user: str,
        resource: str,
        action: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log access denial.

        Args:
            user: User denied access
            resource: Resource attempted
            action: Action attempted
            reason: Reason for denial
            details: Additional details
        """
        self.log(
            event=AuditEvent.ACCESS_DENIED,
            user=user,
            resource=resource,
            action=action,
            result="denied",
            details={"reason": reason, **(details or {})},
        )

    def _write_audit_entry(self, entry: Dict[str, Any]) -> None:
        """
        Write audit entry to file.

        Args:
            entry: Audit entry dictionary
        """
        try:
            with open(self.audit_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def query_logs(
        self,
        event_type: Optional[AuditEvent] = None,
        user: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> list:
        """
        Query audit logs.

        Args:
            event_type: Filter by event type
            user: Filter by user
            start_time: Filter by start time
            end_time: Filter by end time
            limit: Maximum results to return

        Returns:
            List of matching audit entries
        """
        results = []

        try:
            with open(self.audit_file, "r") as f:
                for line in f:
                    if not line.strip():
                        continue

                    entry = json.loads(line)

                    # Apply filters
                    if event_type and entry.get("event") != event_type:
                        continue

                    if user and entry.get("user") != user:
                        continue

                    if start_time or end_time:
                        entry_time = datetime.fromisoformat(
                            entry.get("timestamp", "").replace("Z", "")
                        )

                        if start_time and entry_time < start_time:
                            continue

                        if end_time and entry_time > end_time:
                            continue

                    results.append(entry)

                    if len(results) >= limit:
                        break

        except FileNotFoundError:
            logger.warning("Audit log file not found")
        except Exception as e:
            logger.error(f"Failed to query audit logs: {e}")

        return results

    def get_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get summary of audit events.

        Args:
            hours: Number of hours to look back

        Returns:
            Summary statistics
        """
        start_time = datetime.utcnow() - timedelta(hours=hours)

        logs = self.query_logs(start_time=start_time, limit=10000)

        summary = {
            "total_events": len(logs),
            "time_range_hours": hours,
            "events_by_type": {},
            "events_by_user": {},
            "events_by_result": {},
        }

        for entry in logs:
            event_type = entry.get("event", "unknown")
            user = entry.get("user", "unknown")
            result = entry.get("result", "unknown")

            summary["events_by_type"][event_type] = (
                summary["events_by_type"].get(event_type, 0) + 1
            )
            summary["events_by_user"][user] = summary["events_by_user"].get(user, 0) + 1
            summary["events_by_result"][result] = (
                summary["events_by_result"].get(result, 0) + 1
            )

        return summary
