"""Tests for audit logger."""

import pytest
import json
from pathlib import Path
from datetime import datetime, timedelta
from src.utils.audit_logger import AuditLogger, AuditEvent


class TestAuditLogger:
    """Test audit logging functionality."""

    @pytest.fixture
    def audit_file(self, temp_dir):
        """Create temporary audit file."""
        return temp_dir / "test_audit.log"

    @pytest.fixture
    def logger(self, audit_file):
        """Create audit logger instance."""
        return AuditLogger(str(audit_file), enable_console=False)

    def test_initialization(self, audit_file, logger: AuditLogger):
        """Test audit logger initialization."""
        assert logger.audit_file == audit_file
        assert logger.enable_console is False

    def test_log_basic(self, logger: AuditLogger, audit_file):
        """Test basic logging."""
        logger.log(
            event=AuditEvent.SCAN_STARTED,
            user="test_user",
            resource="test.txt",
            action="scan",
            result="success"
        )

        assert audit_file.exists()

        with open(audit_file, "r") as f:
            line = f.readline()
            entry = json.loads(line)

            assert entry["event"] == AuditEvent.SCAN_STARTED
            assert entry["user"] == "test_user"
            assert entry["resource"] == "test.txt"
            assert entry["action"] == "scan"
            assert entry["result"] == "success"

    def test_log_scan_started(self, logger: AuditLogger, audit_file):
        """Test logging scan started event."""
        logger.log_scan_started(
            scan_id="test-123",
            source="document.pdf",
            source_type="document",
            user="analyst"
        )

        with open(audit_file, "r") as f:
            entry = json.loads(f.readline())

            assert entry["event"] == AuditEvent.SCAN_STARTED
            assert entry["details"]["scan_id"] == "test-123"
            assert entry["details"]["source_type"] == "document"
            assert entry["user"] == "analyst"

    def test_log_scan_completed(self, logger: AuditLogger, audit_file):
        """Test logging scan completed event."""
        logger.log_scan_completed(
            scan_id="test-123",
            source="document.pdf",
            total_findings=15,
            duration_seconds=2.5
        )

        with open(audit_file, "r") as f:
            entry = json.loads(f.readline())

            assert entry["event"] == AuditEvent.SCAN_COMPLETED
            assert entry["details"]["total_findings"] == 15
            assert entry["details"]["duration_seconds"] == 2.5

    def test_log_pii_detected(self, logger: AuditLogger, audit_file):
        """Test logging PII detection."""
        logger.log_pii_detected(
            scan_id="test-123",
            pii_type="EMAIL_ADDRESS",
            location="line 5",
            severity="medium"
        )

        with open(audit_file, "r") as f:
            entry = json.loads(f.readline())

            assert entry["event"] == AuditEvent.PII_DETECTED
            assert entry["details"]["pii_type"] == "EMAIL_ADDRESS"
            assert entry["details"]["severity"] == "medium"

    def test_log_anonymization(self, logger: AuditLogger, audit_file):
        """Test logging anonymization."""
        logger.log_anonymization(
            scan_id="test-123",
            strategy="mask",
            pii_count=10,
            user="operator"
        )

        with open(audit_file, "r") as f:
            entry = json.loads(f.readline())

            assert entry["event"] == AuditEvent.ANONYMIZATION
            assert entry["details"]["strategy"] == "mask"
            assert entry["details"]["pii_count"] == 10

    def test_log_export(self, logger: AuditLogger, audit_file):
        """Test logging export operation."""
        logger.log_export(
            scan_id="test-123",
            export_format="csv",
            destination="findings.csv"
        )

        with open(audit_file, "r") as f:
            entry = json.loads(f.readline())

            assert entry["event"] == AuditEvent.EXPORT
            assert entry["details"]["format"] == "csv"
            assert entry["details"]["destination"] == "findings.csv"

    def test_log_compliance_check(self, logger: AuditLogger, audit_file):
        """Test logging compliance check."""
        logger.log_compliance_check(
            scan_id="test-123",
            compliance_score=75.5,
            total_violations=3
        )

        with open(audit_file, "r") as f:
            entry = json.loads(f.readline())

            assert entry["event"] == AuditEvent.COMPLIANCE_CHECK
            assert entry["details"]["compliance_score"] == 75.5
            assert entry["details"]["total_violations"] == 3

    def test_log_access_granted(self, logger: AuditLogger, audit_file):
        """Test logging access granted."""
        logger.log_access_granted(
            user="analyst",
            resource="scan-results",
            action="read"
        )

        with open(audit_file, "r") as f:
            entry = json.loads(f.readline())

            assert entry["event"] == AuditEvent.ACCESS_GRANTED
            assert entry["result"] == "granted"

    def test_log_access_denied(self, logger: AuditLogger, audit_file):
        """Test logging access denied."""
        logger.log_access_denied(
            user="guest",
            resource="scan-results",
            action="delete",
            reason="insufficient permissions"
        )

        with open(audit_file, "r") as f:
            entry = json.loads(f.readline())

            assert entry["event"] == AuditEvent.ACCESS_DENIED
            assert entry["result"] == "denied"
            assert entry["details"]["reason"] == "insufficient permissions"

    def test_query_logs_no_filter(self, logger: AuditLogger):
        """Test querying logs without filters."""
        # Add multiple entries
        logger.log(AuditEvent.SCAN_STARTED, user="user1", resource="file1.txt")
        logger.log(AuditEvent.SCAN_COMPLETED, user="user1", resource="file1.txt")
        logger.log(AuditEvent.PII_DETECTED, user="user2", resource="file2.txt")

        results = logger.query_logs()

        assert len(results) == 3

    def test_query_logs_by_event_type(self, logger: AuditLogger):
        """Test querying logs by event type."""
        logger.log(AuditEvent.SCAN_STARTED, user="user1", resource="file1.txt")
        logger.log(AuditEvent.SCAN_COMPLETED, user="user1", resource="file1.txt")
        logger.log(AuditEvent.PII_DETECTED, user="user2", resource="file2.txt")

        results = logger.query_logs(event_type=AuditEvent.SCAN_STARTED)

        assert len(results) == 1
        assert results[0]["event"] == AuditEvent.SCAN_STARTED

    def test_query_logs_by_user(self, logger: AuditLogger):
        """Test querying logs by user."""
        logger.log(AuditEvent.SCAN_STARTED, user="user1", resource="file1.txt")
        logger.log(AuditEvent.SCAN_COMPLETED, user="user1", resource="file1.txt")
        logger.log(AuditEvent.PII_DETECTED, user="user2", resource="file2.txt")

        results = logger.query_logs(user="user1")

        assert len(results) == 2
        assert all(r["user"] == "user1" for r in results)

    def test_query_logs_by_time_range(self, logger: AuditLogger):
        """Test querying logs by time range."""
        # Log entries
        logger.log(AuditEvent.SCAN_STARTED, user="user1")

        # Query with time filter
        start_time = datetime.utcnow() - timedelta(minutes=5)
        end_time = datetime.utcnow() + timedelta(minutes=5)

        results = logger.query_logs(start_time=start_time, end_time=end_time)

        assert len(results) >= 1

    def test_query_logs_limit(self, logger: AuditLogger):
        """Test query limit."""
        # Add many entries
        for i in range(10):
            logger.log(AuditEvent.SCAN_STARTED, user=f"user{i}")

        results = logger.query_logs(limit=5)

        assert len(results) == 5

    def test_get_summary(self, logger: AuditLogger):
        """Test getting audit summary."""
        # Add various events
        logger.log(AuditEvent.SCAN_STARTED, user="user1")
        logger.log(AuditEvent.SCAN_COMPLETED, user="user1")
        logger.log(AuditEvent.PII_DETECTED, user="user2")
        logger.log(AuditEvent.SCAN_STARTED, user="user1")

        summary = logger.get_summary(hours=24)

        assert summary["total_events"] >= 4
        assert "events_by_type" in summary
        assert "events_by_user" in summary
        assert "events_by_result" in summary

    def test_get_summary_events_by_type(self, logger: AuditLogger):
        """Test summary events by type."""
        logger.log(AuditEvent.SCAN_STARTED, user="user1")
        logger.log(AuditEvent.SCAN_STARTED, user="user2")
        logger.log(AuditEvent.PII_DETECTED, user="user1")

        summary = logger.get_summary(hours=24)

        assert summary["events_by_type"][AuditEvent.SCAN_STARTED] == 2
        assert summary["events_by_type"][AuditEvent.PII_DETECTED] == 1

    def test_get_summary_events_by_user(self, logger: AuditLogger):
        """Test summary events by user."""
        logger.log(AuditEvent.SCAN_STARTED, user="user1")
        logger.log(AuditEvent.SCAN_STARTED, user="user1")
        logger.log(AuditEvent.PII_DETECTED, user="user2")

        summary = logger.get_summary(hours=24)

        assert summary["events_by_user"]["user1"] == 2
        assert summary["events_by_user"]["user2"] == 1

    def test_multiple_entries(self, logger: AuditLogger, audit_file):
        """Test logging multiple entries."""
        for i in range(5):
            logger.log(
                event=AuditEvent.SCAN_STARTED,
                user=f"user{i}",
                resource=f"file{i}.txt"
            )

        with open(audit_file, "r") as f:
            lines = f.readlines()

        assert len(lines) == 5

        # Verify each entry is valid JSON
        for line in lines:
            entry = json.loads(line)
            assert "event" in entry
            assert "user" in entry
            assert "timestamp" in entry
