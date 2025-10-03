"""Tests for scan comparator."""

import pytest
from datetime import datetime
from src.utils.comparator import ScanComparator
from src.models import ScanResult, Finding, Severity


class TestScanComparator:
    """Test scan comparison functionality."""

    @pytest.fixture
    def comparator(self):
        """Create a scan comparator instance."""
        return ScanComparator()

    @pytest.fixture
    def baseline_result(self):
        """Create baseline scan result."""
        result = ScanResult(
            source="test.txt",
            source_type="document",
            scan_id="baseline-123"
        )

        # Add findings
        result.add_finding(Finding(
            id="baseline-1",
            source="test.txt",
            location="line 1",
            pii_type="EMAIL",
            content="john@example.com",
            context="Email: john@example.com",
            confidence=0.95,
            severity=Severity.MEDIUM,
            recommendation="Encrypt or mask email"
        ))

        result.add_finding(Finding(
            id="baseline-2",
            source="test.txt",
            location="line 2",
            pii_type="PHONE_NUMBER",
            content="555-1234",
            context="Phone: 555-1234",
            confidence=0.90,
            severity=Severity.MEDIUM,
            recommendation="Mask phone number"
        ))

        result.add_finding(Finding(
            id="baseline-3",
            source="test.txt",
            location="line 3",
            pii_type="SSN",
            content="123-45-6789",
            context="SSN: 123-45-6789",
            confidence=0.98,
            severity=Severity.CRITICAL,
            recommendation="Hash SSN"
        ))

        result.complete()
        return result

    @pytest.fixture
    def current_result(self):
        """Create current scan result."""
        result = ScanResult(
            source="test.txt",
            source_type="document",
            scan_id="current-456"
        )

        # Keep email finding (unchanged)
        result.add_finding(Finding(
            id="current-1",
            source="test.txt",
            location="line 1",
            pii_type="EMAIL",
            content="john@example.com",
            context="Email: john@example.com",
            confidence=0.95,
            severity=Severity.MEDIUM,
            recommendation="Encrypt or mask email"
        ))

        # Phone was removed (resolved)
        # SSN still present but different confidence (modified)
        result.add_finding(Finding(
            id="current-2",
            source="test.txt",
            location="line 3",
            pii_type="SSN",
            content="123-45-6789",
            context="SSN: 123-45-6789",
            confidence=0.99,  # Changed confidence
            severity=Severity.CRITICAL,
            recommendation="Hash SSN"
        ))

        # New finding
        result.add_finding(Finding(
            id="current-3",
            source="test.txt",
            location="line 4",
            pii_type="CREDIT_CARD",
            content="4532-1234-5678-9010",
            context="CC: 4532-1234-5678-9010",
            confidence=0.95,
            severity=Severity.CRITICAL,
            recommendation="Remove credit card number"
        ))

        result.complete()
        return result

    def test_compare_basic(self, comparator: ScanComparator, baseline_result, current_result):
        """Test basic comparison."""
        comparison = comparator.compare(baseline_result, current_result)

        assert "baseline" in comparison
        assert "current" in comparison
        assert "changes" in comparison
        assert "summary" in comparison

    def test_compare_new_findings(self, comparator: ScanComparator, baseline_result, current_result):
        """Test detection of new findings."""
        comparison = comparator.compare(baseline_result, current_result)

        new_findings = comparison["changes"]["new_findings"]
        assert len(new_findings) == 1
        assert new_findings[0]["pii_type"] == "CREDIT_CARD"

    def test_compare_resolved_findings(self, comparator: ScanComparator, baseline_result, current_result):
        """Test detection of resolved findings."""
        comparison = comparator.compare(baseline_result, current_result)

        resolved = comparison["changes"]["resolved_findings"]
        assert len(resolved) == 1
        assert resolved[0]["pii_type"] == "PHONE_NUMBER"

    def test_compare_modified_findings(self, comparator: ScanComparator, baseline_result, current_result):
        """Test detection of modified findings."""
        comparison = comparator.compare(baseline_result, current_result)

        modified = comparison["changes"]["modified_findings"]
        assert len(modified) == 1
        assert modified[0]["pii_type"] == "SSN"
        assert modified[0]["baseline_confidence"] == 0.98
        assert modified[0]["current_confidence"] == 0.99

    def test_compare_unchanged_findings(self, comparator: ScanComparator, baseline_result, current_result):
        """Test detection of unchanged findings."""
        comparison = comparator.compare(baseline_result, current_result)

        unchanged = comparison["changes"]["unchanged_findings"]
        # Email should be unchanged
        assert any(f["pii_type"] == "EMAIL" for f in unchanged)

    def test_compare_summary(self, comparator: ScanComparator, baseline_result, current_result):
        """Test comparison summary."""
        comparison = comparator.compare(baseline_result, current_result)

        summary = comparison["summary"]
        assert summary["new_count"] == 1
        assert summary["resolved_count"] == 1
        assert summary["modified_count"] == 1
        assert summary["net_change"] == 0  # 1 new - 1 resolved

    def test_compare_trend_worse(self, comparator: ScanComparator, baseline_result):
        """Test trend detection when getting worse."""
        # Current with more findings
        current = ScanResult(
            source="test.txt",
            source_type="document",
            scan_id="current-456"
        )

        # Add all baseline findings plus new ones
        for finding in baseline_result.findings:
            current.add_finding(finding)

        current.add_finding(Finding(
            id="trend-worse-1",
            source="test.txt",
            location="line 5",
            pii_type="CREDIT_CARD",
            content="4532-1234",
            context="CC: 4532-1234",
            confidence=0.95,
            severity=Severity.CRITICAL,
            recommendation="Remove credit card"
        ))

        current.complete()

        comparison = comparator.compare(baseline_result, current)
        assert comparison["summary"]["trend"] == "worse"

    def test_compare_trend_better(self, comparator: ScanComparator, baseline_result):
        """Test trend detection when getting better."""
        # Current with fewer findings
        current = ScanResult(
            source="test.txt",
            source_type="document",
            scan_id="current-456"
        )

        # Only add first finding
        current.add_finding(baseline_result.findings[0])
        current.complete()

        comparison = comparator.compare(baseline_result, current)
        assert comparison["summary"]["trend"] == "better"

    def test_compare_trend_stable(self, comparator: ScanComparator, baseline_result):
        """Test trend detection when stable."""
        # Current with same number of findings
        current = ScanResult(
            source="test.txt",
            source_type="document",
            scan_id="current-456"
        )

        # Different findings but same count
        current.add_finding(Finding(
            id="stable-1",
            source="test.txt",
            location="line 10",
            pii_type="EMAIL",
            content="different@example.com",
            context="Email: different@example.com",
            confidence=0.95,
            severity=Severity.MEDIUM,
            recommendation="Mask email"
        ))

        current.add_finding(Finding(
            id="stable-2",
            source="test.txt",
            location="line 11",
            pii_type="PHONE_NUMBER",
            content="555-9999",
            context="Phone: 555-9999",
            confidence=0.90,
            severity=Severity.MEDIUM,
            recommendation="Mask phone"
        ))

        current.add_finding(Finding(
            id="stable-3",
            source="test.txt",
            location="line 12",
            pii_type="SSN",
            content="999-99-9999",
            context="SSN: 999-99-9999",
            confidence=0.98,
            severity=Severity.CRITICAL,
            recommendation="Hash SSN"
        ))

        current.complete()

        comparison = comparator.compare(baseline_result, current)
        assert comparison["summary"]["trend"] == "stable"

    def test_compare_severity_distribution(self, comparator: ScanComparator, baseline_result, current_result):
        """Test severity distribution comparison."""
        comparison = comparator.compare_severity_distribution(baseline_result, current_result)

        assert "baseline" in comparison
        assert "current" in comparison
        assert "changes" in comparison

    def test_compare_pii_types(self, comparator: ScanComparator, baseline_result, current_result):
        """Test PII type comparison."""
        comparison = comparator.compare_pii_types(baseline_result, current_result)

        assert "new_types" in comparison
        assert "removed_types" in comparison
        assert "changed_types" in comparison

        assert "CREDIT_CARD" in comparison["new_types"]
        assert "PHONE_NUMBER" in comparison["removed_types"]

    def test_generate_comparison_report(self, comparator: ScanComparator, baseline_result, current_result):
        """Test report generation."""
        report = comparator.generate_comparison_report(baseline_result, current_result)

        assert "SCAN COMPARISON REPORT" in report
        assert "SUMMARY" in report
        assert "NEW FINDINGS" in report
        assert "RESOLVED FINDINGS" in report
        assert baseline_result.scan_id in report
        assert current_result.scan_id in report

    def test_create_signature(self, comparator: ScanComparator):
        """Test finding signature creation."""
        finding = Finding(
            id="sig-test-1",
            source="test.txt",
            location="line 1",
            pii_type="EMAIL",
            content="john@example.com",
            context="Email: john@example.com",
            confidence=0.95,
            severity=Severity.MEDIUM,
            recommendation="Mask email"
        )

        signature = comparator._create_signature(finding)

        assert "line 1" in signature
        assert "EMAIL" in signature
        assert "john@example.com" in signature
