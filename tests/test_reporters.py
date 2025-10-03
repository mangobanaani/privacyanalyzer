"""Tests for report generation."""

import pytest
from pathlib import Path
from src.reporters.csv_reporter import CSVReporter
from src.models import ScanResult, Finding, Severity


class TestCSVReporter:
    """Test CSV export functionality."""

    @pytest.fixture
    def reporter(self):
        """Create a CSV reporter instance."""
        return CSVReporter()

    @pytest.fixture
    def sample_result(self):
        """Create a sample scan result."""
        result = ScanResult(
            source="test.txt",
            source_type="document",
            scan_id="test-123"
        )

        finding = Finding(
            id="reporter-finding-1",
            source="test.txt",
            location="line 1",
            pii_type="EMAIL",
            content="test@example.com",
            context="Contact me at test@example.com for more info.",
            confidence=0.95,
            severity=Severity.MEDIUM,
            recommendation="Encrypt email addresses in storage",
            gdpr_articles=["Art. 6"]
        )

        result.add_finding(finding)
        result.complete()

        return result

    def test_export_findings(self, reporter: CSVReporter, sample_result: ScanResult, temp_dir: Path):
        """Test exporting findings to CSV."""
        output_path = temp_dir / "findings.csv"

        reporter.export_findings(sample_result, str(output_path))

        assert output_path.exists()

        # Read and verify content
        with open(output_path, "r") as f:
            content = f.read()
            assert "EMAIL" in content
            assert "test.txt" in content
            assert "medium" in content.lower()

    def test_export_summary(self, reporter: CSVReporter, sample_result: ScanResult, temp_dir: Path):
        """Test exporting summary to CSV."""
        output_path = temp_dir / "summary.csv"

        reporter.export_summary(sample_result, str(output_path))

        assert output_path.exists()

        with open(output_path, "r") as f:
            content = f.read()
            assert "Privacy Scan Summary" in content
            assert "test.txt" in content

    def test_export_empty_findings(self, reporter: CSVReporter, temp_dir: Path):
        """Test exporting when there are no findings."""
        result = ScanResult(
            source="clean.txt",
            source_type="document",
            scan_id="clean-123"
        )
        result.complete()

        output_path = temp_dir / "empty.csv"

        # Should handle gracefully
        reporter.export_findings(result, str(output_path))


class TestExcelReporter:
    """Test Excel export functionality."""

    @pytest.fixture
    def reporter(self):
        """Create an Excel reporter instance."""
        from src.reporters.csv_reporter import ExcelReporter
        return ExcelReporter()

    @pytest.fixture
    def sample_result(self):
        """Create a sample scan result."""
        result = ScanResult(
            source="test.txt",
            source_type="document",
            scan_id="test-123"
        )

        finding1 = Finding(
            id="excel-finding-1",
            source="test.txt",
            location="line 1",
            pii_type="EMAIL",
            content="test@example.com",
            context="Email: test@example.com",
            confidence=0.95,
            severity=Severity.MEDIUM,
            recommendation="Encrypt email"
        )

        finding2 = Finding(
            id="excel-finding-2",
            source="test.txt",
            location="line 2",
            pii_type="SSN",
            content="123-45-6789",
            context="SSN: 123-45-6789",
            confidence=0.98,
            severity=Severity.CRITICAL,
            recommendation="Hash SSN"
        )

        result.add_finding(finding1)
        result.add_finding(finding2)
        result.complete()

        return result

    def test_export_excel(self, reporter, sample_result: ScanResult, temp_dir: Path):
        """Test exporting to Excel format."""
        output_path = temp_dir / "report.xlsx"

        try:
            reporter.export_findings(sample_result, str(output_path))

            # If openpyxl is available, should create Excel file
            if output_path.exists():
                assert output_path.suffix == ".xlsx"
            else:
                # Falls back to CSV if openpyxl not available
                csv_path = temp_dir / "report.csv"
                assert csv_path.exists()

        except ImportError:
            # openpyxl not installed, should fall back to CSV
            pytest.skip("openpyxl not installed")


class TestHTMLReporter:
    """Test HTML report generation."""

    @pytest.fixture
    def reporter(self):
        """Create an HTML reporter instance."""
        from src.reporters.html_reporter import HTMLReporter
        return HTMLReporter()

    def test_generate_compliance_report(self, reporter, temp_dir: Path):
        """Test generating HTML compliance report."""
        result = ScanResult(
            source="test.txt",
            source_type="document",
            scan_id="test-123"
        )

        finding = Finding(
            id="html-finding-1",
            source="test.txt",
            location="line 1",
            pii_type="SSN",
            content="123-45-6789",
            context="SSN: 123-45-6789",
            confidence=0.95,
            severity=Severity.CRITICAL,
            recommendation="Hash SSN",
            gdpr_articles=["Art. 9"]
        )

        result.add_finding(finding)
        result.complete()

        compliance_data = {
            "compliance_score": 75.0,
            "status": "at-risk",
            "total_violations": 1,
            "violations": [],
            "recommendations": ["Encrypt special category data"],
            "violations_by_article": {}
        }

        output_path = temp_dir / "report.html"

        reporter.generate_compliance_report(result, str(output_path), compliance_data)

        assert output_path.exists()

        with open(output_path, "r") as f:
            content = f.read()
            assert "Privacy Compliance Report" in content or "compliance" in content.lower()
            assert "75" in content or "75.0" in content
