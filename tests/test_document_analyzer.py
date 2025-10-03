"""Tests for document analyzer."""

import pytest
import asyncio
from pathlib import Path
from src.analyzers.document_analyzer import DocumentAnalyzer
from src.models import ScanResult


class TestDocumentAnalyzer:
    """Test document analysis functionality."""

    @pytest.fixture
    def analyzer(self):
        """Create a document analyzer instance."""
        return DocumentAnalyzer(use_llm=False)

    def test_validate_source_valid(self, analyzer: DocumentAnalyzer, sample_text_file: Path):
        """Test source validation with valid file."""
        assert analyzer.validate_source(str(sample_text_file))

    def test_validate_source_invalid(self, analyzer: DocumentAnalyzer):
        """Test source validation with invalid file."""
        assert not analyzer.validate_source("/nonexistent/file.txt")

    @pytest.mark.asyncio
    async def test_analyze_text_file(self, analyzer: DocumentAnalyzer, sample_text_file: Path):
        """Test analyzing a text file."""
        result = await analyzer.analyze(str(sample_text_file))

        assert isinstance(result, ScanResult)
        assert result.status == "completed"
        assert result.source_type == "document"
        assert result.total_findings > 0

    @pytest.mark.asyncio
    async def test_analyze_empty_file(self, analyzer: DocumentAnalyzer, temp_dir: Path):
        """Test analyzing an empty file."""
        empty_file = temp_dir / "empty.txt"
        empty_file.write_text("")

        result = await analyzer.analyze(str(empty_file))

        assert isinstance(result, ScanResult)
        assert result.status == "completed"
        assert result.total_findings == 0

    @pytest.mark.asyncio
    async def test_analyze_no_pii(self, analyzer: DocumentAnalyzer, temp_dir: Path, sample_text_no_pii: str):
        """Test analyzing file with no PII."""
        clean_file = temp_dir / "clean.txt"
        clean_file.write_text(sample_text_no_pii)

        result = await analyzer.analyze(str(clean_file))

        assert isinstance(result, ScanResult)
        assert result.status == "completed"
        assert result.total_findings == 0

    def test_scan_result_structure(self, analyzer: DocumentAnalyzer):
        """Test that scan results have proper structure."""
        result = analyzer._create_scan_result("test.txt", "document")

        assert hasattr(result, "source")
        assert hasattr(result, "source_type")
        assert hasattr(result, "scan_id")
        assert hasattr(result, "findings")
        assert hasattr(result, "status")
        assert result.status == "in_progress"

    @pytest.mark.asyncio
    async def test_findings_metadata(self, analyzer: DocumentAnalyzer, sample_text_file: Path):
        """Test that findings contain proper metadata."""
        result = await analyzer.analyze(str(sample_text_file))

        if result.total_findings > 0:
            finding = result.findings[0]

            assert hasattr(finding, "id")
            assert hasattr(finding, "pii_type")
            assert hasattr(finding, "confidence")
            assert hasattr(finding, "severity")
            assert hasattr(finding, "location")
            assert hasattr(finding, "gdpr_articles")
            assert hasattr(finding, "recommendation")

    @pytest.mark.asyncio
    async def test_statistics_calculation(self, analyzer: DocumentAnalyzer, sample_text_file: Path):
        """Test that statistics are properly calculated."""
        result = await analyzer.analyze(str(sample_text_file))

        assert hasattr(result, "findings_by_severity")
        assert hasattr(result, "findings_by_type")
        assert isinstance(result.findings_by_severity, dict)
        assert isinstance(result.findings_by_type, dict)
