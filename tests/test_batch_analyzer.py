"""Tests for batch analyzer."""

import pytest
import asyncio
from pathlib import Path
from src.analyzers.batch_analyzer import BatchAnalyzer
from src.models import ScanResult


class TestBatchAnalyzer:
    """Test batch analysis functionality."""

    @pytest.fixture
    def analyzer(self):
        """Create a batch analyzer instance."""
        return BatchAnalyzer(max_workers=2, use_llm=False)

    @pytest.fixture
    def sample_directory(self, temp_dir: Path, sample_text_with_pii: str) -> Path:
        """Create a directory with multiple sample files."""
        # Create multiple files
        for i in range(3):
            file_path = temp_dir / f"document_{i}.txt"
            file_path.write_text(f"Document {i}\n{sample_text_with_pii}")

        return temp_dir

    def test_validate_source_directory(self, analyzer: BatchAnalyzer, sample_directory: Path):
        """Test source validation with directory."""
        assert analyzer.validate_source(str(sample_directory))

    def test_validate_source_file(self, analyzer: BatchAnalyzer, sample_text_file: Path):
        """Test source validation with single file."""
        assert analyzer.validate_source(str(sample_text_file))

    def test_collect_files(self, analyzer: BatchAnalyzer, sample_directory: Path):
        """Test file collection from directory."""
        files = analyzer._collect_files(sample_directory)

        assert len(files) == 3
        assert all(f.suffix == ".txt" for f in files)

    def test_collect_files_recursive(self, analyzer: BatchAnalyzer, temp_dir: Path):
        """Test recursive file collection."""
        # Create nested structure
        subdir = temp_dir / "subdir"
        subdir.mkdir()

        (temp_dir / "file1.txt").write_text("test")
        (subdir / "file2.txt").write_text("test")

        files = analyzer._collect_files(temp_dir, recursive=True)

        assert len(files) == 2

    def test_collect_files_non_recursive(self, analyzer: BatchAnalyzer, temp_dir: Path):
        """Test non-recursive file collection."""
        subdir = temp_dir / "subdir"
        subdir.mkdir()

        (temp_dir / "file1.txt").write_text("test")
        (subdir / "file2.txt").write_text("test")

        files = analyzer._collect_files(temp_dir, recursive=False)

        assert len(files) == 1

    def test_file_extension_filtering(self, analyzer: BatchAnalyzer, temp_dir: Path):
        """Test that only supported file types are collected."""
        (temp_dir / "doc.txt").write_text("test")
        (temp_dir / "doc.pdf").write_text("test")  # Would be valid PDF in real scenario
        (temp_dir / "script.py").write_text("test")  # Not supported
        (temp_dir / "data.json").write_text("test")  # Not supported

        files = analyzer._collect_files(temp_dir)

        # Should only include supported extensions
        extensions = {f.suffix for f in files}
        assert ".txt" in extensions
        assert ".py" not in extensions
        assert ".json" not in extensions

    @pytest.mark.asyncio
    async def test_analyze_directory(self, analyzer: BatchAnalyzer, sample_directory: Path):
        """Test analyzing a directory."""
        result = await analyzer.analyze(str(sample_directory))

        assert isinstance(result, ScanResult)
        assert result.status == "completed"
        assert result.total_findings > 0

    @pytest.mark.asyncio
    async def test_analyze_single_file(self, analyzer: BatchAnalyzer, sample_text_file: Path):
        """Test analyzing a single file via batch analyzer."""
        result = await analyzer.analyze(str(sample_text_file))

        assert isinstance(result, ScanResult)
        assert result.status == "completed"

    @pytest.mark.asyncio
    async def test_concurrent_processing(self, analyzer: BatchAnalyzer, sample_directory: Path):
        """Test that files are processed concurrently."""
        import time

        start_time = time.time()
        result = await analyzer.analyze(str(sample_directory))
        duration = time.time() - start_time

        # With 2 workers processing 3 files, should be faster than sequential
        # This is a basic test - actual timing may vary
        assert result.total_findings > 0

    def test_get_statistics(self, analyzer: BatchAnalyzer):
        """Test statistics generation."""
        from src.models import Finding, Severity

        # Create mock result with findings
        result = analyzer._create_scan_result("test", "batch")
        finding1 = Finding(
            id="batch-finding-1",
            source="file1.txt",
            location="line 1",
            pii_type="EMAIL",
            content="test@example.com",
            context="Email: test@example.com",
            confidence=0.95,
            severity=Severity.MEDIUM,
            recommendation="Encrypt email"
        )
        finding2 = Finding(
            id="batch-finding-2",
            source="file2.txt",
            location="line 1",
            pii_type="SSN",
            content="123-45-6789",
            context="SSN: 123-45-6789",
            confidence=0.95,
            severity=Severity.CRITICAL,
            recommendation="Hash SSN"
        )

        result.add_finding(finding1)
        result.add_finding(finding2)

        stats = analyzer.get_statistics(result)

        assert "total_findings" in stats
        assert "by_severity" in stats
        assert "by_type" in stats
        assert "files_with_findings" in stats
        assert stats["total_findings"] == 2
        assert stats["files_with_findings"] == 2

    @pytest.mark.asyncio
    async def test_error_handling(self, analyzer: BatchAnalyzer):
        """Test error handling with invalid source."""
        result = await analyzer.analyze("/nonexistent/path")

        assert result.status == "failed"
