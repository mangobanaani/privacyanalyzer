"""Batch analyzer for scanning multiple files and folders."""

import asyncio
from pathlib import Path
from typing import List, Optional, Dict
import uuid

from src.analyzers.base import AnalyzerBase
from src.analyzers.document_analyzer import DocumentAnalyzer
from src.models import ScanResult, Finding
from src.utils import get_logger

logger = get_logger(__name__)


class BatchAnalyzer(AnalyzerBase):
    """Analyze multiple documents in batch."""

    SUPPORTED_EXTENSIONS = {
        ".pdf",
        ".docx",
        ".doc",
        ".txt",
        ".text",
        ".png",
        ".jpg",
        ".jpeg",
        ".tiff",
        ".bmp",
        ".xlsx",
        ".xls",
        ".eml",
        ".msg",
    }

    def __init__(self, config=None, max_workers: int = 4, use_llm: bool = False):
        """
        Initialize batch analyzer.

        Args:
            config: Optional configuration
            max_workers: Maximum concurrent file processing
            use_llm: Enable LLM-powered analysis
        """
        super().__init__(config)
        self.max_workers = max_workers
        # Convert string to boolean if needed (for CLI compatibility)
        if isinstance(use_llm, str):
            use_llm = use_llm.lower() in ('true', '1', 'yes')
        self.use_llm = use_llm
        self.document_analyzer = DocumentAnalyzer(config, use_llm=use_llm)

    def validate_source(self, source) -> bool:
        """
        Validate that the source is a valid file or directory.

        Args:
            source: Path to file or directory

        Returns:
            True if valid
        """
        try:
            path = Path(source)
            return path.exists() and (path.is_file() or path.is_dir())
        except Exception as e:
            logger.error(f"Source validation failed: {e}")
            return False

    async def analyze(self, source) -> ScanResult:
        """
        Analyze a file or directory (recursively).

        Args:
            source: Path to file or directory

        Returns:
            Aggregated ScanResult
        """
        path = Path(source)
        scan_result = self._create_scan_result(str(path), "batch")

        if not self.validate_source(source):
            scan_result.fail(f"Invalid source: {source}")
            return scan_result

        try:
            # Collect files to scan
            if path.is_file():
                files = [path]
            else:
                files = self._collect_files(path)

            logger.info(f"Found {len(files)} files to scan")

            if not files:
                scan_result.complete()
                return scan_result

            # Process files in batches with concurrency limit
            results = await self._process_files_concurrent(files)

            # Aggregate results
            for file_result in results:
                if file_result.status == "completed":
                    for finding in file_result.findings:
                        scan_result.add_finding(finding)

            scan_result.complete()
            logger.info(
                f"Batch scan complete: {len(files)} files, {scan_result.total_findings} findings"
            )

        except Exception as e:
            logger.error(f"Batch analysis failed: {e}")
            scan_result.fail(str(e))
            raise

        return scan_result

    def _collect_files(self, directory: Path, recursive: bool = True) -> List[Path]:
        """
        Collect all supported files from directory.

        Args:
            directory: Directory to scan
            recursive: Whether to scan subdirectories

        Returns:
            List of file paths
        """
        files = []

        if recursive:
            pattern = "**/*"
        else:
            pattern = "*"

        for file_path in directory.glob(pattern):
            if file_path.is_file() and file_path.suffix.lower() in self.SUPPORTED_EXTENSIONS:
                files.append(file_path)

        return sorted(files)

    async def _process_files_concurrent(self, files: List[Path]) -> List[ScanResult]:
        """
        Process files with concurrency control.

        Args:
            files: List of files to process

        Returns:
            List of ScanResults
        """
        semaphore = asyncio.Semaphore(self.max_workers)

        async def process_with_semaphore(file_path: Path) -> ScanResult:
            async with semaphore:
                return await self._process_single_file(file_path)

        tasks = [process_with_semaphore(f) for f in files]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and log them
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Failed to process {files[i]}: {result}")
            else:
                valid_results.append(result)

        return valid_results

    async def _process_single_file(self, file_path: Path) -> ScanResult:
        """
        Process a single file.

        Args:
            file_path: Path to file

        Returns:
            ScanResult for this file
        """
        try:
            logger.info(f"Processing: {file_path.name}")
            result = await self.document_analyzer.analyze(str(file_path))
            return result

        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
            # Return empty result with error
            error_result = self._create_scan_result(str(file_path), "document")
            error_result.fail(str(e))
            return error_result

    def get_statistics(self, scan_result: ScanResult) -> Dict:
        """
        Get detailed statistics from batch scan.

        Args:
            scan_result: Completed scan result

        Returns:
            Statistics dictionary
        """
        stats = {
            "total_findings": scan_result.total_findings,
            "by_severity": scan_result.findings_by_severity,
            "by_type": scan_result.findings_by_type,
            "duration_seconds": scan_result.duration_seconds,
        }

        # Group by source file
        files_with_findings = {}
        for finding in scan_result.findings:
            source = finding.source
            if source not in files_with_findings:
                files_with_findings[source] = 0
            files_with_findings[source] += 1

        stats["files_with_findings"] = len(files_with_findings)
        stats["findings_per_file"] = files_with_findings

        return stats
