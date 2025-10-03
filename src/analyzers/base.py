"""Base analyzer interface."""

from abc import ABC, abstractmethod
from typing import Any, List
from src.models import Finding, ScanResult


class AnalyzerBase(ABC):
    """Base class for all analyzers."""

    def __init__(self, config: Any = None):
        """Initialize analyzer with optional configuration."""
        self.config = config

    @abstractmethod
    def validate_source(self, source: Any) -> bool:
        """
        Validate that the source is accessible and valid.

        Args:
            source: The source to validate (file path, URL, connection string, etc.)

        Returns:
            True if source is valid and accessible, False otherwise
        """
        pass

    @abstractmethod
    async def analyze(self, source: Any) -> ScanResult:
        """
        Analyze the source for PII and privacy issues.

        Args:
            source: The source to analyze

        Returns:
            ScanResult containing all findings

        Raises:
            ValueError: If source is invalid
            Exception: For other analysis errors
        """
        pass

    def _create_scan_result(self, source: str, source_type: str) -> ScanResult:
        """
        Create a new scan result object.

        Args:
            source: Source identifier
            source_type: Type of source being scanned

        Returns:
            Initialized ScanResult
        """
        import uuid

        return ScanResult(
            scan_id=str(uuid.uuid4()), source=source, source_type=source_type, findings=[]
        )
