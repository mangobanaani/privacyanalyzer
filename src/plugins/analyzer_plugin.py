"""Analyzer plugin interface."""

from abc import abstractmethod
from typing import List

from src.plugins.base import Plugin
from src.models import ScanResult


class AnalyzerPlugin(Plugin):
    """Plugin for custom analyzers."""

    @abstractmethod
    async def analyze(self, source: str) -> ScanResult:
        """
        Analyze a source for PII.

        Args:
            source: Source to analyze

        Returns:
            Scan result
        """
        pass

    @abstractmethod
    def supports_source_type(self, source_type: str) -> bool:
        """
        Check if this analyzer supports the source type.

        Args:
            source_type: Type of source (document, database, web, etc.)

        Returns:
            True if supported
        """
        pass

    @abstractmethod
    def get_supported_extensions(self) -> List[str]:
        """
        Get list of supported file extensions.

        Returns:
            List of extensions (e.g., ['.csv', '.json'])
        """
        pass
