"""Detector plugin interface."""

from abc import abstractmethod
from typing import List

from src.plugins.base import Plugin
from src.models import Finding


class DetectorPlugin(Plugin):
    """Plugin for custom PII detectors."""

    @abstractmethod
    def detect(self, text: str, source: str = "") -> List[Finding]:
        """
        Detect PII in text.

        Args:
            text: Text to analyze
            source: Source identifier

        Returns:
            List of findings
        """
        pass

    @abstractmethod
    def get_supported_pii_types(self) -> List[str]:
        """
        Get list of PII types this detector can find.

        Returns:
            List of PII type names
        """
        pass

    @abstractmethod
    def get_detector_priority(self) -> int:
        """
        Get detector priority (higher = runs first).

        Returns:
            Priority value
        """
        pass
