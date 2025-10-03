"""Base plugin interface and metadata."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Any, Optional
from pydantic import BaseModel


class PluginType(str, Enum):
    """Plugin types."""

    ANALYZER = "analyzer"
    DETECTOR = "detector"
    REPORTER = "reporter"
    PROCESSOR = "processor"


class PluginMetadata(BaseModel):
    """Plugin metadata."""

    name: str
    version: str
    description: str
    author: str
    plugin_type: PluginType
    enabled: bool = True
    config: Dict[str, Any] = {}


class Plugin(ABC):
    """Base plugin interface."""

    def __init__(self, metadata: PluginMetadata):
        """
        Initialize plugin.

        Args:
            metadata: Plugin metadata
        """
        self.metadata = metadata
        self._initialized = False

    @abstractmethod
    def initialize(self) -> None:
        """Initialize the plugin. Called when plugin is loaded."""
        pass

    @abstractmethod
    def cleanup(self) -> None:
        """Cleanup resources. Called when plugin is unloaded."""
        pass

    @abstractmethod
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate plugin configuration.

        Args:
            config: Configuration dictionary

        Returns:
            True if valid
        """
        pass

    def is_initialized(self) -> bool:
        """
        Check if plugin is initialized.

        Returns:
            True if initialized
        """
        return self._initialized

    def get_info(self) -> Dict[str, Any]:
        """
        Get plugin information.

        Returns:
            Plugin info dictionary
        """
        return {
            "name": self.metadata.name,
            "version": self.metadata.version,
            "description": self.metadata.description,
            "author": self.metadata.author,
            "type": self.metadata.plugin_type,
            "enabled": self.metadata.enabled,
            "initialized": self._initialized,
        }
