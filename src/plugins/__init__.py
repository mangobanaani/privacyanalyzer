"""Plugin system for extensible analyzers and detectors."""

from .base import Plugin, PluginMetadata, PluginType
from .manager import PluginManager, get_plugin_manager
from .analyzer_plugin import AnalyzerPlugin
from .detector_plugin import DetectorPlugin

__all__ = [
    "Plugin",
    "PluginMetadata",
    "PluginType",
    "PluginManager",
    "get_plugin_manager",
    "AnalyzerPlugin",
    "DetectorPlugin",
]
