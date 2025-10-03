"""Plugin manager for loading and managing plugins."""

import importlib
import sys
from pathlib import Path
from typing import Dict, List, Optional, Type
from src.plugins.base import Plugin, PluginType, PluginMetadata
from src.plugins.analyzer_plugin import AnalyzerPlugin
from src.plugins.detector_plugin import DetectorPlugin
from src.utils import get_logger

logger = get_logger(__name__)


class PluginManager:
    """Manages plugin lifecycle and discovery."""

    def __init__(self, plugin_dir: Optional[str] = None):
        """
        Initialize plugin manager.

        Args:
            plugin_dir: Directory to search for plugins
        """
        self.plugin_dir = Path(plugin_dir) if plugin_dir else Path("plugins")
        self.plugins: Dict[str, Plugin] = {}
        self._plugin_types: Dict[PluginType, List[str]] = {
            PluginType.ANALYZER: [],
            PluginType.DETECTOR: [],
            PluginType.REPORTER: [],
            PluginType.PROCESSOR: [],
        }

    def discover_plugins(self) -> int:
        """
        Discover plugins in plugin directory.

        Returns:
            Number of plugins discovered
        """
        if not self.plugin_dir.exists():
            logger.warning(f"Plugin directory not found: {self.plugin_dir}")
            return 0

        count = 0

        # Add plugin directory to Python path
        if str(self.plugin_dir) not in sys.path:
            sys.path.insert(0, str(self.plugin_dir))

        # Scan for Python modules
        for plugin_file in self.plugin_dir.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue

            try:
                module_name = plugin_file.stem
                module = importlib.import_module(module_name)

                # Look for plugin classes
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)

                    # Check if it's a plugin class (not the base class)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, Plugin)
                        and attr not in [Plugin, AnalyzerPlugin, DetectorPlugin]
                    ):
                        self.load_plugin_class(attr)
                        count += 1

            except Exception as e:
                logger.error(f"Failed to load plugin from {plugin_file}: {e}")

        logger.info(f"Discovered {count} plugins")
        return count

    def load_plugin_class(self, plugin_class: Type[Plugin]) -> str:
        """
        Load a plugin class.

        Args:
            plugin_class: Plugin class to instantiate

        Returns:
            Plugin name

        Raises:
            ValueError: If plugin invalid
        """
        # Get plugin metadata (should be defined as class attribute)
        if not hasattr(plugin_class, "METADATA"):
            raise ValueError(f"Plugin {plugin_class.__name__} missing METADATA attribute")

        metadata_dict = plugin_class.METADATA
        metadata = PluginMetadata(**metadata_dict)

        # Instantiate plugin
        plugin = plugin_class(metadata)

        # Initialize
        try:
            plugin.initialize()
            plugin._initialized = True
        except Exception as e:
            logger.error(f"Failed to initialize plugin {metadata.name}: {e}")
            raise

        # Register plugin
        self.plugins[metadata.name] = plugin
        self._plugin_types[metadata.plugin_type].append(metadata.name)

        logger.info(f"Loaded plugin: {metadata.name} v{metadata.version}")
        return metadata.name

    def register_plugin(self, plugin: Plugin) -> None:
        """
        Register a plugin instance.

        Args:
            plugin: Plugin instance
        """
        if not plugin.is_initialized():
            plugin.initialize()
            plugin._initialized = True

        self.plugins[plugin.metadata.name] = plugin
        self._plugin_types[plugin.metadata.plugin_type].append(plugin.metadata.name)

        logger.info(f"Registered plugin: {plugin.metadata.name}")

    def get_plugin(self, name: str) -> Optional[Plugin]:
        """
        Get plugin by name.

        Args:
            name: Plugin name

        Returns:
            Plugin instance or None
        """
        return self.plugins.get(name)

    def get_plugins_by_type(self, plugin_type: PluginType) -> List[Plugin]:
        """
        Get all plugins of a specific type.

        Args:
            plugin_type: Type of plugins to retrieve

        Returns:
            List of plugins
        """
        plugin_names = self._plugin_types.get(plugin_type, [])
        return [self.plugins[name] for name in plugin_names if name in self.plugins]

    def get_analyzer_plugins(self) -> List[AnalyzerPlugin]:
        """
        Get all analyzer plugins.

        Returns:
            List of analyzer plugins
        """
        return self.get_plugins_by_type(PluginType.ANALYZER)

    def get_detector_plugins(self) -> List[DetectorPlugin]:
        """
        Get all detector plugins.

        Returns:
            List of detector plugins
        """
        return self.get_plugins_by_type(PluginType.DETECTOR)

    def enable_plugin(self, name: str) -> bool:
        """
        Enable a plugin.

        Args:
            name: Plugin name

        Returns:
            True if successful
        """
        plugin = self.get_plugin(name)
        if plugin:
            plugin.metadata.enabled = True
            logger.info(f"Enabled plugin: {name}")
            return True
        return False

    def disable_plugin(self, name: str) -> bool:
        """
        Disable a plugin.

        Args:
            name: Plugin name

        Returns:
            True if successful
        """
        plugin = self.get_plugin(name)
        if plugin:
            plugin.metadata.enabled = False
            logger.info(f"Disabled plugin: {name}")
            return True
        return False

    def unload_plugin(self, name: str) -> bool:
        """
        Unload and cleanup a plugin.

        Args:
            name: Plugin name

        Returns:
            True if successful
        """
        plugin = self.get_plugin(name)
        if not plugin:
            return False

        try:
            plugin.cleanup()
            plugin._initialized = False

            # Remove from registry
            del self.plugins[name]
            self._plugin_types[plugin.metadata.plugin_type].remove(name)

            logger.info(f"Unloaded plugin: {name}")
            return True

        except Exception as e:
            logger.error(f"Failed to unload plugin {name}: {e}")
            return False

    def unload_all(self) -> None:
        """Unload all plugins."""
        for name in list(self.plugins.keys()):
            self.unload_plugin(name)

    def list_plugins(self) -> List[Dict[str, any]]:
        """
        List all plugins and their info.

        Returns:
            List of plugin info dictionaries
        """
        return [plugin.get_info() for plugin in self.plugins.values()]


# Global plugin manager instance
_plugin_manager: Optional[PluginManager] = None


def get_plugin_manager(plugin_dir: Optional[str] = None) -> PluginManager:
    """
    Get global plugin manager instance.

    Args:
        plugin_dir: Plugin directory (only used on first call)

    Returns:
        PluginManager instance
    """
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager(plugin_dir)
    return _plugin_manager


def reset_plugin_manager() -> None:
    """Reset the global plugin manager (useful for testing)."""
    global _plugin_manager
    if _plugin_manager:
        _plugin_manager.unload_all()
    _plugin_manager = None
