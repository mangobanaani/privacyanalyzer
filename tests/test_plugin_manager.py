"""Tests for plugin manager."""

import pytest
from pathlib import Path
from src.plugins.manager import PluginManager, reset_plugin_manager
from src.plugins.base import Plugin, PluginMetadata, PluginType
from src.plugins.analyzer_plugin import AnalyzerPlugin
from src.plugins.detector_plugin import DetectorPlugin
from src.models import ScanResult, Finding


class TestPlugin(Plugin):
    """Test plugin implementation."""

    METADATA = {
        "name": "test_plugin",
        "version": "1.0.0",
        "description": "Test plugin",
        "author": "Test Author",
        "plugin_type": PluginType.ANALYZER,
    }

    def __init__(self, metadata: PluginMetadata):
        """Initialize test plugin."""
        super().__init__(metadata)
        self.initialized = False
        self.cleaned_up = False

    def initialize(self) -> None:
        """Initialize plugin."""
        self.initialized = True

    def cleanup(self) -> None:
        """Cleanup plugin."""
        self.cleaned_up = True

    def validate_config(self, config: dict) -> bool:
        """Validate config."""
        return True


class TestAnalyzerPlugin(AnalyzerPlugin):
    """Test analyzer plugin."""

    METADATA = {
        "name": "test_analyzer",
        "version": "1.0.0",
        "description": "Test analyzer",
        "author": "Test",
        "plugin_type": PluginType.ANALYZER,
    }

    def __init__(self, metadata: PluginMetadata):
        """Initialize."""
        super().__init__(metadata)

    def initialize(self) -> None:
        """Initialize."""
        pass

    def cleanup(self) -> None:
        """Cleanup."""
        pass

    def validate_config(self, config: dict) -> bool:
        """Validate."""
        return True

    async def analyze(self, source: str) -> ScanResult:
        """Analyze."""
        result = ScanResult(source=source, source_type="test", scan_id="test")
        result.complete()
        return result

    def supports_source_type(self, source_type: str) -> bool:
        """Check support."""
        return source_type == "test"

    def get_supported_extensions(self) -> list:
        """Get extensions."""
        return [".test"]


class TestPluginManager:
    """Test plugin manager functionality."""

    @pytest.fixture
    def temp_plugin_dir(self, temp_dir):
        """Create temporary plugin directory."""
        plugin_dir = temp_dir / "plugins"
        plugin_dir.mkdir()
        return plugin_dir

    @pytest.fixture
    def manager(self, temp_plugin_dir):
        """Create plugin manager instance."""
        return PluginManager(str(temp_plugin_dir))

    def test_initialization(self, temp_plugin_dir, manager: PluginManager):
        """Test plugin manager initialization."""
        assert manager.plugin_dir == temp_plugin_dir
        assert len(manager.plugins) == 0

    def test_register_plugin(self, manager: PluginManager):
        """Test registering a plugin."""
        metadata = PluginMetadata(
            name="test",
            version="1.0.0",
            description="Test",
            author="Author",
            plugin_type=PluginType.ANALYZER
        )

        plugin = TestPlugin(metadata)
        manager.register_plugin(plugin)

        assert "test" in manager.plugins
        assert plugin.is_initialized()

    def test_get_plugin(self, manager: PluginManager):
        """Test getting a plugin by name."""
        metadata = PluginMetadata(
            name="test",
            version="1.0.0",
            description="Test",
            author="Author",
            plugin_type=PluginType.ANALYZER
        )

        plugin = TestPlugin(metadata)
        manager.register_plugin(plugin)

        retrieved = manager.get_plugin("test")

        assert retrieved is plugin

    def test_get_plugin_not_found(self, manager: PluginManager):
        """Test getting non-existent plugin."""
        assert manager.get_plugin("non_existent") is None

    def test_get_plugins_by_type(self, manager: PluginManager):
        """Test getting plugins by type."""
        # Register analyzer plugin
        analyzer_metadata = PluginMetadata(
            name="analyzer",
            version="1.0.0",
            description="Analyzer",
            author="Author",
            plugin_type=PluginType.ANALYZER
        )
        analyzer = TestPlugin(analyzer_metadata)
        manager.register_plugin(analyzer)

        # Register detector plugin
        detector_metadata = PluginMetadata(
            name="detector",
            version="1.0.0",
            description="Detector",
            author="Author",
            plugin_type=PluginType.DETECTOR
        )
        detector = TestPlugin(detector_metadata)
        manager.register_plugin(detector)

        analyzers = manager.get_plugins_by_type(PluginType.ANALYZER)
        detectors = manager.get_plugins_by_type(PluginType.DETECTOR)

        assert len(analyzers) == 1
        assert len(detectors) == 1
        assert analyzers[0].metadata.name == "analyzer"

    def test_get_analyzer_plugins(self, manager: PluginManager):
        """Test getting analyzer plugins."""
        metadata = PluginMetadata(
            name="analyzer",
            version="1.0.0",
            description="Analyzer",
            author="Author",
            plugin_type=PluginType.ANALYZER
        )

        plugin = TestAnalyzerPlugin(metadata)
        manager.register_plugin(plugin)

        analyzers = manager.get_analyzer_plugins()

        assert len(analyzers) == 1
        assert isinstance(analyzers[0], AnalyzerPlugin)

    def test_enable_plugin(self, manager: PluginManager):
        """Test enabling a plugin."""
        metadata = PluginMetadata(
            name="test",
            version="1.0.0",
            description="Test",
            author="Author",
            plugin_type=PluginType.ANALYZER,
            enabled=False
        )

        plugin = TestPlugin(metadata)
        manager.register_plugin(plugin)

        assert not plugin.metadata.enabled

        manager.enable_plugin("test")

        assert plugin.metadata.enabled

    def test_disable_plugin(self, manager: PluginManager):
        """Test disabling a plugin."""
        metadata = PluginMetadata(
            name="test",
            version="1.0.0",
            description="Test",
            author="Author",
            plugin_type=PluginType.ANALYZER,
            enabled=True
        )

        plugin = TestPlugin(metadata)
        manager.register_plugin(plugin)

        assert plugin.metadata.enabled

        manager.disable_plugin("test")

        assert not plugin.metadata.enabled

    def test_unload_plugin(self, manager: PluginManager):
        """Test unloading a plugin."""
        metadata = PluginMetadata(
            name="test",
            version="1.0.0",
            description="Test",
            author="Author",
            plugin_type=PluginType.ANALYZER
        )

        plugin = TestPlugin(metadata)
        manager.register_plugin(plugin)

        assert "test" in manager.plugins
        assert plugin.is_initialized()

        success = manager.unload_plugin("test")

        assert success
        assert "test" not in manager.plugins
        assert plugin.cleaned_up

    def test_unload_all(self, manager: PluginManager):
        """Test unloading all plugins."""
        # Register multiple plugins
        for i in range(3):
            metadata = PluginMetadata(
                name=f"test{i}",
                version="1.0.0",
                description=f"Test {i}",
                author="Author",
                plugin_type=PluginType.ANALYZER
            )
            plugin = TestPlugin(metadata)
            manager.register_plugin(plugin)

        assert len(manager.plugins) == 3

        manager.unload_all()

        assert len(manager.plugins) == 0

    def test_list_plugins(self, manager: PluginManager):
        """Test listing plugins."""
        metadata = PluginMetadata(
            name="test",
            version="1.0.0",
            description="Test Plugin",
            author="Test Author",
            plugin_type=PluginType.ANALYZER
        )

        plugin = TestPlugin(metadata)
        manager.register_plugin(plugin)

        plugin_list = manager.list_plugins()

        assert len(plugin_list) == 1
        assert plugin_list[0]["name"] == "test"
        assert plugin_list[0]["version"] == "1.0.0"
        assert plugin_list[0]["initialized"] is True

    def test_load_plugin_class(self, manager: PluginManager):
        """Test loading a plugin class."""
        name = manager.load_plugin_class(TestPlugin)

        assert name == "test_plugin"
        assert "test_plugin" in manager.plugins
        assert manager.plugins["test_plugin"].is_initialized()

    def test_load_plugin_class_no_metadata(self, manager: PluginManager):
        """Test loading plugin without metadata fails."""
        class BadPlugin(Plugin):
            def initialize(self):
                pass

            def cleanup(self):
                pass

            def validate_config(self, config):
                return True

        with pytest.raises(ValueError):
            manager.load_plugin_class(BadPlugin)


class TestGlobalPluginManager:
    """Test global plugin manager functions."""

    def setup_method(self):
        """Reset before each test."""
        reset_plugin_manager()

    def teardown_method(self):
        """Reset after each test."""
        reset_plugin_manager()

    def test_get_plugin_manager_singleton(self):
        """Test that plugin manager is singleton."""
        from src.plugins.manager import get_plugin_manager

        first = get_plugin_manager()
        second = get_plugin_manager()

        assert first is second

    def test_reset_plugin_manager(self):
        """Test resetting plugin manager."""
        from src.plugins.manager import get_plugin_manager

        first = get_plugin_manager()

        metadata = PluginMetadata(
            name="test",
            version="1.0.0",
            description="Test",
            author="Author",
            plugin_type=PluginType.ANALYZER
        )
        plugin = TestPlugin(metadata)
        first.register_plugin(plugin)

        reset_plugin_manager()

        second = get_plugin_manager()

        assert len(second.plugins) == 0
