"""Tests for dependency injection container."""

import pytest
from src.core.container import Container, get_container, reset_container


class TestContainer:
    """Test dependency injection container."""

    @pytest.fixture
    def container(self):
        """Create a fresh container for each test."""
        container = Container()
        yield container
        container.clear()

    def test_register_singleton_instance(self, container: Container):
        """Test registering a singleton instance."""
        instance = {"value": 42}
        container.register_singleton("test_service", instance)

        resolved = container.resolve("test_service")

        assert resolved is instance
        assert resolved["value"] == 42

    def test_singleton_returns_same_instance(self, container: Container):
        """Test that singleton returns the same instance."""
        instance = {"value": 42}
        container.register_singleton("test_service", instance)

        first = container.resolve("test_service")
        second = container.resolve("test_service")

        assert first is second

    def test_register_factory(self, container: Container):
        """Test registering a factory function."""
        counter = {"count": 0}

        def factory():
            counter["count"] += 1
            return {"instance": counter["count"]}

        container.register_factory("test_service", factory)

        first = container.resolve("test_service")
        second = container.resolve("test_service")

        # Factory should only be called once (singleton)
        assert first is second
        assert first["instance"] == 1

    def test_register_transient(self, container: Container):
        """Test registering a transient dependency."""
        counter = {"count": 0}

        def factory():
            counter["count"] += 1
            return {"instance": counter["count"]}

        container.register_transient("test_service", factory)

        first = container.resolve("test_service")
        second = container.resolve("test_service")

        # Transient should create new instances
        assert first is not second
        assert first["instance"] == 1
        assert second["instance"] == 2

    def test_register_type_singleton(self, container: Container):
        """Test registering a type as singleton."""
        class TestService:
            def __init__(self, value):
                self.value = value

        container.register_type("TestService", TestService, 42, singleton=True)

        first = container.resolve("TestService")
        second = container.resolve("TestService")

        assert isinstance(first, TestService)
        assert first is second
        assert first.value == 42

    def test_register_type_transient(self, container: Container):
        """Test registering a type as transient."""
        class TestService:
            def __init__(self, value):
                self.value = value

        container.register_type("TestService", TestService, 42, singleton=False)

        first = container.resolve("TestService")
        second = container.resolve("TestService")

        assert isinstance(first, TestService)
        assert first is not second
        assert first.value == 42
        assert second.value == 42

    def test_resolve_not_registered(self, container: Container):
        """Test resolving non-registered dependency raises error."""
        with pytest.raises(KeyError):
            container.resolve("non_existent")

    def test_resolve_type(self, container: Container):
        """Test resolving by type."""
        class TestService:
            def __init__(self):
                self.value = 42

        container.register_type("TestService", TestService)

        resolved = container.resolve_type(TestService)

        assert isinstance(resolved, TestService)
        assert resolved.value == 42

    def test_has_dependency(self, container: Container):
        """Test checking if dependency exists."""
        container.register_singleton("test", {"value": 42})

        assert container.has("test")
        assert not container.has("non_existent")

    def test_clear(self, container: Container):
        """Test clearing container."""
        container.register_singleton("test1", {"value": 1})
        container.register_singleton("test2", {"value": 2})

        assert container.has("test1")
        assert container.has("test2")

        container.clear()

        assert not container.has("test1")
        assert not container.has("test2")

    def test_register_with_kwargs(self, container: Container):
        """Test registering type with keyword arguments."""
        class TestService:
            def __init__(self, name, value=10):
                self.name = name
                self.value = value

        container.register_type("TestService", TestService, "test", value=20)

        resolved = container.resolve("TestService")

        assert resolved.name == "test"
        assert resolved.value == 20


class TestGlobalContainer:
    """Test global container functions."""

    def setup_method(self):
        """Reset container before each test."""
        reset_container()

    def teardown_method(self):
        """Reset container after each test."""
        reset_container()

    def test_get_container_singleton(self):
        """Test that get_container returns singleton."""
        first = get_container()
        second = get_container()

        assert first is second

    def test_get_container_has_defaults(self):
        """Test that global container has default dependencies."""
        container = get_container()

        # Should have default dependencies registered
        assert container.has("Settings")
        assert container.has("PIIDetector")
        assert container.has("GDPREngine")

    def test_reset_container(self):
        """Test resetting global container."""
        first = get_container()
        first.register_singleton("test", {"value": 42})

        reset_container()

        second = get_container()

        # Should be a new instance
        assert not second.has("test")

    def test_default_dependencies_resolution(self):
        """Test resolving default dependencies."""
        container = get_container()

        settings = container.resolve("Settings")
        detector = container.resolve("PIIDetector")
        gdpr = container.resolve("GDPREngine")

        assert settings is not None
        assert detector is not None
        assert gdpr is not None
