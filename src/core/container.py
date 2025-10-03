"""Dependency injection container."""

from typing import Dict, Any, Callable, Optional, TypeVar, Type
from functools import lru_cache

T = TypeVar("T")


class Container:
    """
    Dependency injection container.

    Manages creation and lifecycle of application dependencies.
    """

    def __init__(self):
        """Initialize container."""
        self._singletons: Dict[str, Any] = {}
        self._factories: Dict[str, Callable] = {}
        self._transient: Dict[str, Callable] = {}

    def register_singleton(self, name: str, instance: Any) -> None:
        """
        Register a singleton instance.

        Args:
            name: Dependency name
            instance: Instance to register
        """
        self._singletons[name] = instance

    def register_factory(self, name: str, factory: Callable[[], Any]) -> None:
        """
        Register a factory function for singleton creation.

        Args:
            name: Dependency name
            factory: Factory function that creates the instance
        """
        self._factories[name] = factory

    def register_transient(self, name: str, factory: Callable[[], Any]) -> None:
        """
        Register a transient (new instance each time) dependency.

        Args:
            name: Dependency name
            factory: Factory function
        """
        self._transient[name] = factory

    def register_type(
        self,
        name: str,
        cls: Type[T],
        *args,
        singleton: bool = True,
        **kwargs
    ) -> None:
        """
        Register a type with constructor arguments.

        Args:
            name: Dependency name
            cls: Class to instantiate
            *args: Constructor arguments
            singleton: Whether to create as singleton (default) or transient
            **kwargs: Constructor keyword arguments
        """
        factory = lambda: cls(*args, **kwargs)

        if singleton:
            self.register_factory(name, factory)
        else:
            self.register_transient(name, factory)

    def resolve(self, name: str) -> Any:
        """
        Resolve a dependency by name.

        Args:
            name: Dependency name

        Returns:
            Resolved instance

        Raises:
            KeyError: If dependency not registered
        """
        # Check singletons first
        if name in self._singletons:
            return self._singletons[name]

        # Create from factory (singleton)
        if name in self._factories:
            instance = self._factories[name]()
            self._singletons[name] = instance
            return instance

        # Create from transient factory
        if name in self._transient:
            return self._transient[name]()

        raise KeyError(f"Dependency '{name}' not registered")

    def resolve_type(self, cls: Type[T]) -> T:
        """
        Resolve a dependency by type.

        Args:
            cls: Class type to resolve

        Returns:
            Instance of the type
        """
        name = cls.__name__
        return self.resolve(name)

    def has(self, name: str) -> bool:
        """
        Check if dependency is registered.

        Args:
            name: Dependency name

        Returns:
            True if registered
        """
        return (
            name in self._singletons
            or name in self._factories
            or name in self._transient
        )

    def clear(self) -> None:
        """Clear all dependencies."""
        self._singletons.clear()
        self._factories.clear()
        self._transient.clear()


# Global container instance
_container: Optional[Container] = None


def get_container() -> Container:
    """
    Get global container instance.

    Returns:
        Container instance
    """
    global _container
    if _container is None:
        _container = Container()
        _setup_default_dependencies(_container)
    return _container


def _setup_default_dependencies(container: Container) -> None:
    """
    Setup default dependencies.

    Args:
        container: Container to configure
    """
    from src.detectors.pii_detector import PIIDetector
    from src.detectors.gdpr_engine import GDPREngine
    from src.anonymizers import AnonymizationEngine
    from src.utils import AuditLogger
    from src.models import Settings

    # Register core dependencies
    container.register_type("Settings", Settings)
    container.register_type("PIIDetector", PIIDetector)
    container.register_type("GDPREngine", GDPREngine)
    container.register_type("AnonymizationEngine", AnonymizationEngine)
    container.register_type("AuditLogger", AuditLogger, "audit.log", False)


def reset_container() -> None:
    """Reset the global container (useful for testing)."""
    global _container
    if _container:
        _container.clear()
    _container = None
