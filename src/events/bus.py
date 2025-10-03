"""Event bus for publishing and subscribing to events."""

import asyncio
from typing import Dict, List, Callable, Optional, Set
from collections import defaultdict

from src.events.events import Event, EventType
from src.events.handlers import EventHandler
from src.utils import get_logger

logger = get_logger(__name__)


class EventBus:
    """Event bus for pub/sub pattern."""

    def __init__(self):
        """Initialize event bus."""
        self._handlers: Dict[EventType, List[EventHandler]] = defaultdict(list)
        self._callbacks: Dict[EventType, List[Callable]] = defaultdict(list)
        self._history: List[Event] = []
        self._max_history = 1000

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """
        Subscribe a handler to an event type.

        Args:
            event_type: Event type to subscribe to
            handler: Event handler
        """
        if handler not in self._handlers[event_type]:
            self._handlers[event_type].append(handler)
            logger.debug(f"Subscribed {handler.__class__.__name__} to {event_type}")

    def subscribe_callback(self, event_type: EventType, callback: Callable[[Event], None]) -> None:
        """
        Subscribe a callback function to an event type.

        Args:
            event_type: Event type to subscribe to
            callback: Callback function
        """
        if callback not in self._callbacks[event_type]:
            self._callbacks[event_type].append(callback)
            logger.debug(f"Subscribed callback to {event_type}")

    def unsubscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """
        Unsubscribe a handler from an event type.

        Args:
            event_type: Event type
            handler: Handler to remove
        """
        if handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)
            logger.debug(f"Unsubscribed {handler.__class__.__name__} from {event_type}")

    def unsubscribe_callback(self, event_type: EventType, callback: Callable) -> None:
        """
        Unsubscribe a callback from an event type.

        Args:
            event_type: Event type
            callback: Callback to remove
        """
        if callback in self._callbacks[event_type]:
            self._callbacks[event_type].remove(callback)
            logger.debug(f"Unsubscribed callback from {event_type}")

    async def publish(self, event: Event) -> None:
        """
        Publish an event to all subscribers.

        Args:
            event: Event to publish
        """
        logger.debug(f"Publishing event: {event.event_type}")

        # Add to history
        self._add_to_history(event)

        # Notify handlers
        handlers = self._handlers.get(event.event_type, [])
        for handler in handlers:
            try:
                await handler.handle(event)
            except Exception as e:
                logger.error(f"Error in event handler {handler.__class__.__name__}: {e}")

        # Notify callbacks
        callbacks = self._callbacks.get(event.event_type, [])
        for callback in callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event)
                else:
                    callback(event)
            except Exception as e:
                logger.error(f"Error in event callback: {e}")

    def publish_sync(self, event: Event) -> None:
        """
        Publish an event synchronously (creates event loop if needed).

        Args:
            event: Event to publish
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Create task in running loop
                asyncio.create_task(self.publish(event))
            else:
                # Run in current loop
                loop.run_until_complete(self.publish(event))
        except RuntimeError:
            # No event loop, create one
            asyncio.run(self.publish(event))

    def _add_to_history(self, event: Event) -> None:
        """
        Add event to history.

        Args:
            event: Event to add
        """
        self._history.append(event)

        # Trim history if too long
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

    def get_history(
        self,
        event_type: Optional[EventType] = None,
        limit: int = 100
    ) -> List[Event]:
        """
        Get event history.

        Args:
            event_type: Filter by event type (None for all)
            limit: Maximum events to return

        Returns:
            List of events
        """
        if event_type:
            events = [e for e in self._history if e.event_type == event_type]
        else:
            events = self._history

        return events[-limit:]

    def clear_history(self) -> None:
        """Clear event history."""
        self._history.clear()

    def get_subscribers(self, event_type: EventType) -> Dict[str, int]:
        """
        Get subscriber count for an event type.

        Args:
            event_type: Event type

        Returns:
            Dictionary with handler and callback counts
        """
        return {
            "handlers": len(self._handlers.get(event_type, [])),
            "callbacks": len(self._callbacks.get(event_type, [])),
        }


# Global event bus instance
_event_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """
    Get global event bus instance.

    Returns:
        EventBus instance
    """
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus


def reset_event_bus() -> None:
    """Reset the global event bus (useful for testing)."""
    global _event_bus
    _event_bus = None
