"""Event handler interface."""

from abc import ABC, abstractmethod
from typing import List

from src.events.events import Event, EventType


class EventHandler(ABC):
    """Base event handler interface."""

    @abstractmethod
    async def handle(self, event: Event) -> None:
        """
        Handle an event.

        Args:
            event: Event to handle
        """
        pass

    @abstractmethod
    def get_subscribed_events(self) -> List[EventType]:
        """
        Get list of event types this handler subscribes to.

        Returns:
            List of event types
        """
        pass

    def can_handle(self, event: Event) -> bool:
        """
        Check if this handler can handle the event.

        Args:
            event: Event to check

        Returns:
            True if can handle
        """
        return event.event_type in self.get_subscribed_events()
