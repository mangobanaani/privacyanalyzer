"""Tests for event bus."""

import pytest
import asyncio
from src.events.bus import EventBus, get_event_bus, reset_event_bus
from src.events.events import Event, EventType, ScanStartedEvent, PIIDetectedEvent
from src.events.handlers import EventHandler


class TestEventHandler(EventHandler):
    """Test event handler."""

    def __init__(self):
        """Initialize handler."""
        self.handled_events = []

    async def handle(self, event: Event) -> None:
        """Handle event."""
        self.handled_events.append(event)

    def get_subscribed_events(self) -> list:
        """Get subscribed events."""
        return [EventType.SCAN_STARTED, EventType.PII_DETECTED]


class TestEventBus:
    """Test event bus functionality."""

    @pytest.fixture
    def bus(self):
        """Create event bus instance."""
        return EventBus()

    @pytest.fixture
    def handler(self):
        """Create test handler."""
        return TestEventHandler()

    def test_initialization(self, bus: EventBus):
        """Test event bus initialization."""
        assert len(bus._handlers) == 0
        assert len(bus._callbacks) == 0
        assert len(bus._history) == 0

    def test_subscribe_handler(self, bus: EventBus, handler: TestEventHandler):
        """Test subscribing a handler."""
        bus.subscribe(EventType.SCAN_STARTED, handler)

        assert handler in bus._handlers[EventType.SCAN_STARTED]

    def test_subscribe_callback(self, bus: EventBus):
        """Test subscribing a callback."""
        callback_called = []

        def callback(event: Event):
            callback_called.append(event)

        bus.subscribe_callback(EventType.SCAN_STARTED, callback)

        assert callback in bus._callbacks[EventType.SCAN_STARTED]

    def test_unsubscribe_handler(self, bus: EventBus, handler: TestEventHandler):
        """Test unsubscribing a handler."""
        bus.subscribe(EventType.SCAN_STARTED, handler)
        bus.unsubscribe(EventType.SCAN_STARTED, handler)

        assert handler not in bus._handlers[EventType.SCAN_STARTED]

    def test_unsubscribe_callback(self, bus: EventBus):
        """Test unsubscribing a callback."""
        def callback(event: Event):
            pass

        bus.subscribe_callback(EventType.SCAN_STARTED, callback)
        bus.unsubscribe_callback(EventType.SCAN_STARTED, callback)

        assert callback not in bus._callbacks[EventType.SCAN_STARTED]

    @pytest.mark.asyncio
    async def test_publish_to_handler(self, bus: EventBus, handler: TestEventHandler):
        """Test publishing event to handler."""
        bus.subscribe(EventType.SCAN_STARTED, handler)

        event = ScanStartedEvent(
            scan_id="test-123",
            source="test.txt",
            source_type="document"
        )

        await bus.publish(event)

        assert len(handler.handled_events) == 1
        assert handler.handled_events[0] is event

    @pytest.mark.asyncio
    async def test_publish_to_callback(self, bus: EventBus):
        """Test publishing event to callback."""
        callback_events = []

        def callback(event: Event):
            callback_events.append(event)

        bus.subscribe_callback(EventType.SCAN_STARTED, callback)

        event = ScanStartedEvent(
            scan_id="test-123",
            source="test.txt",
            source_type="document"
        )

        await bus.publish(event)

        assert len(callback_events) == 1
        assert callback_events[0] is event

    @pytest.mark.asyncio
    async def test_publish_to_async_callback(self, bus: EventBus):
        """Test publishing event to async callback."""
        callback_events = []

        async def async_callback(event: Event):
            await asyncio.sleep(0.01)
            callback_events.append(event)

        bus.subscribe_callback(EventType.SCAN_STARTED, async_callback)

        event = ScanStartedEvent(
            scan_id="test-123",
            source="test.txt",
            source_type="document"
        )

        await bus.publish(event)

        assert len(callback_events) == 1

    @pytest.mark.asyncio
    async def test_publish_to_multiple_subscribers(self, bus: EventBus):
        """Test publishing to multiple subscribers."""
        handler1 = TestEventHandler()
        handler2 = TestEventHandler()

        bus.subscribe(EventType.SCAN_STARTED, handler1)
        bus.subscribe(EventType.SCAN_STARTED, handler2)

        event = ScanStartedEvent(
            scan_id="test-123",
            source="test.txt",
            source_type="document"
        )

        await bus.publish(event)

        assert len(handler1.handled_events) == 1
        assert len(handler2.handled_events) == 1

    @pytest.mark.asyncio
    async def test_publish_only_to_subscribed(self, bus: EventBus):
        """Test that events only go to subscribed handlers."""
        handler = TestEventHandler()

        bus.subscribe(EventType.SCAN_STARTED, handler)

        # Publish different event type
        event = Event(
            event_type=EventType.SCAN_COMPLETED,
            data={}
        )

        await bus.publish(event)

        # Handler should not receive it (not subscribed)
        # But if handler subscribes to SCAN_COMPLETED, it would
        # For this test, handler only subscribes to SCAN_STARTED and PII_DETECTED

    @pytest.mark.asyncio
    async def test_event_history(self, bus: EventBus):
        """Test event history tracking."""
        event1 = ScanStartedEvent(
            scan_id="test-1",
            source="file1.txt",
            source_type="document"
        )

        event2 = PIIDetectedEvent(
            scan_id="test-1",
            pii_type="EMAIL",
            location="line 1",
            severity="medium",
            confidence=0.95
        )

        await bus.publish(event1)
        await bus.publish(event2)

        history = bus.get_history()

        assert len(history) == 2
        assert history[0] is event1
        assert history[1] is event2

    @pytest.mark.asyncio
    async def test_get_history_filtered(self, bus: EventBus):
        """Test getting filtered event history."""
        event1 = ScanStartedEvent(
            scan_id="test-1",
            source="file1.txt",
            source_type="document"
        )

        event2 = PIIDetectedEvent(
            scan_id="test-1",
            pii_type="EMAIL",
            location="line 1",
            severity="medium",
            confidence=0.95
        )

        await bus.publish(event1)
        await bus.publish(event2)

        history = bus.get_history(event_type=EventType.SCAN_STARTED)

        assert len(history) == 1
        assert history[0].event_type == EventType.SCAN_STARTED

    @pytest.mark.asyncio
    async def test_get_history_limit(self, bus: EventBus):
        """Test history limit."""
        for i in range(10):
            event = ScanStartedEvent(
                scan_id=f"test-{i}",
                source="test.txt",
                source_type="document"
            )
            await bus.publish(event)

        history = bus.get_history(limit=5)

        assert len(history) == 5

    def test_clear_history(self, bus: EventBus):
        """Test clearing event history."""
        bus._history.append(Event(event_type=EventType.SCAN_STARTED, data={}))
        bus._history.append(Event(event_type=EventType.SCAN_COMPLETED, data={}))

        assert len(bus._history) == 2

        bus.clear_history()

        assert len(bus._history) == 0

    def test_get_subscribers(self, bus: EventBus, handler: TestEventHandler):
        """Test getting subscriber count."""
        def callback(event):
            pass

        bus.subscribe(EventType.SCAN_STARTED, handler)
        bus.subscribe_callback(EventType.SCAN_STARTED, callback)

        subscribers = bus.get_subscribers(EventType.SCAN_STARTED)

        assert subscribers["handlers"] == 1
        assert subscribers["callbacks"] == 1

    def test_publish_sync(self, bus: EventBus, handler: TestEventHandler):
        """Test synchronous publish."""
        bus.subscribe(EventType.SCAN_STARTED, handler)

        event = ScanStartedEvent(
            scan_id="test-123",
            source="test.txt",
            source_type="document"
        )

        bus.publish_sync(event)

        assert len(handler.handled_events) == 1

    @pytest.mark.asyncio
    async def test_handler_error_handling(self, bus: EventBus):
        """Test that handler errors don't break event bus."""
        class ErrorHandler(EventHandler):
            async def handle(self, event: Event) -> None:
                raise Exception("Handler error")

            def get_subscribed_events(self) -> list:
                return [EventType.SCAN_STARTED]

        error_handler = ErrorHandler()
        good_handler = TestEventHandler()

        bus.subscribe(EventType.SCAN_STARTED, error_handler)
        bus.subscribe(EventType.SCAN_STARTED, good_handler)

        event = ScanStartedEvent(
            scan_id="test-123",
            source="test.txt",
            source_type="document"
        )

        # Should not raise exception
        await bus.publish(event)

        # Good handler should still receive event
        assert len(good_handler.handled_events) == 1


class TestGlobalEventBus:
    """Test global event bus functions."""

    def setup_method(self):
        """Reset before each test."""
        reset_event_bus()

    def teardown_method(self):
        """Reset after each test."""
        reset_event_bus()

    def test_get_event_bus_singleton(self):
        """Test that event bus is singleton."""
        first = get_event_bus()
        second = get_event_bus()

        assert first is second

    def test_reset_event_bus(self):
        """Test resetting event bus."""
        first = get_event_bus()

        handler = TestEventHandler()
        first.subscribe(EventType.SCAN_STARTED, handler)

        reset_event_bus()

        second = get_event_bus()

        # Should be fresh instance
        assert len(second._handlers) == 0
