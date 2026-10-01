"""In-memory relay broker implementation."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


class RelayBroker:
    """Simple topic-based broker for relaying messages to subscribers."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callable[[Any], None]]] = {}

    def subscribe(self, topic: str, handler: Callable[[Any], None]) -> None:
        """Register a handler for a topic."""
        if not callable(handler):
            msg = "handler must be callable"
            raise TypeError(msg)

        handlers = self._subscribers.setdefault(topic, [])
        if handler not in handlers:
            handlers.append(handler)

    def unsubscribe(self, topic: str, handler: Callable[[Any], None]) -> bool:
        """Unregister a handler from a topic."""
        handlers = self._subscribers.get(topic)
        if not handlers or handler not in handlers:
            return False

        handlers.remove(handler)
        if not handlers:
            self._subscribers.pop(topic, None)
        return True

    def publish(self, topic: str, payload: Any) -> int:
        """Relay payload to every subscriber of a topic."""
        handlers = list(self._subscribers.get(topic, []))
        for handler in handlers:
            handler(payload)
        return len(handlers)

    def relay(self, topic: str, payload: Any) -> int:
        """Alias for publish to match relay terminology."""
        return self.publish(topic, payload)
