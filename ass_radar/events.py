"""Core event primitives used by the radar pipeline.

This module defines the event model and the thread-safe broker used to publish
radar events to subscriber callbacks. It is intentionally lightweight so the
rest of the package can focus on packet parsing and relay logic without
depending on a heavyweight runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from ass_radar.event_path_stats import EventPathSnapshot, EventPathStats

EventCallback = Callable[["RadarEvent"], None]


class RuntimeSource(str, Enum):
    """Normalized runtime origin for an event payload.

    The source is kept as a small enum so callers can distinguish capture,
    relay, replay, and unknown origins without relying on raw strings.
    """

    CAPTURE = "capture"
    RELAY = "relay"
    REPLAY = "replay"
    UNKNOWN = "unknown"

    @classmethod
    def normalize(cls, value: object) -> "RuntimeSource":
        """Coerce a runtime label into a safe enum value."""
        try:
            return cls(value)
        except (TypeError, ValueError):
            return cls.UNKNOWN


@dataclass(frozen=True)
class RadarEvent:
    """Structured payload emitted by the local radar pipeline.

    The dataclass is intentionally immutable so subscribers can reason about the
    event without later mutation causing race conditions.
    """

    kind: str
    code: int
    parameters: dict[int | str, Any] = field(default_factory=dict)
    source: str = "unknown"
    raw: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    runtime_source: RuntimeSource = RuntimeSource.UNKNOWN

    def __post_init__(self) -> None:
        """Normalize the runtime source regardless of caller input type."""
        object.__setattr__(self, "runtime_source", RuntimeSource.normalize(self.runtime_source))


class Subscription:
    """Handle for a callback registered on a :class:`RadarEventBus`."""

    def __init__(self, bus: "RadarEventBus", callback: EventCallback) -> None:
        self._bus = bus
        self._callback = callback
        self._active = True

    def unsubscribe(self) -> None:
        """Remove the callback from the event bus if it is still active."""
        if not self._active:
            return None
        self._bus.unsubscribe(self._callback)
        self._active = False


class RadarEventBus:
    """Thread-safe dispatcher for application-level radar events."""

    def __init__(self, *, clock_ms: Callable[[], int] | None = None) -> None:
        from ass_radar.event_path_stats import EventPathStats

        self._lock = RLock()
        self._subscribers: list[EventCallback] = []
        self._event_path_stats = EventPathStats(clock_ms=clock_ms)

    @property
    def event_path_stats(self) -> "EventPathStats":
        """Return the event-path tracker used by this bus instance."""
        return self._event_path_stats

    def event_path_snapshot(self) -> "EventPathSnapshot":
        """Capture a snapshot of event path statistics for inspection."""
        return self._event_path_stats.snapshot()

    def reset_event_path_source(self, source: RuntimeSource | str) -> int:
        """Reset the event-path source and return the resulting revision."""
        return self._event_path_stats.reset_source(source)

    def subscribe(self, callback: EventCallback) -> Subscription:
        """Register a callback and return a subscription handle."""
        with self._lock:
            self._subscribers.append(callback)
        return Subscription(self, callback)

    def unsubscribe(self, callback: EventCallback) -> None:
        """Remove a callback from the bus without affecting other subscribers."""
        with self._lock:
            self._subscribers = [item for item in self._subscribers if item is not callback]

    def publish(self, event: RadarEvent) -> None:
        """Publish one event to all subscribed callbacks."""
        self._event_path_stats.record_published(event)
        with self._lock:
            subscribers = list(self._subscribers)
        for callback in subscribers:
            callback(event)
