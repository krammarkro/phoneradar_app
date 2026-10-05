"""Public package interface for the ass_radar event and relay helpers.

The project exposes a small set of runtime primitives for radar event handling,
Photon packet parsing, and downstream relay integration.
"""

from __future__ import annotations

from ass_radar.events import RadarEvent, RadarEventBus, RuntimeSource, Subscription

__all__ = [
    "__version__",
    "RadarEvent",
    "RadarEventBus",
    "RuntimeSource",
    "Subscription",
]

__version__: str = "0.3.3"
