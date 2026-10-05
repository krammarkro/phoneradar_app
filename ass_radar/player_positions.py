"""Utility checks for validating player position data from relay sources.

These helpers intentionally keep the validation logic compact and deterministic so
other modules can use them as a quick trust and plausibility gate before
accepting position updates.
"""

from __future__ import annotations
import math

MAX_ABSOLUTE_PLAYER_POSITION = 100000.0
TRUSTED_PLAYER_POSITION_SOURCES = frozenset({'local_relay_xor', 'local_relay_decrypted', 'vps_relay_xor', 'vps_relay_decrypted'})
TRUSTED_PLAYER_SPAWN_POSITION_SOURCES = frozenset({'vps_relay_xor', 'local_relay_xor'})


def is_trusted_player_position_source(value: object) -> bool:
    """Return True when the source is considered trusted for live player positions."""
    return isinstance(value, str) and value in TRUSTED_PLAYER_POSITION_SOURCES


def is_trusted_player_spawn_position_source(value: object) -> bool:
    """Return True when the source is considered trusted for spawn positions."""
    return isinstance(value, str) and value in TRUSTED_PLAYER_SPAWN_POSITION_SOURCES


def is_plausible_player_position(x: object, y: object) -> bool:
    """Check whether a coordinate pair falls within a sane map-space range."""
    if isinstance(x, bool) or isinstance(y, bool):
        return False
    if not isinstance(x, int | float) or not isinstance(y, int | float):
        return False
    try:
        x_value = float(x)
        y_value = float(y)
    except (OverflowError, TypeError, ValueError):
        return False
    # Reject non-finite values and coordinates beyond the known map bounds.
    return math.isfinite(x_value) and math.isfinite(y_value) and abs(x_value) <= MAX_ABSOLUTE_PLAYER_POSITION and abs(y_value) <= MAX_ABSOLUTE_PLAYER_POSITION
