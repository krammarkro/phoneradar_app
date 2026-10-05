# Source Generated with Decompyle++
# File: keysync.pyc (Python 3.11)

from __future__ import annotations
CURRENT_KEY_SYNC_EVENT_CODE = 600
KEY_SYNC_EVENT_CODES = frozenset({
    CURRENT_KEY_SYNC_EVENT_CODE})

def is_key_sync_event_code(value = None):
    
    try:
        return int(value) in KEY_SYNC_EVENT_CODES
    except (TypeError, ValueError):
        return False


