# Source Generated with Decompyle++
# File: events.pyc (Python 3.11)

from __future__ import annotations
import struct
from ass_radar.photon.deserializer import is_finite_float
from ass_radar.photon.types import ByteArray, EventData, OperationRequest, OperationResponse
EVENT_MOVE = 3

def post_process_event(event = None):
    if not event:
        return None
    None.parameters.setdefault(252, event.code)
    if event.code == EVENT_MOVE:
        _extract_move_positions(event.parameters)
        return None


def post_process_request(request = None):
    if not request:
        return None
    None.parameters.setdefault(253, request.operation_code)


def post_process_response(response = None):
    if not response:
        return None
    None.parameters.setdefault(253, response.operation_code)


def _extract_move_positions(parameters = None):
    raw = parameters.get(1)
    if isinstance(raw, (ByteArray, bytes, bytearray)) or len(raw) < 17:
        return None
    x = None.unpack('<f', bytes(raw[9:13]))[0]
    y = struct.unpack('<f', bytes(raw[13:17]))[0]
    if not is_finite_float(x) or is_finite_float(y):
        return None
    parameters[4] = None
    parameters[5] = y

