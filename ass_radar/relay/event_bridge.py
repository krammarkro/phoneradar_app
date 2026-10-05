from __future__ import annotations

import json
import struct
from typing import Any

from ass_radar.photon.deserializer import deserialize_event_live, to_jsonable
from ass_radar.photon.types import ByteArray, EventData
from ass_radar.player_positions import is_plausible_player_position
from ass_radar.product_events import DIAGNOSTIC_ONLY_ROUTES, EVENT_MOVE, EVENT_NEW_CHARACTER, RouteResolution, resolve_event_route

XOR_POSITION_LENGTH = 8
MOVE_POSITION_OFFSET = 9
NEW_CHARACTER_POSITION_PARAMETER = 16


class DecryptedRadarEventBridge:
    def __init__(self) -> None:
        self._xor_code: bytes | None = None
        self._diagnostics: list[dict[str, Any]] = []

    def drain_diagnostics(self) -> list[dict[str, Any]]:
        diagnostics = list(self._diagnostics)
        self._diagnostics.clear()
        return diagnostics

    def handle_decrypted_payload(self, payload: bytes, *, outer_message_type: int, direction: str) -> list[dict[str, Any]]:
        exported: list[dict[str, Any]] = []
        for shape, event in _iter_event_candidates(payload):
            resolution = resolve_event_route(kind="event", observed_code=event.code, parameters=event.parameters)
            if not resolution:
                continue
            exported.extend(self._handle_event(event, resolution=resolution, outer_message_type=outer_message_type, direction=direction, shape=shape))
        return exported

    def handle_plain_event(self, event: EventData, *, outer_message_type: int, direction: str, resolution: RouteResolution | None = None) -> list[dict[str, Any]]:
        if resolution is None:
            resolution = resolve_event_route(kind="event", observed_code=event.code, parameters=event.parameters)
        if not resolution:
            return []
        return self._handle_event(event, resolution=resolution, outer_message_type=outer_message_type, direction=direction, shape="plain_event")

    def _handle_event(self, event: EventData, *, resolution: RouteResolution, outer_message_type: int, direction: str, shape: str) -> list[dict[str, Any]]:
        routed_code = resolution.routed.code
        if resolution.routed in DIAGNOSTIC_ONLY_ROUTES:
            xor_code = _raw_bytes(event.parameters.get(0))
            if len(xor_code) != XOR_POSITION_LENGTH:
                self._xor_code = None
                self._emit("key_sync_invalid", routed_code=routed_code, outer_message_type=outer_message_type, direction=direction, shape=shape, xor_code=xor_code)
                return []
            self._xor_code = xor_code
            self._emit("key_sync_updated", routed_code=routed_code, outer_message_type=outer_message_type, direction=direction, shape=shape, xor_code=xor_code)
            return []
        if routed_code == EVENT_NEW_CHARACTER:
            spawn_position = self._decode_spawn_position(event, outer_message_type=outer_message_type, direction=direction, shape=shape)
            position_source = "relay_xor" if spawn_position else "relay_decrypted"
            return [
                _radar_event_payload(
                    event=event,
                    routed_code=routed_code,
                    parameters=to_jsonable(_with_routed_code(event.parameters, routed_code)),
                    position_source=position_source,
                    outer_message_type=outer_message_type,
                    direction=direction,
                    shape=shape,
                    spawn_position=spawn_position,
                )
            ]
        if routed_code != EVENT_MOVE:
            return []
        decoded = self._decode_move_position(event, outer_message_type=outer_message_type, direction=direction, shape=shape)
        if not decoded:
            return []
        self._emit(
            "move_decoded",
            routed_code=routed_code,
            outer_message_type=outer_message_type,
            direction=direction,
            shape=shape,
            position_source="relay_xor",
            entity_id_present=_int_or_none(event.parameters.get(0)) is not None,
        )
        return [
            _radar_event_payload(
                event=event,
                routed_code=routed_code,
                parameters={
                    "0": _int_or_none(event.parameters.get(0)),
                    "4": decoded[0],
                    "5": decoded[1],
                    "252": EVENT_MOVE,
                },
                position_source="relay_xor",
                outer_message_type=outer_message_type,
                direction=direction,
                shape=shape,
            )
        ]

    def _decode_spawn_position(self, event: EventData, *, outer_message_type: int, direction: str, shape: str) -> tuple[float, float] | None:
        entity_id_present = _int_or_none(event.parameters.get(0)) is not None
        encrypted_position = _strict_spawn_position_bytes(event.parameters.get(NEW_CHARACTER_POSITION_PARAMETER))
        if not encrypted_position:
            self._emit(
                "spawn_position_invalid",
                routed_code=EVENT_NEW_CHARACTER,
                outer_message_type=outer_message_type,
                direction=direction,
                shape=shape,
                position_source="relay_decrypted",
                entity_id_present=entity_id_present,
            )
            return None
        if not self._xor_code:
            self._emit(
                "spawn_position_missing_key",
                routed_code=EVENT_NEW_CHARACTER,
                outer_message_type=outer_message_type,
                direction=direction,
                shape=shape,
                position_source="relay_decrypted",
                entity_id_present=entity_id_present,
            )
            return None
        decoded = _decode_xor_position(encrypted_position=encrypted_position, xor_code=self._xor_code)
        if not decoded:
            self._emit(
                "spawn_position_implausible",
                routed_code=EVENT_NEW_CHARACTER,
                outer_message_type=outer_message_type,
                direction=direction,
                shape=shape,
                position_source="relay_decrypted",
                entity_id_present=entity_id_present,
            )
            return None
        self._emit(
            "spawn_position_decoded",
            routed_code=EVENT_NEW_CHARACTER,
            outer_message_type=outer_message_type,
            direction=direction,
            shape=shape,
            position_source="relay_xor",
            entity_id_present=entity_id_present,
        )
        return decoded

    def _decode_move_position(self, event: EventData, *, outer_message_type: int, direction: str, shape: str) -> tuple[float, float] | None:
        if not self._xor_code:
            self._emit(
                "move_missing_key",
                routed_code=EVENT_MOVE,
                outer_message_type=outer_message_type,
                direction=direction,
                shape=shape,
                entity_id_present=_int_or_none(event.parameters.get(0)) is not None,
            )
            return None
        raw = _raw_bytes(event.parameters.get(1))
        end = MOVE_POSITION_OFFSET + XOR_POSITION_LENGTH
        if len(raw) < end:
            self._emit(
                "move_payload_too_short",
                routed_code=EVENT_MOVE,
                outer_message_type=outer_message_type,
                direction=direction,
                shape=shape,
                entity_id_present=_int_or_none(event.parameters.get(0)) is not None,
                byte_array_length=len(raw),
            )
            return None
        encrypted = raw[MOVE_POSITION_OFFSET:end]
        decoded = _decode_xor_position(encrypted_position=encrypted, xor_code=self._xor_code)
        if not decoded:
            self._emit(
                "move_implausible_position",
                routed_code=EVENT_MOVE,
                outer_message_type=outer_message_type,
                direction=direction,
                shape=shape,
                entity_id_present=_int_or_none(event.parameters.get(0)) is not None,
                byte_array_length=len(raw),
            )
            return None
        return decoded

    def _emit(
        self,
        status: str,
        *,
        routed_code: int,
        outer_message_type: int,
        direction: str,
        shape: str,
        position_source: str | None = None,
        entity_id_present: bool | None = None,
        xor_code: bytes | None = None,
        byte_array_length: int | None = None,
    ) -> None:
        item: dict[str, Any] = {
            "eventType": "radar_bridge",
            "status": str(status),
            "direction": str(direction),
            "outerMessageType": int(outer_message_type),
            "shape": str(shape),
            "routedCode": int(routed_code),
        }
        if position_source is not None:
            item["positionSource"] = position_source
        if entity_id_present is not None:
            item["entityIdPresent"] = bool(entity_id_present)
        if byte_array_length is not None:
            item["byteArrayLength"] = int(byte_array_length)
        if xor_code is not None:
            item["xorCodeLength"] = len(xor_code)
        self._diagnostics.append(item)


def build_radar_event_export_payload(event: dict[str, Any]) -> bytes:
    return (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _iter_event_candidates(payload: bytes) -> list[tuple[str, EventData]]:
    candidates: list[tuple[str, EventData]] = []
    direct = _deserialize_event_or_none(payload)
    if direct:
        candidates.append(("direct_event", direct))
    if payload and payload[0] == 4:
        inner = _deserialize_event_or_none(payload[1:])
        if inner:
            candidates.append(("inner_event", inner))
    return candidates


def _deserialize_event_or_none(payload: bytes) -> EventData | None:
    try:
        return deserialize_event_live(payload)
    except Exception:
        return None


def _radar_event_payload(
    *,
    event: EventData,
    routed_code: int,
    parameters: dict[str, Any],
    position_source: str,
    outer_message_type: int,
    direction: str,
    shape: str,
    spawn_position: tuple[float, float] | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "decrypted": True,
        "direction": str(direction),
        "outer_message_type": int(outer_message_type),
        "position_source": position_source,
        "routed_code": int(routed_code),
        "shape": shape,
    }
    if spawn_position is not None:
        x, y = spawn_position
        metadata["spawn_position"] = {"x": float(x), "y": float(y)}
    return {
        "type": "radar_event",
        "kind": "event",
        "code": int(event.code),
        "parameters": parameters,
        "source": "relay",
        "metadata": metadata,
    }


def _with_routed_code(parameters: dict[int, Any], routed_code: int) -> dict[int, Any]:
    copied = dict(parameters)
    copied[252] = int(routed_code)
    return copied


def _raw_bytes(value: Any) -> bytes:
    if isinstance(value, (ByteArray, bytes, bytearray)):
        return bytes(value)
    if isinstance(value, dict) and value.get("type") == "Buffer" and isinstance(value.get("data"), list):
        try:
            return bytes(int(item) & 255 for item in value["data"])
        except (TypeError, ValueError):
            return b""
    return b""


def _strict_spawn_position_bytes(value: Any) -> bytes | None:
    if isinstance(value, (ByteArray, bytes, bytearray)):
        raw = bytes(value)
    elif isinstance(value, dict) and set(value) == {"type", "data"} and value.get("type") == "Buffer" and isinstance(value.get("data"), list):
        data = value["data"]
        if any(isinstance(item, bool) or not isinstance(item, int) or not (0 <= item <= 255) for item in data):
            return None
        raw = bytes(data)
    else:
        return None
    return raw if len(raw) == XOR_POSITION_LENGTH else None


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _decode_xor_position(*, encrypted_position: bytes, xor_code: bytes) -> tuple[float, float] | None:
    if len(encrypted_position) != XOR_POSITION_LENGTH or len(xor_code) != XOR_POSITION_LENGTH:
        return None
    decoded = bytes(encrypted ^ key for encrypted, key in zip(encrypted_position, xor_code, strict=True))
    x, y = struct.unpack("<ff", decoded)
    if not is_plausible_player_position(x, y):
        return None
    return (float(x), float(y))
