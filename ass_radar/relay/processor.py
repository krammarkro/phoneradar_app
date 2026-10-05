"""Photon relay processing and decrypted payload extraction.

This module takes decrypted protocol payloads, reconstructs event streams, and
forwards normalized radar events to application-level consumers. The processing
flow is intentionally split between transport-level rewriting and event-level
extraction so it can accommodate fragment reassembly and diagnostics.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
import threading
from typing import Any

from ass_radar.photon.split_dh import SplitDhSession
from ass_radar.product_events import DIAGNOSTIC_ONLY_ROUTES, EVENT_MOVE, resolve_event_route
from ass_radar.relay.event_bridge import DecryptedRadarEventBridge
from ass_radar.photon.deserializer import deserialize_event_live, deserialize_request_live, deserialize_response_live, to_jsonable
from ass_radar.photon.events import post_process_event, post_process_request, post_process_response
from ass_radar.photon.packet import PhotonParser
from ass_radar.photon.types import EventData, OperationRequest, OperationResponse

RelayEventCallback = Callable[[dict[str, Any]], None]
RelayDiagnosticCallback = Callable[[dict[str, Any]], None]
RelayFragmentReservationCallback = Callable[[str, int], bool]
RelayFragmentLifecycleCallback = Callable[[str, dict[str, Any]], None]

_SUPPORTED_DIRECTIONS = frozenset({"client_to_upstream", "upstream_to_client"})
_FRAGMENT_LIFECYCLE_FIELDS = ("kind", "commandChannelId", "startSequence", "fragmentCount", "totalLength", "reservedBytes", "receivedFragments", "receivedBytes", "status", "reason")


class RelayPhotonTransportDesync(RuntimeError):
    """Raised when an active rewritten Photon transport can no longer be translated safely."""


class RelayPhotonCryptoTransport:
    """Translate encrypted relay payloads into decrypted application messages."""

    def __init__(self, *, on_decrypted_payload: Callable[[bytes, int, str], None], on_diagnostic: RelayDiagnosticCallback | None = None, strict_transport: bool = False) -> None:
        self._on_decrypted_payload = on_decrypted_payload
        self._on_diagnostic = on_diagnostic
        self._strict_transport = bool(strict_transport)
        self._transport_was_rewritten = False
        self._condition = threading.Condition(threading.RLock())
        self._operation_lock = threading.Lock()
        self._active_operations = 0
        self._finalizing = False
        self._finalized = False
        self._finalize_result = None
        self._pending_callbacks = deque()
        self._draining_callbacks = False
        self._split_dh = SplitDhSession(on_decrypted_payload=self._queue_decrypted_payload)

    @property
    def transport_was_rewritten(self) -> bool:
        return self._transport_was_rewritten

    def process_packets(self, *, direction: str, payload: bytes) -> list[bytes]:
        if not self._begin_operation():
            return []
        with self._operation_lock:
            try:
                result = self._split_dh.process_packet(direction=direction, payload=payload)
                output_payloads = list(result.output_payloads)
                output_payload_length = sum(len(item) for item in output_payloads)
                for event in result.events:
                    self._publish_diagnostic(event, rewritten=result.rewritten, output_payload_length=output_payload_length)
                if result.rewritten:
                    self._transport_was_rewritten = True
                if self._strict_transport and result.transport_stream_lost:
                    raise RelayPhotonTransportDesync("delayed fragment transport packets were retired before completion")
                if self._strict_transport and self._transport_was_rewritten and any(_is_missing_translation_keys(event) for event in result.events):
                    raise RelayPhotonTransportDesync("encrypted payload cannot be translated after active transport rewrite")
                return output_payloads
            finally:
                self._end_operation()

    def finalize(self) -> bool:
        with self._condition:
            if self._finalize_result is not None:
                return bool(self._finalize_result)
            if self._finalizing:
                self._condition.wait_for(lambda: self._finalize_result is not None)
                return bool(self._finalize_result)
            self._finalizing = True
            self._finalized = True
            self._condition.wait_for(lambda: self._active_operations == 0)
        with self._operation_lock:
            try:
                result = bool(self._split_dh.finalize())
            except Exception:
                result = False
        with self._condition:
            self._finalize_result = result
            if not result:
                self._pending_callbacks.append(("diagnostic", {"eventType": "radar_extraction", "status": "incomplete_stream"}))
            self._finalizing = False
            self._condition.notify_all()
        self._drain_callbacks()
        return result

    def _publish_diagnostic(self, event: dict[str, Any] | None, *, rewritten: bool, output_payload_length: int) -> None:
        if self._on_diagnostic is None or event is None:
            return
        diagnostic = _safe_split_dh_diagnostic(event)
        diagnostic["rewritten"] = bool(rewritten)
        diagnostic["outputPayloadLength"] = int(output_payload_length)
        self._queue_callback("diagnostic", diagnostic)

    def _queue_decrypted_payload(self, payload: bytes, outer_message_type: int, direction: str) -> None:
        self._queue_callback("decrypted", (bytes(payload), int(outer_message_type), str(direction)))

    def _queue_callback(self, kind: str, value: object) -> None:
        with self._condition:
            if kind == "decrypted" and self._finalized:
                return
            self._pending_callbacks.append((kind, value))
        self._drain_callbacks()

    def _drain_callbacks(self) -> None:
        with self._condition:
            if self._draining_callbacks or self._active_operations or self._finalizing:
                return
            self._draining_callbacks = True
        try:
            while True:
                with self._condition:
                    if not self._pending_callbacks:
                        break
                    kind, value = self._pending_callbacks.popleft()
                    if kind == "decrypted" and self._finalized:
                        continue
                # handle outside lock
                if kind == "decrypted":
                    payload, outer_message_type, direction = value  # type: ignore
                    try:
                        self._on_decrypted_payload(payload, outer_message_type, direction)
                    except Exception:
                        pass
                else:
                    if self._on_diagnostic is None:
                        continue
                    try:
                        self._on_diagnostic(value)  # type: ignore
                    except Exception:
                        pass
        finally:
            with self._condition:
                self._draining_callbacks = False
                should_continue = bool(self._pending_callbacks) and not self._active_operations and not self._finalizing
            if should_continue:
                self._drain_callbacks()

    def _begin_operation(self) -> bool:
        with self._condition:
            if self._finalized:
                return False
            self._active_operations += 1
            return True

    def _end_operation(self) -> None:
        with self._condition:
            self._active_operations -= 1
            self._condition.notify_all()
        self._drain_callbacks()


class RelayRadarExtractor:
    """Extract radar events from decrypted relay payloads and emitted diagnostics."""

    def __init__(self, *, on_event: RelayEventCallback, on_diagnostic: RelayDiagnosticCallback | None = None, publish_undecoded_move_events: bool = True, publish_bridge_diagnostics: bool = True, event_source: str = "vps_relay", can_reserve_fragment: RelayFragmentReservationCallback | None = None, on_fragment_lifecycle: RelayFragmentLifecycleCallback | None = None) -> None:
        self._on_event = on_event
        self._on_diagnostic = on_diagnostic
        self._publish_undecoded_move_events = bool(publish_undecoded_move_events)
        self._publish_bridge_diagnostics_enabled = bool(publish_bridge_diagnostics)
        self._event_source = str(event_source) if event_source else "vps_relay"
        self._can_reserve_fragment = can_reserve_fragment
        self._on_fragment_lifecycle = on_fragment_lifecycle
        self._bridge = DecryptedRadarEventBridge()
        self._plain_parsers: dict[str, PhotonParser] = {}
        self._condition = threading.Condition(threading.RLock())
        self._operation_lock = threading.Lock()
        self._active_operations = 0
        self._finalizing = False
        self._finalized = False
        self._finalize_result = None
        self._finalized_diagnostic_emitted = False
        self._pending_callbacks: deque[tuple[str, Any]] = deque()
        self._draining_callbacks = False
        self._event_callback_owner: int | None = None

    def handle_decrypted_payload(self, payload: bytes, *, outer_message_type: int, direction: str) -> None:
        if not self._begin_operation():
            return
        try:
            if not self._direction_supported(direction):
                return
            with self._operation_lock:
                events = self._bridge.handle_decrypted_payload(payload, outer_message_type=outer_message_type, direction=direction)
                if not events:
                    events = _decrypted_radar_messages(payload, outer_message_type=outer_message_type, direction=direction)
                self._publish_events(events)
        finally:
            self._end_operation()

    def observe_plain_payload(self, *, direction: str, payload: bytes) -> None:
        if not self._begin_operation():
            return
        try:
            if not self._direction_supported(direction):
                return
            with self._operation_lock:
                parser = self._plain_parsers.get(direction)
                if parser is None:
                    parser = self._new_plain_parser(direction)
                    self._plain_parsers[direction] = parser
                parser.receive_packet(payload)
        finally:
            self._end_operation()

    def finalize(self) -> bool:
        owner = threading.get_ident()
        with self._condition:
            self._condition.wait_for(lambda: self._event_callback_owner is None or self._event_callback_owner == owner)
            if self._finalize_result is not None:
                return bool(self._finalize_result)
            if self._finalizing:
                self._condition.wait_for(lambda: self._finalize_result is not None)
                return bool(self._finalize_result)
            self._finalizing = True
            self._finalized = True
            self._condition.wait_for(lambda: self._active_operations == 0)
        with self._operation_lock:
            parsers = tuple(self._plain_parsers.items())
            self._plain_parsers.clear()
            result = True
            incomplete_directions: list[str] = []
            for direction, parser in parsers:
                try:
                    parser_result = bool(parser.finalize())
                except Exception:
                    parser_result = False
                if not parser_result:
                    result = False
                    incomplete_directions.append(direction)
        with self._condition:
            self._finalize_result = result
            for direction in incomplete_directions:
                self._pending_callbacks.append(("diagnostic", {"eventType": "radar_extraction", "status": "incomplete_stream", "direction": direction}))
            self._finalizing = False
            self._condition.notify_all()
        self._drain_callbacks()
        return result

    def _new_plain_parser(self, direction: str) -> PhotonParser:
        on_frame = None
        if self._on_fragment_lifecycle is not None:
            on_frame = lambda frame, d=direction, s=self: s._observe_plain_parser_frame(d, frame)
        can_reserve_fragment = None
        if self._can_reserve_fragment is not None:
            can_reserve_fragment = lambda total_length, d=direction, s=self: s._reserve_plain_fragment(d, total_length)
        return PhotonParser(
            on_event=lambda event, d=direction, s=self: s._handle_plain_event(event, outer_message_type=4, direction=d),
            on_request=lambda request, d=direction, s=self: s._handle_plain_request(request, outer_message_type=2, direction=d),
            on_response=lambda response, d=direction, s=self: s._handle_plain_response(response, outer_message_type=3, direction=d),
            on_frame=on_frame,
            can_reserve_fragment=can_reserve_fragment,
        )

    def _reserve_plain_fragment(self, direction: str, total_length: int) -> bool:
        if self._can_reserve_fragment is None:
            return True
        return bool(self._can_reserve_fragment(direction, total_length))

    def _observe_plain_parser_frame(self, direction: str, frame: dict[str, Any]) -> None:
        if self._on_fragment_lifecycle is None:
            return
        if frame.get("kind") != "fragment_lifecycle":
            return
        lifecycle = {key: frame[key] for key in _FRAGMENT_LIFECYCLE_FIELDS if key in frame}
        self._on_fragment_lifecycle(direction, lifecycle)

    def _direction_supported(self, direction: object) -> bool:
        if isinstance(direction, str) and direction in _SUPPORTED_DIRECTIONS:
            return True
        self._publish_extraction_diagnostic("invalid_direction", direction=direction if isinstance(direction, str) else None)  # type: ignore
        return False

    def _publish_extraction_diagnostic(self, status: str, *, direction: str | None = None) -> None:
        if self._on_diagnostic is None:
            return
        diagnostic: dict[str, Any] = {"eventType": "radar_extraction", "status": status}
        if direction is not None:
            diagnostic["direction"] = direction
        self._queue_callback("diagnostic", diagnostic)

    def _begin_operation(self) -> bool:
        emit_finalized = False
        with self._condition:
            if self._finalized:
                if not self._finalized_diagnostic_emitted:
                    self._finalized_diagnostic_emitted = True
                    emit_finalized = True
                else:
                    emit_finalized = False
            else:
                self._active_operations += 1
                return True
        if emit_finalized:
            self._publish_extraction_diagnostic("processor_finalized")
            self._drain_callbacks()
        return False

    def _end_operation(self) -> None:
        with self._condition:
            self._active_operations -= 1
            self._condition.notify_all()
        self._drain_callbacks()

    def _queue_callback(self, kind: str, value: object) -> None:
        with self._condition:
            if kind == "event" and self._finalized:
                return
            self._pending_callbacks.append((kind, value))
        self._drain_callbacks()

    def _drain_callbacks(self) -> None:
        with self._condition:
            if self._draining_callbacks or self._active_operations or self._finalizing:
                return
            self._draining_callbacks = True
        try:
            while True:
                with self._condition:
                    if not self._pending_callbacks:
                        break
                    kind, value = self._pending_callbacks.popleft()
                    if kind == "event" and self._finalized:
                        continue
                    if kind == "event":
                        self._event_callback_owner = threading.get_ident()
                # release lock before invoking callbacks
                if kind == "event":
                    try:
                        self._on_event(value)  # type: ignore
                    finally:
                        with self._condition:
                            self._event_callback_owner = None
                            self._condition.notify_all()
                else:
                    if self._on_diagnostic is None:
                        continue
                    try:
                        self._on_diagnostic(value)  # type: ignore
                    except Exception:
                        pass
        finally:
            with self._condition:
                self._draining_callbacks = False
                should_continue = bool(self._pending_callbacks) and not self._active_operations and not self._finalizing
            if should_continue:
                self._drain_callbacks()

    def _handle_plain_event(self, event: EventData, *, outer_message_type: int, direction: str) -> None:
        resolution = resolve_event_route("event", observed_code=event.code, parameters=event.parameters)
        if resolution is None:
            return
        events = self._bridge.handle_plain_event(event, outer_message_type=outer_message_type, direction=direction, resolution=resolution)
        if resolution.routed in DIAGNOSTIC_ONLY_ROUTES:
            self._publish_bridge_diagnostics(self._bridge.drain_diagnostics())
            return
        if not events and resolution.routed.code == EVENT_MOVE and not self._publish_undecoded_move_events:
            self._publish_bridge_diagnostics(self._bridge.drain_diagnostics())
            return
        if not events:
            events = [_plain_radar_event(event, outer_message_type=outer_message_type, direction=direction, routed_code=resolution.routed.code)]
        self._publish_events(events)

    def _handle_plain_request(self, request: OperationRequest, *, outer_message_type: int, direction: str) -> None:
        resolution = resolve_event_route("request", observed_code=request.operation_code, parameters=request.parameters)
        if resolution is None:
            return
        self._publish_events([_plain_radar_request(request, outer_message_type=outer_message_type, direction=direction, routed_code=resolution.routed.code)])

    def _handle_plain_response(self, response: OperationResponse, *, outer_message_type: int, direction: str) -> None:
        resolution = resolve_event_route("response", observed_code=response.operation_code, parameters=response.parameters)
        if resolution is None:
            return
        self._publish_events([_plain_radar_response(response, outer_message_type=outer_message_type, direction=direction, routed_code=resolution.routed.code)])

    def _publish_events(self, events: list[dict[str, Any]]) -> None:
        self._publish_bridge_diagnostics(self._bridge.drain_diagnostics())
        for event in events:
            self._queue_callback("event", normalize_relay_radar_event(event, event_source=self._event_source))

    def _publish_bridge_diagnostics(self, events: list[dict[str, Any]]) -> None:
        if self._on_diagnostic is None or not self._publish_bridge_diagnostics_enabled:
            return
        for event in events:
            diagnostic = _safe_bridge_diagnostic(event)
            self._queue_callback("diagnostic", diagnostic)


class RelayPhotonProcessor:
    def __init__(self, *, on_event: RelayEventCallback, on_diagnostic: RelayDiagnosticCallback | None = None, strict_transport: bool = False, extractor: RelayRadarExtractor | None = None, event_source: str = "vps_relay", publish_bridge_diagnostics: bool = True) -> None:
        self._on_event = on_event
        self._on_diagnostic = on_diagnostic
        self._condition = threading.Condition(threading.RLock())
        self._operation_lock = threading.Lock()
        self._active_operations = 0
        self._finalizing = False
        self._finalized = False
        self._finalize_result = None
        self._finalized_diagnostic_emitted = False
        self._pending_callbacks: deque[tuple[str, Any]] = deque()
        self._draining_callbacks = False
        self._event_callback_owner: int | None = None
        if extractor is not None:
            self._extractor = extractor
        else:
            self._extractor = RelayRadarExtractor(on_event=self._queue_event, on_diagnostic=self._queue_diagnostic, publish_bridge_diagnostics=publish_bridge_diagnostics, event_source=event_source)
        self._transport = RelayPhotonCryptoTransport(on_decrypted_payload=self._handle_decrypted_payload, on_diagnostic=self._queue_diagnostic, strict_transport=strict_transport)

    @property
    def transport_was_rewritten(self) -> bool:
        return self._transport.transport_was_rewritten

    def process_packet(self, *, direction: str, payload: bytes) -> bytes:
        payloads = self.process_packets(direction=direction, payload=payload)
        return payloads[0] if payloads else b""

    def process_packets(self, *, direction: str, payload: bytes) -> list[bytes]:
        if not self._begin_operation():
            return []
        if not self._direction_supported(direction):
            self._end_operation()
            return []
        with self._operation_lock:
            try:
                output_payloads = self._transport.process_packets(direction=direction, payload=payload)
                for output_payload in output_payloads:
                    self._observe_plain_payload(direction=direction, payload=output_payload)
                return output_payloads
            finally:
                self._end_operation()

    def observe_packet(self, *, direction: str, payload: bytes) -> None:
        if not self._begin_operation():
            return
        with self._operation_lock:
            try:
                self._observe_plain_payload(direction=direction, payload=payload)
            finally:
                self._end_operation()

    def handle_decrypted_payload_for_test(self, payload: bytes, *, outer_message_type: int, direction: str) -> None:
        if not self._begin_operation():
            return
        with self._operation_lock:
            try:
                self._handle_decrypted_payload(payload, outer_message_type=outer_message_type, direction=direction)
            finally:
                self._end_operation()

    def finalize(self) -> bool:
        owner = threading.get_ident()
        with self._condition:
            self._condition.wait_for(lambda: self._event_callback_owner is None or self._event_callback_owner == owner)
            if self._finalize_result is not None:
                return bool(self._finalize_result)
            if self._finalizing:
                self._condition.wait_for(lambda: self._finalize_result is not None)
                return bool(self._finalize_result)
            self._finalizing = True
            self._finalized = True
            self._condition.wait_for(lambda: self._active_operations == 0)
        with self._operation_lock:
            try:
                transport_result = bool(self._transport.finalize())
            except Exception:
                transport_result = False
            try:
                extractor_result = bool(self._extractor.finalize())
            except Exception:
                extractor_result = False
            result = transport_result and extractor_result
        with self._condition:
            self._finalize_result = result
            self._finalizing = False
            self._condition.notify_all()
        self._drain_callbacks()
        return result

    def _handle_decrypted_payload(self, payload: bytes, outer_message_type: int, direction: str) -> None:
        try:
            self._extractor.handle_decrypted_payload(payload, outer_message_type=outer_message_type, direction=direction)
        except Exception as exc:
            self._publish_extraction_failure(direction=direction, reason=type(exc).__name__)

    def _observe_plain_payload(self, direction: str, payload: bytes) -> None:
        try:
            self._extractor.observe_plain_payload(direction=direction, payload=payload)
        except Exception as exc:
            self._publish_extraction_failure(direction=direction, reason=type(exc).__name__)

    def _publish_extraction_failure(self, *, direction: str, reason: str) -> None:
        if self._on_diagnostic is None:
            return
        diagnostic = {"eventType": "radar_extraction", "status": "failed", "direction": str(direction), "reason": str(reason)}
        self._queue_diagnostic(diagnostic)

    def _begin_operation(self) -> bool:
        with self._condition:
            if self._finalized:
                if not self._finalized_diagnostic_emitted:
                    self._finalized_diagnostic_emitted = True
                    self._pending_callbacks.append(("diagnostic", {"eventType": "radar_extraction", "status": "processor_finalized"}))
                self._drain_callbacks()
                return False
            self._active_operations += 1
            return True

    def _end_operation(self) -> None:
        with self._condition:
            self._active_operations -= 1
            self._condition.notify_all()
        self._drain_callbacks()

    def _queue_event(self, event: dict[str, Any]) -> None:
        self._queue_callback("event", event)

    def _queue_diagnostic(self, diagnostic: dict[str, Any]) -> None:
        self._queue_callback("diagnostic", diagnostic)

    def _queue_callback(self, kind: str, value: dict[str, Any]) -> None:
        with self._condition:
            if kind == "event" and self._finalized:
                return
            self._pending_callbacks.append((kind, value))
        self._drain_callbacks()

    def _drain_callbacks(self) -> None:
        with self._condition:
            if self._draining_callbacks or self._active_operations or self._finalizing:
                return
            self._draining_callbacks = True
        try:
            while True:
                with self._condition:
                    if not self._pending_callbacks:
                        break
                    kind, value = self._pending_callbacks.popleft()
                    if kind == "event" and self._finalized:
                        continue
                    if kind == "event":
                        self._event_callback_owner = threading.get_ident()
                if kind == "event":
                    try:
                        self._on_event(value)
                    finally:
                        with self._condition:
                            self._event_callback_owner = None
                            self._condition.notify_all()
                else:
                    if self._on_diagnostic is None:
                        continue
                    try:
                        self._on_diagnostic(value)
                    except Exception:
                        pass
        finally:
            with self._condition:
                self._draining_callbacks = False
                should_continue = bool(self._pending_callbacks) and not self._active_operations and not self._finalizing
            if should_continue:
                self._drain_callbacks()

    def _direction_supported(self, direction: object) -> bool:
        if isinstance(direction, str) and direction in _SUPPORTED_DIRECTIONS:
            return True
        if self._on_diagnostic is not None:
            self._queue_diagnostic({"eventType": "radar_extraction", "status": "invalid_direction"})
        return False


def normalize_relay_radar_event(event: dict[str, Any], *, event_source: str = "vps_relay") -> dict[str, Any]:
    normalized = dict(event)
    normalized_source = str(event_source) if event_source else "vps_relay"
    normalized["source"] = normalized_source
    raw_meta = event.get("metadata")
    if isinstance(raw_meta, dict):
        metadata = dict(raw_meta)
    else:
        metadata = {}
    position_source = metadata.get("position_source")
    position_suffix = _position_source_suffix(position_source)
    if position_suffix:
        metadata["position_source"] = f"{normalized_source}_{position_suffix}"
    for key in list(metadata):
        normalized_key = str(key).lower()
        if "token" in normalized_key or "key" in normalized_key or "xor" in normalized_key:
            if key != "position_source":
                metadata.pop(key, None)
    normalized["metadata"] = metadata
    return normalized


def _position_source_suffix(value: object) -> str:
    if not isinstance(value, str):
        return ""
    for prefix in ("relay_", "vps_relay_", "local_relay_"):
        if value.startswith(prefix):
            return value[len(prefix):]
    return ""


def _safe_split_dh_diagnostic(event: dict[str, Any]) -> dict[str, Any]:
    allowed_keys = ("eventType", "direction", "role", "transport", "messageType", "candidateOffset", "candidateLength", "commandIndex", "commandOffset", "commandLength", "encryptedPayloadOffset", "encryptedPayloadLength", "status", "reason", "clientSideReady", "serverSideReady", "startSequence", "totalLength", "retiredSegmentCount", "retiredPacketCount", "retiredPacketBytes")
    diagnostic = {key: event[key] for key in allowed_keys if key in event}
    if "eventType" not in diagnostic:
        diagnostic["eventType"] = "public_value_rewrite"
    key_sync = event.get("keySyncExtractions")
    if isinstance(key_sync, list):
        diagnostic["keySyncExtractionCount"] = len(key_sync)
    probe = event.get("decryptedProbe")
    if isinstance(probe, dict):
        diagnostic["decryptedProbe"] = {key: probe[key] for key in ("outerMessageType", "payloadLength", "candidateCount", "keySyncCandidateObserved") if key in probe}
        candidates = _safe_decrypted_probe_candidates(probe.get("candidates"))
        if candidates:
            diagnostic["decryptedProbe"]["candidates"] = candidates
    return diagnostic


def _safe_decrypted_probe_candidates(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    allowed_keys = ("shape", "kind", "eventCode", "realEventCode", "operationCode", "realOperationCode", "returnCode", "parameterKeys", "byteArrayParameterLengths")
    candidates: list[dict[str, Any]] = []
    for item in value[:8]:
        if not isinstance(item, dict):
            continue
        candidate = {key: item[key] for key in allowed_keys if key in item}
        change_cluster = _safe_change_cluster_summary(item.get("changeCluster"))
        if change_cluster:
            candidate["changeCluster"] = change_cluster
        if candidate:
            candidates.append(candidate)
    return candidates


def _safe_change_cluster_summary(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    allowed_keys = ("mapIdLength", "mapIdKind", "parameter3Length", "parameter3Sha256", "parameter3LastByte")
    summary: dict[str, Any] = {}
    for key in allowed_keys:
        item = value.get(key)
        if key == "mapIdKind":
            if isinstance(item, str):
                summary[key] = item[:32]
            continue
        if key == "parameter3Sha256":
            if isinstance(item, str) and item.startswith("sha256:"):
                summary[key] = item
            continue
        try:
            summary[key] = int(item)  # type: ignore
        except (TypeError, ValueError):
            continue
    return summary


def _is_missing_translation_keys(event: dict[str, Any] | None) -> bool:
    return isinstance(event, dict) and event.get("eventType") == "encrypted_translate" and event.get("status") == "missing_keys"


def _safe_bridge_diagnostic(event: dict[str, Any]) -> dict[str, Any]:
    allowed_keys = ("eventType", "status", "direction", "outerMessageType", "shape", "routedCode", "positionSource", "entityIdPresent", "byteArrayLength", "xorCodeLength")
    diagnostic = {key: event[key] for key in allowed_keys if key in event}
    if "eventType" not in diagnostic:
        diagnostic["eventType"] = "radar_bridge"
    return diagnostic


def _plain_radar_event(event: EventData, *, outer_message_type: int, direction: str, decrypted: bool = False, shape: str = "plain_event", routed_code: int | None = None) -> dict[str, Any]:
    if routed_code is None:
        routed_code = _require_routed_code("event", event.code, event.parameters)
    parameters = dict(event.parameters)
    parameters[252] = routed_code
    return {
        "type": "radar_event",
        "kind": "event",
        "code": int(event.code),
        "parameters": _jsonable_parameters(parameters),
        "source": "vps_relay",
        "metadata": {
            "decrypted": bool(decrypted),
            "direction": str(direction),
            "outer_message_type": int(outer_message_type),
            "position_source": "vps_relay_decrypted" if decrypted else "vps_relay_plain",
            "routed_code": int(routed_code),
            "shape": shape,
        },
    }


def _plain_radar_request(request: OperationRequest, *, outer_message_type: int, direction: str, decrypted: bool = False, shape: str = "plain_request", routed_code: int | None = None) -> dict[str, Any]:
    if routed_code is None:
        routed_code = _require_routed_code("request", request.operation_code, request.parameters)
    parameters = _operation_parameters(request.parameters, operation_code=request.operation_code)
    return {
        "type": "radar_event",
        "kind": "request",
        "code": int(request.operation_code),
        "parameters": _jsonable_parameters(parameters),
        "source": "vps_relay",
        "metadata": {
            "decrypted": bool(decrypted),
            "direction": str(direction),
            "outer_message_type": int(outer_message_type),
            "position_source": "vps_relay_decrypted" if decrypted else "vps_relay_plain",
            "routed_code": int(routed_code),
            "shape": shape,
        },
    }


def _plain_radar_response(response: OperationResponse, *, outer_message_type: int, direction: str, decrypted: bool = False, shape: str = "plain_response", routed_code: int | None = None) -> dict[str, Any]:
    if routed_code is None:
        routed_code = _require_routed_code("response", response.operation_code, response.parameters)
    parameters = _operation_parameters(response.parameters, operation_code=response.operation_code)
    return {
        "type": "radar_event",
        "kind": "response",
        "code": int(response.operation_code),
        "parameters": _jsonable_parameters(parameters),
        "source": "vps_relay",
        "metadata": {
            "decrypted": bool(decrypted),
            "direction": str(direction),
            "outer_message_type": int(outer_message_type),
            "position_source": "vps_relay_decrypted" if decrypted else "vps_relay_plain",
            "return_code": int(response.return_code),
            "routed_code": int(routed_code),
            "shape": shape,
        },
    }


def _require_routed_code(kind: str, observed_code: int, parameters: object) -> int:
    resolution = resolve_event_route(kind, observed_code=observed_code, parameters=parameters)
    if resolution is None:
        raise ValueError("invalid_event_route")
    return resolution.routed.code


def _operation_parameters(parameters: dict[int, Any], *, operation_code: int) -> dict[int, Any]:
    copied = dict(parameters)
    has_routed_key = any((type(key) is int and key == 253) or (type(key) is str and key == "253") for key in copied)
    if not has_routed_key:
        copied[253] = int(operation_code)
    return copied


def _decrypted_radar_messages(payload: bytes, *, outer_message_type: int, direction: str) -> list[dict[str, Any]]:
    candidate = _decrypted_message_candidate(payload, outer_message_type=outer_message_type)
    if candidate is None:
        return []
    kind, shape, item = candidate
    if kind == "event" and isinstance(item, EventData):
        post_process_event(item)
        resolution = resolve_event_route("event", observed_code=item.code, parameters=item.parameters)
        if resolution is None or resolution.routed in DIAGNOSTIC_ONLY_ROUTES:
            return []
        return [_plain_radar_event(item, outer_message_type=outer_message_type, direction=direction, decrypted=True, shape=shape, routed_code=resolution.routed.code)]
    if kind == "request" and isinstance(item, OperationRequest):
        post_process_request(item)
        resolution = resolve_event_route("request", observed_code=item.operation_code, parameters=item.parameters)
        if resolution is None:
            return []
        return [_plain_radar_request(item, outer_message_type=outer_message_type, direction=direction, decrypted=True, shape=shape, routed_code=resolution.routed.code)]
    if kind == "response" and isinstance(item, OperationResponse):
        post_process_response(item)
        resolution = resolve_event_route("response", observed_code=item.operation_code, parameters=item.parameters)
        if resolution is None:
            return []
        return [_plain_radar_response(item, outer_message_type=outer_message_type, direction=direction, decrypted=True, shape=shape, routed_code=resolution.routed.code)]
    return []


def _decrypted_message_candidate(payload: bytes, *, outer_message_type: int) -> tuple[str, str, EventData | OperationRequest | OperationResponse] | None:
    inner = _inner_decrypted_message_candidate(payload)
    if inner is not None:
        return inner
    if outer_message_type == 130:
        request = _deserialize_request_or_none(payload)
        return ("request", "direct_request", request) if request is not None else None
    if outer_message_type == 131:
        response = _deserialize_response_or_none(payload)
        return ("response", "direct_response", response) if response is not None else None
    if outer_message_type == 132:
        event = _deserialize_event_or_none(payload)
        return ("event", "direct_event", event) if event is not None else None
    for kind, shape, parser in (("event", "direct_event", _deserialize_event_or_none), ("request", "direct_request", _deserialize_request_or_none), ("response", "direct_response", _deserialize_response_or_none)):
        parsed = parser(payload)
        if parsed is not None:
            return (kind, shape, parsed)
    return None


def _inner_decrypted_message_candidate(payload: bytes) -> tuple[str, str, EventData | OperationRequest | OperationResponse] | None:
    if not payload:
        return None
    inner_type = payload[0]
    inner_payload = payload[1:]
    if inner_type == 2:
        request = _deserialize_request_or_none(inner_payload)
        return ("request", "inner_request", request) if request is not None else None
    if inner_type in frozenset({3, 7}):
        response = _deserialize_response_or_none(inner_payload)
        return ("response", "inner_response", response) if response is not None else None
    if inner_type == 4:
        event = _deserialize_event_or_none(inner_payload)
        return ("event", "inner_event", event) if event is not None else None
    return None


def _deserialize_event_or_none(payload: bytes) -> EventData | None:
    try:
        return deserialize_event_live(payload)
    except Exception:
        return None


def _deserialize_request_or_none(payload: bytes) -> OperationRequest | None:
    try:
        return deserialize_request_live(payload)
    except Exception:
        return None


def _deserialize_response_or_none(payload: bytes) -> OperationResponse | None:
    try:
        return deserialize_response_live(payload)
    except Exception:
        return None


def _jsonable_parameters(value: Any) -> Any:
    return _jsonable_buffers(to_jsonable(value))


def _jsonable_buffers(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _jsonable_buffers(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable_buffers(item) for item in value]
    if isinstance(value, (bytes, bytearray)):
        return {"type": "Buffer", "data": [int(item) & 255 for item in value]}
    return value
