"""Photon packet parser and fragment reassembly logic.

The packet layer deals with low-level Photon transport framing: command headers,
message wrappers, fragmented payloads, and the stream state needed to reassemble
messages that arrive over multiple commands. Higher-level code in the project then
converts the emitted event/request/response objects into broker-safe radar data.
"""

from __future__ import annotations

import hashlib
from bisect import bisect_left
from dataclasses import dataclass, field
from typing import Any, Callable

from ass_radar.photon.deserializer import deserialize_event_live, deserialize_request_live, deserialize_response_live
from ass_radar.photon.events import post_process_event, post_process_request, post_process_response
from ass_radar.photon.types import EventData, OperationRequest, OperationResponse

PHOTON_HEADER_LENGTH = 12
COMMAND_HEADER_LENGTH = 12
FRAGMENT_HEADER_LENGTH = 20
MAX_FRAGMENT_COUNT = 4096
MAX_REASSEMBLED_MESSAGE_SIZE = 1048576
MAX_PENDING_SEGMENTS = 64
MAX_PENDING_SEGMENT_BYTES = 16777216
PHOTON_INIT_MAGIC = bytes.fromhex('e9712dd5')
CMD_ACK = 1
CMD_CONNECT = 2
CMD_VERIFY_CONNECT = 3
CMD_DISCONNECT = 4
CMD_PING = 5
CMD_SEND_RELIABLE = 6
CMD_SEND_UNRELIABLE = 7
CMD_SEND_FRAGMENT = 8
CMD_SEND_UNSEQUENCED = 11
CMD_FETCH_SERVER_TIMESTAMP = 12
_CONTROL_COMMAND_LENGTHS = {
    CMD_ACK: 20,
    CMD_CONNECT: 44,
    CMD_VERIFY_CONNECT: 44,
    CMD_DISCONNECT: 12,
    CMD_PING: 12,
    CMD_FETCH_SERVER_TIMESTAMP: 12,
}
_MESSAGE_COMMANDS = frozenset({CMD_SEND_RELIABLE, CMD_SEND_UNRELIABLE, CMD_SEND_UNSEQUENCED})
_SUPPORTED_COMMANDS = frozenset().union(_CONTROL_COMMAND_LENGTHS, _MESSAGE_COMMANDS, {CMD_SEND_FRAGMENT})
MSG_REQUEST = 2
MSG_RESPONSE = 3
MSG_EVENT = 4
MSG_RESPONSE_ALT = 7
MSG_ENCRYPTED_REQUEST = 130
MSG_ENCRYPTED_RESPONSE = 131
MSG_ENCRYPTED_EVENT = 132
MSG_ENCRYPTED = MSG_ENCRYPTED_RESPONSE
ENCRYPTED_MESSAGE_TYPES = frozenset({MSG_ENCRYPTED_REQUEST, MSG_ENCRYPTED_RESPONSE, MSG_ENCRYPTED_EVENT})


@dataclass(frozen=True)
class _FragmentPiece:
    offset: int
    data: bytes


@dataclass
class _SegmentedPackage:
    fragment_count: int
    total_length: int
    payload: bytearray
    fragments: dict[int, _FragmentPiece] = field(default_factory=dict)
    fragment_offsets: list[int] = field(default_factory=list)
    fragments_by_offset: dict[int, _FragmentPiece] = field(default_factory=dict)
    received_bytes: int = 0


class PhotonParser:
    """Incrementally parse a Photon stream and emit decoded protocol objects.

    The parser walks packet headers, command records, and message wrappers while
    tracking fragmented payloads across multiple commands. It exposes callbacks for
    decoded event/request/response objects and keeps raw transport diagnostics in
    a structured frame stream for debugging.
    """

    def __init__(
        self,
        on_event: Callable[[EventData], None] | None = None,
        on_request: Callable[[OperationRequest], None] | None = None,
        on_response: Callable[[OperationResponse], None] | None = None,
        on_encrypted: Callable[[], None] | None = None,
        on_parse_error: Callable[[str, int], None] | None = None,
        on_frame: Callable[[dict[str, Any]], None] | None = None,
        on_raw_message: Callable[[int, bytes], None] | None = None,
        can_reserve_fragment: Callable[[int], bool] | None = None,
        should_abort: Callable[[], bool] | None = None,
    ) -> None:
        self._pending_segments: dict[tuple[int, int], _SegmentedPackage] = {}
        self._pending_reserved_bytes = 0
        self._receive_in_progress = False
        self._reporting_reentrant_receive = False
        self.on_event = on_event
        self.on_request = on_request
        self.on_response = on_response
        self.on_encrypted = on_encrypted
        self.on_parse_error = on_parse_error
        self.on_frame = on_frame
        self.on_raw_message = on_raw_message
        self.can_reserve_fragment = can_reserve_fragment
        self.should_abort = should_abort

    def receive_packet(self, payload: bytes | bytearray | memoryview) -> bool:
        if self._receive_in_progress:
            if not self._reporting_reentrant_receive:
                self._reporting_reentrant_receive = True
                try:
                    self._parse_error('reentrant packet receive rejected', 0)
                finally:
                    self._reporting_reentrant_receive = False
            return False
        self._receive_in_progress = True
        try:
            return self._receive_packet_once(payload)
        finally:
            self._receive_in_progress = False

    def _receive_packet_once(self, payload: bytes | bytearray | memoryview) -> bool:
        src = bytes(payload)
        if src.startswith(PHOTON_INIT_MAGIC):
            if not self._discard_all_pending(status='discarded', reason='photon_init_reset'):
                return False
            self._emit_frame(_photon_init_summary(src))
            return not self._abort_requested()
        if len(src) < PHOTON_HEADER_LENGTH:
            self._parse_error('payload shorter than photon header', len(src))
            return False
        flags = src[2]
        command_count = src[3]
        offset = PHOTON_HEADER_LENGTH
        encrypted_packet = bool(flags & 1)
        self._emit_frame({
            'kind': 'packet',
            'packetLength': len(src),
            'flags': int(flags),
            'encrypted': encrypted_packet,
            'commandCount': int(command_count),
        })
        if encrypted_packet:
            if self.on_encrypted is not None:
                self.on_encrypted()
            return False
        for command_index in range(command_count):
            offset, ok = self._handle_command(src, offset, command_index=command_index)
            if not ok or self._abort_requested():
                return False
        if offset != len(src):
            self._parse_error('trailing bytes after commands', len(src) - offset)
            return False
        return True

    def finalize(self) -> bool:
        if not self._pending_segments:
            return True
        self._discard_all_pending(status='incomplete', reason='end_of_stream')
        return False

    def _handle_command(self, src: bytes, offset: int, *, command_index: int) -> tuple[int, bool]:
        if not _available(src, offset, COMMAND_HEADER_LENGTH):
            self._parse_error('invalid command header', len(src))
            return len(src), False
        command_offset = offset
        command_type = src[offset]
        command_channel_id = src[offset + 1]
        command_flags = src[offset + 2]
        command_length = int.from_bytes(src[offset + 4: offset + 8], 'big')
        command_sequence = int.from_bytes(src[offset + 8: offset + 12], 'big')
        command_payload_length = command_length - COMMAND_HEADER_LENGTH
        disposition = _command_disposition(command_type)
        self._emit_frame({
            'kind': 'command',
            'commandIndex': int(command_index),
            'commandType': int(command_type),
            'commandChannelId': int(command_channel_id),
            'commandFlags': int(command_flags),
            'commandSequence': int(command_sequence),
            'commandLength': int(command_length),
            'commandPayloadLength': int(max(0, command_payload_length)),
            'commandHeaderPreviewHex': src[command_offset: command_offset + COMMAND_HEADER_LENGTH].hex(),
            'supported': command_type in _SUPPORTED_COMMANDS,
            'commandDisposition': disposition,
        })
        if command_payload_length < 0 or not _available(src, command_offset, command_length):
            self._parse_error('invalid command length', len(src))
            return len(src), False
        command_end = command_offset + command_length
        payload_offset = command_offset + COMMAND_HEADER_LENGTH
        expected_length = _CONTROL_COMMAND_LENGTHS.get(command_type)
        if expected_length is not None:
            if command_length != expected_length:
                self._parse_error('invalid control command length', command_length)
                return command_end, False
            return command_end, True
        if command_type not in _SUPPORTED_COMMANDS:
            self._parse_error('unsupported command type', command_length)
            return command_end, False
        if command_type in _MESSAGE_COMMANDS:
            prefix_length = 4 if command_type in (CMD_SEND_UNRELIABLE, CMD_SEND_UNSEQUENCED) else 0
            message_length = command_payload_length - prefix_length
            if message_length < 2:
                self._parse_error('invalid message command payload', command_payload_length)
                return command_end, False
            transport = {
                CMD_SEND_RELIABLE: 'reliable',
                CMD_SEND_UNRELIABLE: 'unreliable',
                CMD_SEND_UNSEQUENCED: 'unsequenced',
            }[command_type]
            ok = self._handle_message(src, payload_offset + prefix_length, message_length, command_index=command_index, transport=transport)
            return command_end, ok
        ok = self._handle_send_fragment(src, payload_offset, command_payload_length, command_index=command_index, command_channel_id=command_channel_id)
        return command_end, ok

    def _handle_message(self, src: bytes | bytearray, offset: int, command_length: int, *, command_index: int | None, transport: str) -> bool:
        if command_length < 2 or not _available(src, offset, command_length):
            self._parse_error('invalid message command payload', command_length)
            return False
        message_type = src[offset + 1]
        data_offset = offset + 2
        data_length = command_length - 2
        data = bytes(src[data_offset: data_offset + data_length])
        self._emit_frame({
            'kind': 'message',
            'commandIndex': command_index,
            'transport': transport,
            'messageType': int(message_type),
            'encrypted': message_type in ENCRYPTED_MESSAGE_TYPES,
            **_payload_summary(data),
        })
        if self.on_raw_message is not None:
            try:
                self.on_raw_message(message_type, data)
            except Exception:
                self._parse_error('raw message callback failed', len(data))
                return False
        if message_type in ENCRYPTED_MESSAGE_TYPES:
            if self.on_encrypted is not None:
                self.on_encrypted()
            return True
        try:
            if message_type == MSG_REQUEST:
                request = deserialize_request_live(data)
                post_process_request(request)
                if self.on_request is not None:
                    self.on_request(request)
            elif message_type in (MSG_RESPONSE, MSG_RESPONSE_ALT):
                response = deserialize_response_live(data)
                post_process_response(response)
                if self.on_response is not None:
                    self.on_response(response)
            elif message_type == MSG_EVENT:
                event = deserialize_event_live(data)
                post_process_event(event)
                if self.on_event is not None:
                    self.on_event(event)
        except Exception:
            self._parse_error('message decode failed', len(data))
        return True

    def _handle_send_fragment(self, src: bytes, offset: int, command_length: int, *, command_index: int, command_channel_id: int) -> bool:
        if command_length < FRAGMENT_HEADER_LENGTH or not _available(src, offset, command_length):
            self._parse_error('invalid fragment command payload', command_length)
            return False
        start_sequence = int.from_bytes(src[offset: offset + 4], 'big')
        fragment_count = int.from_bytes(src[offset + 4: offset + 8], 'big')
        fragment_number = int.from_bytes(src[offset + 8: offset + 12], 'big')
        total_length = int.from_bytes(src[offset + 12: offset + 16], 'big')
        fragment_offset = int.from_bytes(src[offset + 16: offset + 20], 'big')
        fragment_data_offset = offset + FRAGMENT_HEADER_LENGTH
        fragment_length = command_length - FRAGMENT_HEADER_LENGTH
        key = (command_channel_id, start_sequence)
        invalid_reason = _fragment_header_error(
            fragment_count=fragment_count,
            fragment_number=fragment_number,
            total_length=total_length,
            fragment_offset=fragment_offset,
            fragment_length=fragment_length,
        )
        if invalid_reason is not None:
            return self._reject_fragment(
                key,
                command_index=command_index,
                fragment_count=fragment_count,
                fragment_number=fragment_number,
                total_length=total_length,
                fragment_offset=fragment_offset,
                fragment_length=fragment_length,
                reason=invalid_reason,
            )
        segment = self._pending_segments.get(key)
        if segment is not None:
            if segment.fragment_count != fragment_count or segment.total_length != total_length:
                return self._reject_fragment(
                    key,
                    command_index=command_index,
                    fragment_count=fragment_count,
                    fragment_number=fragment_number,
                    total_length=total_length,
                    fragment_offset=fragment_offset,
                    fragment_length=fragment_length,
                    reason='metadata_mismatch',
                )
        existing = segment.fragments.get(fragment_number) if segment is not None else None
        if existing is not None:
            if existing.offset != fragment_offset or len(existing.data) != fragment_length:
                return self._reject_fragment(
                    key,
                    command_index=command_index,
                    fragment_count=fragment_count,
                    fragment_number=fragment_number,
                    total_length=total_length,
                    fragment_offset=fragment_offset,
                    fragment_length=fragment_length,
                    reason='conflicting_retransmission',
                )
            fragment_data = bytes(src[fragment_data_offset: fragment_data_offset + fragment_length])
            if existing.data == fragment_data:
                self._emit_fragment_frame(
                    key,
                    command_index=command_index,
                    fragment_count=fragment_count,
                    fragment_number=fragment_number,
                    total_length=total_length,
                    fragment_offset=fragment_offset,
                    fragment_length=fragment_length,
                    status='retransmitted',
                )
                return True
            return self._reject_fragment(
                key,
                command_index=command_index,
                fragment_count=fragment_count,
                fragment_number=fragment_number,
                total_length=total_length,
                fragment_offset=fragment_offset,
                fragment_length=fragment_length,
                reason='conflicting_retransmission',
            )
        fragment_end = fragment_offset + fragment_length
        fragment_offset_index = 0
        if segment is not None:
            fragment_offset_index = bisect_left(segment.fragment_offsets, fragment_offset)
            previous_piece = segment.fragments_by_offset[segment.fragment_offsets[fragment_offset_index - 1]] if fragment_offset_index > 0 else None
            next_piece = segment.fragments_by_offset[segment.fragment_offsets[fragment_offset_index]] if fragment_offset_index < len(segment.fragment_offsets) else None
            if previous_piece is not None and previous_piece.offset + len(previous_piece.data) > fragment_offset:
                return self._reject_fragment(
                    key,
                    command_index=command_index,
                    fragment_count=fragment_count,
                    fragment_number=fragment_number,
                    total_length=total_length,
                    fragment_offset=fragment_offset,
                    fragment_length=fragment_length,
                    reason='overlap',
                )
            if next_piece is not None and fragment_end > next_piece.offset:
                return self._reject_fragment(
                    key,
                    command_index=command_index,
                    fragment_count=fragment_count,
                    fragment_number=fragment_number,
                    total_length=total_length,
                    fragment_offset=fragment_offset,
                    fragment_length=fragment_length,
                    reason='overlap',
                )
        completes_assembly = (len(segment.fragments) if segment is not None else 0) + 1 == fragment_count
        if completes_assembly:
            if _fragment_candidate_has_gap(segment, fragment_offset=fragment_offset, fragment_length=fragment_length, total_length=total_length):
                return self._reject_fragment(
                    key,
                    command_index=command_index,
                    fragment_count=fragment_count,
                    fragment_number=fragment_number,
                    total_length=total_length,
                    fragment_offset=fragment_offset,
                    fragment_length=fragment_length,
                    reason='fragment_gap',
                )
        if segment is None:
            if not self._evict_for_capacity(total_length):
                return False
            if not self._fragment_reservation_allowed(total_length):
                return False
            if not self._evict_for_capacity(total_length):
                return False
        fragment_data = bytes(src[fragment_data_offset: fragment_data_offset + fragment_length])
        if segment is None:
            segment = _SegmentedPackage(fragment_count=fragment_count, total_length=total_length, payload=bytearray(total_length))
            self._pending_segments[key] = segment
            self._pending_reserved_bytes += total_length
            if not self._emit_fragment_lifecycle(key, segment, status='opened'):
                return False
        segment.payload[fragment_offset:fragment_end] = fragment_data
        piece = _FragmentPiece(offset=fragment_offset, data=fragment_data)
        segment.fragments[fragment_number] = piece
        segment.fragment_offsets.insert(fragment_offset_index, fragment_offset)
        segment.fragments_by_offset[fragment_offset] = piece
        segment.received_bytes += fragment_length
        self._emit_fragment_frame(
            key,
            command_index=command_index,
            fragment_count=fragment_count,
            fragment_number=fragment_number,
            total_length=total_length,
            fragment_offset=fragment_offset,
            fragment_length=fragment_length,
            status='accepted',
        )
        if not completes_assembly:
            return True
        self._remove_segment(key)
        if not self._emit_fragment_lifecycle(key, segment, status='completed'):
            return False
        return self._handle_message(segment.payload, 0, len(segment.payload), command_index=command_index, transport='fragment')

    def _reject_fragment(self, key: tuple[int, int], *, command_index: int, fragment_count: int, fragment_number: int, total_length: int, fragment_offset: int, fragment_length: int, reason: str) -> bool:
        self._emit_fragment_frame(
            key,
            command_index=command_index,
            fragment_count=fragment_count,
            fragment_number=fragment_number,
            total_length=total_length,
            fragment_offset=fragment_offset,
            fragment_length=fragment_length,
            status='rejected',
            reason=reason,
        )
        segment = self._remove_segment(key)
        if segment is not None:
            if not self._emit_fragment_lifecycle(key, segment, status='discarded', reason=reason):
                return False
        self._parse_error(f'invalid fragment: {reason}', fragment_length)
        return False

    def _fragment_reservation_allowed(self, total_length: int) -> bool:
        if self.can_reserve_fragment is None:
            return True
        try:
            allowed = bool(self.can_reserve_fragment(total_length))
        except Exception:
            self._parse_error('fragment reservation callback failed', 0)
            return False
        if not allowed:
            self._parse_error('fragment reservation rejected', 0)
            return False
        return True

    def _evict_for_capacity(self, total_length: int) -> bool:
        if not self._pending_segments:
            return True
        # First check if eviction needed
        if len(self._pending_segments) < MAX_PENDING_SEGMENTS and self._pending_reserved_bytes + total_length <= MAX_PENDING_SEGMENT_BYTES:
            return True
        # In original pyasm this is a loop while either condition holds
        while self._pending_segments:
            if len(self._pending_segments) < MAX_PENDING_SEGMENTS and self._pending_reserved_bytes + total_length <= MAX_PENDING_SEGMENT_BYTES:
                break
            oldest_key = next(iter(self._pending_segments))
            segment = self._remove_segment(oldest_key)
            if segment is not None:
                if not self._emit_fragment_lifecycle(oldest_key, segment, status='evicted', reason='capacity'):
                    return False
        return True

    def _remove_segment(self, key: tuple[int, int]) -> _SegmentedPackage | None:
        segment = self._pending_segments.pop(key, None)
        if segment is not None:
            self._pending_reserved_bytes -= segment.total_length
        return segment

    def _discard_all_pending(self, *, status: str, reason: str) -> bool:
        accepted = True
        for key in tuple(self._pending_segments):
            segment = self._remove_segment(key)
            if segment is not None:
                if not self._emit_fragment_lifecycle(key, segment, status=status, reason=reason):
                    accepted = False
        return accepted

    def _emit_fragment_frame(self, key: tuple[int, int], *, command_index: int, fragment_count: int, fragment_number: int, total_length: int, fragment_offset: int, fragment_length: int, status: str, reason: str | None = None) -> None:
        frame: dict[str, Any] = {
            'kind': 'fragment',
            'commandIndex': int(command_index),
            'commandChannelId': int(key[0]),
            'startSequence': int(key[1]),
            'fragmentCount': int(fragment_count),
            'fragmentNumber': int(fragment_number),
            'totalLength': int(total_length),
            'fragmentOffset': int(fragment_offset),
            'fragmentLength': int(fragment_length),
            'status': status,
        }
        if reason is not None:
            frame['reason'] = reason
        self._emit_frame(frame)

    def _abort_requested(self) -> bool:
        if self.should_abort is None:
            return False
        try:
            return bool(self.should_abort())
        except Exception:
            self._parse_error('abort predicate failed', 0)
            return True

    def _emit_fragment_lifecycle(self, key: tuple[int, int], segment: _SegmentedPackage, *, status: str, reason: str | None = None) -> bool:
        frame: dict[str, Any] = {
            'kind': 'fragment_lifecycle',
            'commandChannelId': int(key[0]),
            'startSequence': int(key[1]),
            'fragmentCount': int(segment.fragment_count),
            'totalLength': int(segment.total_length),
            'reservedBytes': int(segment.total_length),
            'receivedFragments': len(segment.fragments),
            'receivedBytes': int(segment.received_bytes),
            'status': status,
        }
        if reason is not None:
            frame['reason'] = reason
        self._emit_frame(frame)
        return not self._abort_requested()

    def _parse_error(self, reason: str, payload_length: int) -> None:
        if self.on_parse_error is None:
            return
        try:
            self.on_parse_error(reason, payload_length)
        except Exception:
            pass

    def _emit_frame(self, frame: dict[str, Any]) -> None:
        if self.on_frame is None:
            return
        try:
            self.on_frame(frame)
        except Exception:
            self._parse_error('frame callback failed', 0)

    # Compatibility aliases mentioned in task description
    feed = receive_packet
    feed_one = _receive_packet_once
    parse_fragment = _handle_send_fragment
    handle_reliable = _handle_message


def _command_disposition(command_type: int) -> str:
    if command_type in _CONTROL_COMMAND_LENGTHS:
        return 'control'
    if command_type in _MESSAGE_COMMANDS:
        return 'message'
    if command_type == CMD_SEND_FRAGMENT:
        return 'fragment'
    return 'unsupported'


def _fragment_header_error(*, fragment_count: int, fragment_number: int, total_length: int, fragment_offset: int, fragment_length: int) -> str | None:
    if not 1 <= fragment_count <= MAX_FRAGMENT_COUNT:
        return 'fragment_count'
    if fragment_number >= fragment_count:
        return 'fragment_number'
    if not 1 <= total_length <= MAX_REASSEMBLED_MESSAGE_SIZE:
        return 'total_length'
    if fragment_length <= 0:
        return 'empty_fragment'
    if fragment_offset + fragment_length > total_length:
        return 'fragment_bounds'
    return None


def _fragment_candidate_has_gap(segment: _SegmentedPackage | None, *, fragment_offset: int, fragment_length: int, total_length: int) -> bool:
    ranges: list[tuple[int, int]] = []
    if segment is not None:
        ranges.extend((offset, len(segment.fragments_by_offset[offset].data)) for offset in segment.fragment_offsets)
    ranges.insert(bisect_left(ranges, (fragment_offset, fragment_length)), (fragment_offset, fragment_length))
    cursor = 0
    for piece_offset, piece_length in sorted(ranges):
        if piece_offset != cursor:
            return True
        cursor += piece_length
    return cursor != total_length


def _available(src: bytes | bytearray, offset: int, count: int) -> bool:
    return count >= 0 and offset >= 0 and len(src) - offset >= count


def _payload_summary(payload: bytes) -> dict[str, Any]:
    return {
        'payloadLength': len(payload),
        'payloadSha256': f"sha256:{hashlib.sha256(payload).hexdigest()}",
        'payloadPreviewHex': payload[:16].hex(),
    }


def _photon_init_summary(payload: bytes) -> dict[str, Any]:
    tail = payload[len(PHOTON_INIT_MAGIC):]
    return {
        'kind': 'photon_init',
        'packetLength': len(payload),
        'initMagicHex': PHOTON_INIT_MAGIC.hex(),
        'initStage': int(payload[4]) if len(payload) > 4 else None,
        'initChannel': int(payload[5]) if len(payload) > 5 else None,
        'encrypted': False,
        **_payload_summary(tail),
    }

