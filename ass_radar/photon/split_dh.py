"""Split-Diffie-Hellman flow and fragment reassembly for Photon transport rewriting.

This module sits between the packet parser and the encryption layer. It rewrites
public DH values discovered in packet payloads, tracks fragmented Photon commands,
and derives the AES keys needed to translate encrypted traffic without breaking the
underlying transport semantics.
"""

from __future__ import annotations

import hashlib
import secrets
from bisect import bisect_left
from dataclasses import dataclass, field
from typing import Any, Callable

from ass_radar.photon.dh import MODP_768_PRIME, derive_aes_key, public_from_private, shared_secret_from_public
from ass_radar.photon.encrypted import KeySyncExtraction, find_encrypted_message_targets, translate_encrypted_messages, translate_encrypted_reliable_payload
from ass_radar.photon.packet import ENCRYPTED_MESSAGE_TYPES, MAX_FRAGMENT_COUNT as PHOTON_MAX_FRAGMENT_COUNT, MAX_PENDING_SEGMENT_BYTES as PHOTON_MAX_PENDING_SEGMENT_BYTES, MAX_PENDING_SEGMENTS as PHOTON_MAX_PENDING_SEGMENTS, MAX_REASSEMBLED_MESSAGE_SIZE as PHOTON_MAX_REASSEMBLED_MESSAGE_SIZE
from ass_radar.photon.rewrite import find_public_value_target, rewrite_public_value

CMD_SEND_FRAGMENT = 8
COMMAND_HEADER_LENGTH = 12
FRAGMENT_HEADER_LENGTH = 20

MAX_FRAGMENT_COUNT = PHOTON_MAX_FRAGMENT_COUNT
MAX_REASSEMBLED_MESSAGE_SIZE = PHOTON_MAX_REASSEMBLED_MESSAGE_SIZE
MAX_PENDING_FRAGMENT_SEGMENTS = PHOTON_MAX_PENDING_SEGMENTS
MAX_PENDING_FRAGMENT_BYTES = PHOTON_MAX_PENDING_SEGMENT_BYTES
MAX_RETAINED_FRAGMENT_PACKETS_PER_SEGMENT = MAX_FRAGMENT_COUNT * 2
MAX_RETAINED_FRAGMENT_PACKET_BYTES_PER_SEGMENT = MAX_REASSEMBLED_MESSAGE_SIZE * 2
MAX_PENDING_FRAGMENT_PACKET_COUNT = MAX_FRAGMENT_COUNT * 16
MAX_PENDING_FRAGMENT_PACKET_BYTES = MAX_PENDING_FRAGMENT_BYTES


@dataclass(frozen=True)
class SplitDhProcessResult:
    """Result of evaluating one packet in the split-DH rewriting session."""

    payload: bytes
    rewritten: bool
    event: dict[str, Any] | None = None
    delayed: bool = False
    extra_payloads: tuple[bytes, ...] = ()
    additional_events: tuple[dict[str, Any], ...] = ()
    transport_stream_lost: bool = False

    @property
    def output_payloads(self) -> tuple[bytes, ...]:
        """Return the final payload(s) to emit for this packet processing pass."""
        if self.delayed:
            return ()
        return (self.payload, *self.extra_payloads)

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        """Return the diagnostics/events generated while rewriting this packet."""
        if self.event is None:
            return self.additional_events
        return (self.event, *self.additional_events)


@dataclass(frozen=True)
class _FragmentCommand:
    command_index: int
    command_offset: int
    command_length: int
    command_channel_id: int
    start_sequence: int
    fragment_count: int
    fragment_number: int
    total_length: int
    fragment_offset: int
    fragment_length: int
    chunk_offset: int


@dataclass(frozen=True)
class _FragmentParse:
    commands: tuple[_FragmentCommand, ...]
    fragment_command_seen: bool
    malformed: bool


@dataclass(frozen=True)
class _BufferedFragmentPacket:
    payload: bytes
    commands: tuple[_FragmentCommand, ...]


@dataclass(frozen=True)
class _FragmentPiece:
    offset: int
    data: bytes


@dataclass(frozen=True)
class _FragmentStreamLoss:
    reason: str
    retired_packet_count: int
    retired_packet_bytes: int


@dataclass
class _FragmentSegment:
    fragment_count: int
    total_length: int
    payload: bytearray
    bytes_written: int = 0
    fragments: dict[int, _FragmentPiece] = field(default_factory=dict)
    fragment_offsets: list[int] = field(default_factory=list)
    fragments_by_offset: dict[int, _FragmentPiece] = field(default_factory=dict)
    packets: list[_BufferedFragmentPacket] = field(default_factory=list)
    packet_payloads: set[bytes] = field(default_factory=set)
    retained_packet_count: int = 0
    retained_packet_bytes: int = 0


class SplitDhSession:
    """Manage a proxy-side DH handshake and packet rewrite session.

    The session generates private keys for the proxy, watches for peer public-value
    exchanges, derives the resulting shared secrets, and then uses those secrets to
    translate ciphertext between the client and server streams.
    """

    def __init__(self, *, proxy_client_side_private: int | None = None, proxy_server_side_private: int | None = None, on_key_sync: Callable[[KeySyncExtraction], None] | None = None, on_decrypted_payload: Callable[[bytes, int, str], None] | None = None) -> None:
        if not proxy_client_side_private:
            self.proxy_client_side_private = _random_private_value()
        else:
            self.proxy_client_side_private = proxy_client_side_private
        if not proxy_server_side_private:
            self.proxy_server_side_private = _random_private_value()
        else:
            self.proxy_server_side_private = proxy_server_side_private
        self.public_for_client = public_from_private(self.proxy_client_side_private)
        self.public_for_server = public_from_private(self.proxy_server_side_private)
        self.observed_client_public: bytes | None = None
        self.observed_server_public: bytes | None = None
        self.client_side_aes_key: bytes | None = None
        self.server_side_aes_key: bytes | None = None
        self.on_key_sync = on_key_sync
        self.on_decrypted_payload = on_decrypted_payload
        self._fragment_segments: dict[tuple[str, int, int], _FragmentSegment] = {}
        self._pending_fragment_bytes = 0
        self._pending_fragment_packet_count = 0
        self._pending_fragment_packet_bytes = 0
        self._fragment_stream_losses: list[_FragmentStreamLoss] = []
        self._finalize_result: bool | None = None

    def process_packets(self, *, direction: str, payload: bytes) -> SplitDhProcessResult:
        """Alias for processing a single packet while preserving the external API."""
        return self.process_packet(direction=direction, payload=payload)

    def finalize(self) -> bool:
        """Close the session and mark any incomplete fragment segments as abandoned."""
        if self._finalize_result is not None:
            return self._finalize_result
        result = not self._fragment_segments
        for key in tuple(self._fragment_segments):
            self._retire_fragment_segment(key, reason='finalize_incomplete')
        self._fragment_stream_losses.clear()
        self._finalize_result = result
        return result

    def process_packet(self, *, direction: str, payload: bytes) -> SplitDhProcessResult:
        """Process one packet in the direction-aware split-DH stream."""
        if self._finalize_result is not None:
            return SplitDhProcessResult(payload=payload, rewritten=False)
        self._fragment_stream_losses.clear()
        fragment_result = self._process_fragment_packet(direction=direction, payload=payload)
        if fragment_result is not None:
            return self._attach_fragment_stream_loss(direction=direction, result=fragment_result)
        encrypted_result = self._process_encrypted_packet(direction=direction, payload=payload)
        if encrypted_result is not None:
            return encrypted_result
        expected_message_type = _expected_message_type_for_direction(direction)
        if expected_message_type is None:
            return SplitDhProcessResult(payload=payload, rewritten=False)
        target = find_public_value_target(payload, expected_message_type=expected_message_type)
        if target is None:
            return SplitDhProcessResult(payload=payload, rewritten=False)
        observed_public = payload[target.candidate_slice]
        replacement_public = self._replacement_public_value(expected_message_type)
        rewrite = rewrite_public_value(payload, replacement_public, expected_message_type=expected_message_type)
        # The proxy needs to derive a key for each direction independently, using the
        # observed peer public value and the local proxy-side private exponent.
        if expected_message_type == 6:
            self.observed_client_public = observed_public
            self.client_side_aes_key = derive_aes_key(shared_secret_from_public(observed_public, self.proxy_client_side_private))
        else:
            self.observed_server_public = observed_public
            self.server_side_aes_key = derive_aes_key(shared_secret_from_public(observed_public, self.proxy_server_side_private))
        return SplitDhProcessResult(
            payload=rewrite.payload,
            rewritten=True,
            event={
                'direction': str(direction),
                'role': target.role,
                'messageType': target.message_type,
                'candidateOffset': target.candidate_offset,
                'candidateLength': target.candidate_length,
                'commandIndex': target.command_index,
                'commandOffset': target.command_offset,
                'commandLength': target.command_length,
                'observedPublicSha256': _sha256(observed_public),
                'replacementPublicSha256': _sha256(replacement_public),
                'originalPayloadSha256': rewrite.original_payload_sha256,
                'rewrittenPayloadSha256': rewrite.rewritten_payload_sha256,
                'clientSideReady': self.client_side_aes_key is not None,
                'serverSideReady': self.server_side_aes_key is not None,
                'clientSideAesKeySha256': _sha256(self.client_side_aes_key) if self.client_side_aes_key is not None else None,
                'serverSideAesKeySha256': _sha256(self.server_side_aes_key) if self.server_side_aes_key is not None else None,
            },
        )

    def _process_encrypted_packet(self, *, direction: str, payload: bytes) -> SplitDhProcessResult | None:
        """Translate encrypted Photon messages once both sides have negotiated keys."""
        targets = find_encrypted_message_targets(payload)
        if not targets:
            return None
        source_key, target_key = self._translation_keys(direction)
        if source_key is None or target_key is None:
            target = targets[0]
            return SplitDhProcessResult(
                payload=payload,
                rewritten=False,
                event={
                    'eventType': 'encrypted_translate',
                    'direction': str(direction),
                    'messageType': target.message_type,
                    'status': 'missing_keys',
                    'encryptedPayloadOffset': target.encrypted_payload_offset,
                    'encryptedPayloadLength': target.encrypted_payload_length,
                    'commandIndex': target.command_index,
                    'commandOffset': target.command_offset,
                    'commandLength': target.command_length,
                    'clientSideReady': self.client_side_aes_key is not None,
                    'serverSideReady': self.server_side_aes_key is not None,
                },
            )
        result = translate_encrypted_messages(payload, source_key=source_key, target_key=target_key, direction=direction, on_key_sync=self.on_key_sync, on_decrypted_payload=self.on_decrypted_payload)
        first_event = result.events[0] if result.events else None
        if first_event is not None:
            additional = tuple(result.events[1:])
        else:
            additional = tuple(result.events)
        return SplitDhProcessResult(
            payload=result.payload,
            rewritten=result.translated,
            event=first_event,
            additional_events=additional,
        )

    def _process_fragment_packet(self, *, direction: str, payload: bytes) -> SplitDhProcessResult | None:
        """Buffer fragmented Photon payloads until enough commands have arrived."""
        parsed = _fragment_commands(payload)
        if not parsed.fragment_command_seen:
            return None
        if parsed.malformed:
            self._discard_fragment_direction(direction, reason='malformed_fragment')
            return _fragment_rejected_result(direction=direction, payload=payload, reason='malformed_fragment')
        commands = parsed.commands
        fragment_identities = {(c.command_channel_id, c.start_sequence) for c in commands}
        if len(fragment_identities) != 1:
            for command_channel_id, start_sequence in fragment_identities:
                self._retire_fragment_segment((str(direction), int(command_channel_id), int(start_sequence)), reason='multiple_fragment_sequences')
            return _fragment_rejected_result(direction=direction, payload=payload, reason='multiple_fragment_sequences')
        command = commands[0]
        key = (str(direction), int(command.command_channel_id), int(command.start_sequence))
        for fragment in commands:
            invalid_reason = _fragment_command_error(fragment)
            if invalid_reason is not None:
                self._retire_fragment_segment(key, reason=invalid_reason)
                return _fragment_rejected_result(direction=direction, payload=payload, reason=invalid_reason)
            if fragment.fragment_count != command.fragment_count or fragment.total_length != command.total_length:
                self._retire_fragment_segment(key, reason='metadata_mismatch')
                return _fragment_rejected_result(direction=direction, payload=payload, reason='metadata_mismatch')
        segment = self._fragment_segments.get(key)
        if segment is None:
            if not self._retire_fragment_segments_for_capacity(command.total_length):
                return _fragment_rejected_result(direction=direction, payload=payload, reason='capacity')
            try:
                fragment_payload = bytearray(command.total_length)
            except (MemoryError, OverflowError):
                return _fragment_rejected_result(direction=direction, payload=payload, reason='allocation_failed')
            segment = _FragmentSegment(fragment_count=command.fragment_count, total_length=command.total_length, payload=fragment_payload)
            self._fragment_segments[key] = segment
            self._pending_fragment_bytes += command.total_length
        else:
            if segment.fragment_count != command.fragment_count or segment.total_length != command.total_length:
                self._retire_fragment_segment(key, reason='metadata_mismatch')
                return _fragment_rejected_result(direction=direction, payload=payload, reason='metadata_mismatch')
        for fragment in commands:
            end = fragment.fragment_offset + fragment.fragment_length
            fragment_data = bytes(payload[fragment.chunk_offset:fragment.chunk_offset + fragment.fragment_length])
            existing = segment.fragments.get(fragment.fragment_number)
            if existing is not None:
                if existing.offset == fragment.fragment_offset and existing.data == fragment_data:
                    continue
                self._retire_fragment_segment(key, reason='conflicting_retransmission')
                return _fragment_rejected_result(direction=direction, payload=payload, reason='conflicting_retransmission')
            offset_index = bisect_left(segment.fragment_offsets, fragment.fragment_offset)
            previous_piece = segment.fragments_by_offset[segment.fragment_offsets[offset_index - 1]] if offset_index > 0 else None
            next_piece = segment.fragments_by_offset[segment.fragment_offsets[offset_index]] if offset_index < len(segment.fragment_offsets) else None
            if previous_piece is not None and previous_piece.offset + len(previous_piece.data) > fragment.fragment_offset:
                self._retire_fragment_segment(key, reason='overlap')
                return _fragment_rejected_result(direction=direction, payload=payload, reason='overlap')
            if next_piece is not None and end > next_piece.offset:
                self._retire_fragment_segment(key, reason='overlap')
                return _fragment_rejected_result(direction=direction, payload=payload, reason='overlap')
            piece = _FragmentPiece(offset=fragment.fragment_offset, data=fragment_data)
            segment.payload[fragment.fragment_offset:end] = fragment_data
            segment.bytes_written += fragment.fragment_length
            segment.fragments[fragment.fragment_number] = piece
            segment.fragment_offsets.insert(offset_index, fragment.fragment_offset)
            segment.fragments_by_offset[fragment.fragment_offset] = piece
        if not self._retain_fragment_packet(key=key, segment=segment, payload=payload, commands=commands):
            self._retire_fragment_segment(key, reason='retained_packet_capacity')
            return _fragment_rejected_result(direction=direction, payload=payload, reason='retained_packet_capacity')
        if len(segment.fragments) < segment.fragment_count:
            return SplitDhProcessResult(payload=b'', rewritten=False, delayed=True)
        if segment.bytes_written != segment.total_length or _fragment_segment_has_gap(segment):
            self._retire_fragment_segment(key, reason='fragment_gap')
            return _fragment_rejected_result(direction=direction, payload=payload, reason='fragment_gap')
        self._retire_fragment_segment(key, reason=None)
        source_key, target_key = self._translation_keys(direction)
        assembled_payload = bytes(segment.payload)
        events: list[dict[str, Any]] = []
        translated_payload = assembled_payload
        segment_rewritten = False
        message_type: int | None = int(assembled_payload[1]) if len(assembled_payload) >= 2 else None
        if message_type in ENCRYPTED_MESSAGE_TYPES:
            if source_key is None or target_key is None:
                events.append({
                    'eventType': 'encrypted_translate',
                    'direction': str(direction),
                    'messageType': message_type,
                    'status': 'missing_keys',
                    'transport': 'fragment',
                    'commandChannelId': command.command_channel_id,
                    'startSequence': command.start_sequence,
                    'totalLength': command.total_length,
                    'clientSideReady': self.client_side_aes_key is not None,
                    'serverSideReady': self.server_side_aes_key is not None,
                })
            else:
                translation = translate_encrypted_reliable_payload(
                    assembled_payload,
                    source_key=source_key,
                    target_key=target_key,
                    direction=direction,
                    event_context={'transport': 'fragment', 'commandChannelId': command.command_channel_id, 'startSequence': command.start_sequence, 'totalLength': command.total_length},
                    on_key_sync=self.on_key_sync,
                    on_decrypted_payload=self.on_decrypted_payload,
                )
                translated_payload = translation.payload
                segment_rewritten = translation.translated
                events.extend(translation.events)
        output_payloads: list[bytes] = []
        rewritten = segment_rewritten
        for packet in segment.packets:
            rewritten_packet = bytearray(packet.payload)
            for fragment in packet.commands:
                start = fragment.fragment_offset
                end = start + fragment.fragment_length
                if start < 0 or end > len(translated_payload):
                    continue
                rewritten_packet[fragment.chunk_offset:fragment.chunk_offset + fragment.fragment_length] = translated_payload[start:end]
            packet_payload = bytes(rewritten_packet)
            encrypted_result = self._process_encrypted_packet(direction=direction, payload=packet_payload)
            if encrypted_result is not None:
                packet_payload = encrypted_result.payload
                rewritten = rewritten or encrypted_result.rewritten
                events.extend(encrypted_result.events)
            output_payloads.append(packet_payload)
        first_event = events[0] if events else None
        payload_out = output_payloads[0] if output_payloads else b''
        extra = tuple(output_payloads[1:])
        if first_event is not None:
            additional = tuple(events[1:])
        else:
            additional = tuple(events)
        return SplitDhProcessResult(
            payload=payload_out,
            rewritten=rewritten,
            event=first_event,
            extra_payloads=extra,
            additional_events=additional,
        )

    def _retire_fragment_segments_for_capacity(self, total_length: int) -> bool:
        """Evict older fragment segments until the session can accept a new assembly."""
        if self._fragment_segments:
            if len(self._fragment_segments) >= MAX_PENDING_FRAGMENT_SEGMENTS or self._pending_fragment_bytes + total_length > MAX_PENDING_FRAGMENT_BYTES:
                # Drop the oldest incomplete work first so newer packets can still be processed.
                while self._fragment_segments:
                    oldest_key = next(iter(self._fragment_segments))
                    self._retire_fragment_segment(oldest_key, reason='assembly_capacity_eviction')
                    if not self._fragment_segments:
                        break
                    if len(self._fragment_segments) >= MAX_PENDING_FRAGMENT_SEGMENTS:
                        continue
                    if self._pending_fragment_bytes + total_length > MAX_PENDING_FRAGMENT_BYTES:
                        continue
                    break
        return len(self._fragment_segments) < MAX_PENDING_FRAGMENT_SEGMENTS and self._pending_fragment_bytes + total_length <= MAX_PENDING_FRAGMENT_BYTES

    def _retain_fragment_packet(self, *, key: tuple[str, int, int], segment: _FragmentSegment, payload: bytes, commands: tuple[_FragmentCommand, ...]) -> bool:
        """Keep a copy of a raw packet for later reassembly and retransmit diagnostics."""
        if payload in segment.packet_payloads:
            return True
        packet_length = len(payload)
        if segment.retained_packet_count + 1 > MAX_RETAINED_FRAGMENT_PACKETS_PER_SEGMENT or segment.retained_packet_bytes + packet_length > MAX_RETAINED_FRAGMENT_PACKET_BYTES_PER_SEGMENT:
            return False
        if self._fragment_segments:
            if self._pending_fragment_packet_count + 1 > MAX_PENDING_FRAGMENT_PACKET_COUNT or self._pending_fragment_packet_bytes + packet_length > MAX_PENDING_FRAGMENT_PACKET_BYTES:
                # If the global retained-packet budget is full, discard older segments to keep the session alive.
                while self._fragment_segments:
                    try:
                        oldest_other_key = next(c for c in self._fragment_segments if c != key)
                    except StopIteration:
                        oldest_other_key = None
                    if oldest_other_key is None:
                        break
                    self._retire_fragment_segment(oldest_other_key, reason='retained_packet_capacity_eviction')
                    if self._pending_fragment_packet_count + 1 > MAX_PENDING_FRAGMENT_PACKET_COUNT:
                        continue
                    if self._pending_fragment_packet_bytes + packet_length > MAX_PENDING_FRAGMENT_PACKET_BYTES:
                        continue
                    break
        if self._pending_fragment_packet_count + 1 > MAX_PENDING_FRAGMENT_PACKET_COUNT or self._pending_fragment_packet_bytes + packet_length > MAX_PENDING_FRAGMENT_PACKET_BYTES:
            return False
        segment.packets.append(_BufferedFragmentPacket(payload=payload, commands=commands))
        segment.packet_payloads.add(payload)
        segment.retained_packet_count += 1
        segment.retained_packet_bytes += packet_length
        self._pending_fragment_packet_count += 1
        self._pending_fragment_packet_bytes += packet_length
        return True

    def _retire_fragment_segment(self, key: tuple[str, int, int], *, reason: str | None = None) -> _FragmentSegment | None:
        """Remove a fragment segment from active tracking and account for any retained packet data."""
        segment = self._fragment_segments.pop(key, None)
        if segment is None:
            return None
        self._pending_fragment_bytes -= segment.total_length
        self._pending_fragment_packet_count -= segment.retained_packet_count
        self._pending_fragment_packet_bytes -= segment.retained_packet_bytes
        if reason is not None and segment.retained_packet_count:
            self._fragment_stream_losses.append(_FragmentStreamLoss(reason=str(reason), retired_packet_count=segment.retained_packet_count, retired_packet_bytes=segment.retained_packet_bytes))
        return segment

    def _discard_fragment_direction(self, direction: str, *, reason: str) -> None:
        """Drop all fragment assemblies associated with one traffic direction."""
        normalized_direction = str(direction)
        for key in tuple(self._fragment_segments):
            if key[0] == normalized_direction:
                self._retire_fragment_segment(key, reason=reason)

    def _attach_fragment_stream_loss(self, *, direction: str, result: SplitDhProcessResult) -> SplitDhProcessResult:
        """Add a stream-loss diagnostic when fragments were rejected or retired mid-flight."""
        losses = tuple(self._fragment_stream_losses)
        self._fragment_stream_losses.clear()
        if not losses:
            return result
        reasons = {loss.reason for loss in losses}
        reason = next(iter(reasons)) if len(reasons) == 1 else 'multiple_segment_retirements'
        stream_loss_event = {
            'eventType': 'fragment_transport',
            'direction': str(direction),
            'status': 'stream_lost',
            'reason': reason,
            'retiredSegmentCount': len(losses),
            'retiredPacketCount': sum(loss.retired_packet_count for loss in losses),
            'retiredPacketBytes': sum(loss.retired_packet_bytes for loss in losses),
        }
        return SplitDhProcessResult(
            payload=result.payload,
            rewritten=result.rewritten,
            event=result.event,
            delayed=result.delayed,
            extra_payloads=result.extra_payloads,
            additional_events=(*result.additional_events, stream_loss_event),
            transport_stream_lost=True,
        )

    def _translation_keys(self, direction: str) -> tuple[bytes | None, bytes | None]:
        """Return the AES keys needed to translate traffic in the given direction."""
        if direction == 'client_to_upstream':
            return (self.client_side_aes_key, self.server_side_aes_key)
        if direction == 'upstream_to_client':
            return (self.server_side_aes_key, self.client_side_aes_key)
        return (None, None)

    def _replacement_public_value(self, message_type: int) -> bytes:
        """Select the proxy public value that should replace the observed peer value."""
        if message_type == 6:
            return self.public_for_server
        if message_type == 7:
            return self.public_for_client
        raise ValueError(f'unsupported split-DH messageType {message_type}')


def _expected_message_type_for_direction(direction: str) -> int | None:
    """Map each relay direction to the public-value message type we expect to see."""
    if direction == 'client_to_upstream':
        return 6
    if direction == 'upstream_to_client':
        return 7
    return None


def _random_private_value() -> int:
    """Generate a valid private DH exponent inside the protocol's allowed range."""
    return secrets.randbelow(MODP_768_PRIME - 3) + 2


def _fragment_commands(payload: bytes) -> _FragmentParse:
    """Parse fragment-related Photon commands from a raw packet for reassembly."""
    if len(payload) < 12:
        return _FragmentParse(commands=(), fragment_command_seen=False, malformed=False)
    commands: list[_FragmentCommand] = []
    command_count = payload[3]
    offset = 12
    fragment_command_seen = False
    for command_index in range(command_count):
        if offset + COMMAND_HEADER_LENGTH > len(payload):
            return _FragmentParse(commands=tuple(commands), fragment_command_seen=fragment_command_seen, malformed=fragment_command_seen)
        command_type = int(payload[offset])
        is_fragment = command_type == CMD_SEND_FRAGMENT
        fragment_command_seen = fragment_command_seen or is_fragment
        command_length = int.from_bytes(payload[offset + 4:offset + 8], 'big')
        if command_length < COMMAND_HEADER_LENGTH or offset + command_length > len(payload):
            return _FragmentParse(commands=tuple(commands), fragment_command_seen=fragment_command_seen, malformed=is_fragment or bool(commands))
        command_payload_offset = offset + COMMAND_HEADER_LENGTH
        command_payload_length = command_length - COMMAND_HEADER_LENGTH
        if is_fragment:
            if command_payload_length < FRAGMENT_HEADER_LENGTH:
                return _FragmentParse(commands=tuple(commands), fragment_command_seen=True, malformed=True)
            fragment_header = command_payload_offset
            chunk_offset = fragment_header + FRAGMENT_HEADER_LENGTH
            fragment_length = command_payload_length - FRAGMENT_HEADER_LENGTH
            commands.append(_FragmentCommand(
                command_index=command_index,
                command_offset=offset,
                command_length=command_length,
                command_channel_id=int(payload[offset + 1]),
                start_sequence=int.from_bytes(payload[fragment_header:fragment_header + 4], 'big'),
                fragment_count=int.from_bytes(payload[fragment_header + 4:fragment_header + 8], 'big'),
                fragment_number=int.from_bytes(payload[fragment_header + 8:fragment_header + 12], 'big'),
                total_length=int.from_bytes(payload[fragment_header + 12:fragment_header + 16], 'big'),
                fragment_offset=int.from_bytes(payload[fragment_header + 16:fragment_header + 20], 'big'),
                fragment_length=fragment_length,
                chunk_offset=chunk_offset,
            ))
        offset += command_length
    return _FragmentParse(commands=tuple(commands), fragment_command_seen=fragment_command_seen, malformed=fragment_command_seen and offset != len(payload))


def _fragment_command_error(fragment: _FragmentCommand) -> str | None:
    """Validate one fragment command and return a compact error reason if malformed."""
    if not 1 <= fragment.fragment_count <= MAX_FRAGMENT_COUNT:
        return 'fragment_count'
    if fragment.fragment_number >= fragment.fragment_count:
        return 'fragment_number'
    if not 1 <= fragment.total_length <= MAX_REASSEMBLED_MESSAGE_SIZE:
        return 'total_length'
    if fragment.fragment_length <= 0:
        return 'empty_fragment'
    if fragment.fragment_offset + fragment.fragment_length > fragment.total_length:
        return 'fragment_bounds'
    return None


def _fragment_segment_has_gap(segment: _FragmentSegment) -> bool:
    """Check whether the assembled fragment offsets leave a gap in the message."""
    cursor = 0
    for offset in segment.fragment_offsets:
        if offset != cursor:
            return True
        cursor += len(segment.fragments_by_offset[offset].data)
    return cursor != segment.total_length


def _fragment_rejected_result(*, direction: str, payload: bytes, reason: str) -> SplitDhProcessResult:
    """Create a consistent diagnostic result when fragment assembly fails."""
    return SplitDhProcessResult(
        payload=payload,
        rewritten=False,
        event={
            'eventType': 'encrypted_translate',
            'direction': str(direction),
            'status': 'fragment_rejected',
            'reason': str(reason),
        },
    )


def _sha256(payload: bytes) -> str:
    """Return a compact SHA-256 fingerprint for logging and diagnostics."""
    return f'sha256:{hashlib.sha256(payload).hexdigest()}'
