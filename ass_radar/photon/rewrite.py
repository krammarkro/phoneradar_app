from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ass_radar.photon.dh import MODP_768_BYTE_LENGTH, validate_public_value

CMD_SEND_RELIABLE = 6
CMD_SEND_UNRELIABLE = 7


@dataclass(frozen=True)
class PublicValueTarget:
    role: str
    message_type: int
    candidate_offset: int
    candidate_length: int
    command_index: int
    command_offset: int
    command_length: int

    @property
    def candidate_slice(self) -> slice:
        return slice(self.candidate_offset, self.candidate_offset + self.candidate_length)


@dataclass(frozen=True)
class PublicValueRewrite:
    payload: bytes
    target: PublicValueTarget
    original_payload_sha256: str
    rewritten_payload_sha256: str


def find_public_value_target(payload: bytes, *, expected_message_type: int | None = None) -> PublicValueTarget | None:
    for command in _iter_commands(payload):
        message = _message_from_command(command, payload)
        if message is None:
            continue
        message_type = message.message_type
        if expected_message_type is not None and message_type != expected_message_type:
            continue
        shape = _handshake_shape(message_type)
        if shape is None:
            continue
        role, prefix_length = shape
        candidate_offset = message.payload_offset + prefix_length
        candidate_end = candidate_offset + MODP_768_BYTE_LENGTH
        if candidate_end > len(payload) or message.payload_length < prefix_length + MODP_768_BYTE_LENGTH:
            continue
        candidate = payload[candidate_offset:candidate_end]
        if not validate_public_value(candidate).valid:
            continue
        return PublicValueTarget(
            role=role,
            message_type=message_type,
            candidate_offset=candidate_offset,
            candidate_length=MODP_768_BYTE_LENGTH,
            command_index=command.command_index,
            command_offset=command.command_offset,
            command_length=command.command_length,
        )
    return None


def rewrite_public_value(payload: bytes, replacement_public_value: bytes, *, expected_message_type: int | None = None) -> PublicValueRewrite:
    if len(replacement_public_value) != MODP_768_BYTE_LENGTH:
        raise ValueError(f"expected 96-byte DH public value, got {len(replacement_public_value)} bytes")
    validation = validate_public_value(replacement_public_value)
    if not validation.valid:
        raise ValueError(f"invalid replacement DH public value: {validation.reason}")
    target = find_public_value_target(payload, expected_message_type=expected_message_type)
    if target is None and expected_message_type is not None:
        raise ValueError(f"no handshake public value found for expected messageType {expected_message_type}")
    if target is None:
        raise ValueError("no handshake public value found")
    rewritten = bytearray(payload)
    rewritten[target.candidate_slice] = replacement_public_value
    rewritten_payload = bytes(rewritten)
    return PublicValueRewrite(
        payload=rewritten_payload,
        target=target,
        original_payload_sha256=_sha256(payload),
        rewritten_payload_sha256=_sha256(rewritten_payload),
    )


@dataclass(frozen=True)
class _Command:
    command_index: int
    command_offset: int
    command_type: int
    command_channel_id: int
    command_flags: int
    command_length: int
    command_sequence: int


@dataclass(frozen=True)
class _Message:
    message_type: int
    payload_offset: int
    payload_length: int


def _iter_commands(payload: bytes) -> list[_Command]:
    if len(payload) < 12:
        return []
    commands: list[_Command] = []
    command_count = payload[3]
    offset = 12
    for command_index in range(command_count):
        if offset + 12 > len(payload):
            break
        command_length = int.from_bytes(payload[offset + 4 : offset + 8], "big")
        if command_length < 12 or offset + command_length > len(payload):
            break
        commands.append(
            _Command(
                command_index=command_index,
                command_offset=offset,
                command_type=int(payload[offset]),
                command_channel_id=int(payload[offset + 1]),
                command_flags=int(payload[offset + 2]),
                command_length=command_length,
                command_sequence=int.from_bytes(payload[offset + 8 : offset + 12], "big"),
            )
        )
        offset += command_length
    return commands


def _message_from_command(command: _Command, payload: bytes) -> _Message | None:
    command_payload_offset = command.command_offset + 12
    reliable_offset = command_payload_offset
    reliable_length = command.command_length - 12
    if command.command_type == CMD_SEND_UNRELIABLE:
        if reliable_length < 4:
            return None
        reliable_offset += 4
        reliable_length -= 4
    elif command.command_type != CMD_SEND_RELIABLE:
        return None
    if reliable_length < 2 or reliable_offset + reliable_length > len(payload):
        return None
    return _Message(
        message_type=int(payload[reliable_offset + 1]),
        payload_offset=reliable_offset + 2,
        payload_length=reliable_length - 2,
    )


def _handshake_shape(message_type: int) -> tuple[str, int] | None:
    if message_type == 6:
        return ("client_public_value", 5)
    if message_type == 7:
        return ("server_public_value", 8)
    return None


def _sha256(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"
