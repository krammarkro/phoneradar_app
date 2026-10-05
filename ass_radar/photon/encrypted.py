"""Encryption translation and key-sync extraction for Photon traffic.

The helpers in this module reinterpret encrypted relay traffic by decrypting the
payload with the source key, inspecting it for key-sync markers, and then
re-encrypting it with the target key. This allows the relay layer to safely
rewrite encrypted packets without losing the original protocol semantics.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Callable

from Crypto.Cipher import AES

from ass_radar.photon.keysync import is_key_sync_event_code
from ass_radar.photon.deserializer import deserialize_event_live, deserialize_request_live, deserialize_response_live
from ass_radar.photon.packet import ENCRYPTED_MESSAGE_TYPES
from ass_radar.photon.types import ByteArray

CMD_SEND_RELIABLE = 6
CMD_SEND_UNRELIABLE = 7
AES_BLOCK_SIZE = 16


@dataclass(frozen=True)
class EncryptedMessageTarget:
    message_type: int
    encrypted_payload_offset: int
    encrypted_payload_length: int
    command_index: int
    command_offset: int
    command_length: int

    @property
    def encrypted_payload_slice(self) -> slice:
        return slice(self.encrypted_payload_offset, self.encrypted_payload_offset + self.encrypted_payload_length)


@dataclass(frozen=True)
class EncryptedTranslationResult:
    payload: bytes
    translated: bool
    events: list[dict[str, Any]]


@dataclass(frozen=True)
class ReliablePayloadTranslationResult:
    payload: bytes
    translated: bool
    events: list[dict[str, Any]]


@dataclass(frozen=True)
class KeySyncExtraction:
    xor_code: bytes
    safe_summary: dict[str, Any]


def translate_encrypted_messages(
    payload: bytes,
    *,
    source_key: bytes,
    target_key: bytes,
    direction: str,
    on_key_sync: Callable[[KeySyncExtraction], None] | None = None,
    on_decrypted_payload: Callable[[bytes, int, str], None] | None = None,
) -> EncryptedTranslationResult:
    """Rewrite encrypted packet payloads from one AES key to another.

    Each encrypted message is decrypted with the source key, optionally scanned for
    key-sync markers, and then re-encrypted with the target key before being written
    back into the original packet stream.
    """
    _require_aes_key(source_key, name="source_key")
    _require_aes_key(target_key, name="target_key")
    rewritten = bytearray(payload)
    translated = False
    events: list[dict[str, Any]] = []
    for target in find_encrypted_message_targets(payload):
        ciphertext = payload[target.encrypted_payload_slice]
        base_event = _event_base(direction=direction, target=target, ciphertext=ciphertext)
        if len(ciphertext) == 0 or len(ciphertext) % AES_BLOCK_SIZE != 0:
            events.append({**base_event, **{"status": "not_block_aligned"}})
            continue
        plaintext = _aes_cbc_zero_iv_decrypt(source_key, ciphertext)
        translated_ciphertext = _aes_cbc_zero_iv_encrypt(target_key, plaintext)
        if on_decrypted_payload is not None:
            on_decrypted_payload(plaintext, target.message_type, direction)
        key_sync_extractions = extract_key_sync_codes(plaintext, outer_message_type=target.message_type)
        if on_key_sync is not None:
            for extraction in key_sync_extractions:
                on_key_sync(extraction)
        rewritten[target.encrypted_payload_slice] = translated_ciphertext
        translated = True
        event: dict[str, Any] = {
            **base_event,
            **{
                "status": "translated",
                "translatedCiphertextSha256": _sha256(translated_ciphertext),
                "decryptedPayloadSha256": _sha256(plaintext),
                "decryptedProbe": probe_decrypted_payload(plaintext, outer_message_type=target.message_type),
                "sourceAesKeySha256": _sha256(source_key),
                "targetAesKeySha256": _sha256(target_key),
            },
        }
        if key_sync_extractions:
            event["keySyncExtractions"] = [extraction.safe_summary for extraction in key_sync_extractions]
        events.append(event)
    return EncryptedTranslationResult(payload=bytes(rewritten), translated=translated, events=events)


def translate_encrypted_reliable_payload(
    payload: bytes,
    *,
    source_key: bytes,
    target_key: bytes,
    direction: str,
    event_context: dict[str, Any] | None = None,
    on_key_sync: Callable[[KeySyncExtraction], None] | None = None,
    on_decrypted_payload: Callable[[bytes, int, str], None] | None = None,
) -> ReliablePayloadTranslationResult:
    _require_aes_key(source_key, name="source_key")
    _require_aes_key(target_key, name="target_key")
    if len(payload) < 2:
        return ReliablePayloadTranslationResult(payload=payload, translated=False, events=[])
    message_type = int(payload[1])
    if message_type not in ENCRYPTED_MESSAGE_TYPES:
        return ReliablePayloadTranslationResult(payload=payload, translated=False, events=[])
    ciphertext = payload[2:]
    base_event: dict[str, Any] = {
        "eventType": "encrypted_translate",
        "direction": str(direction),
        "messageType": message_type,
        "encryptedPayloadOffset": 2,
        "encryptedPayloadLength": len(ciphertext),
        "ciphertextSha256": _sha256(ciphertext),
    }
    if event_context:
        base_event.update(event_context)
    if len(ciphertext) == 0 or len(ciphertext) % AES_BLOCK_SIZE != 0:
        return ReliablePayloadTranslationResult(
            payload=payload,
            translated=False,
            events=[{**base_event, **{"status": "not_block_aligned"}}],
        )
    plaintext = _aes_cbc_zero_iv_decrypt(source_key, ciphertext)
    translated_ciphertext = _aes_cbc_zero_iv_encrypt(target_key, plaintext)
    if on_decrypted_payload is not None:
        on_decrypted_payload(plaintext, message_type, direction)
    key_sync_extractions = extract_key_sync_codes(plaintext, outer_message_type=message_type)
    if on_key_sync is not None:
        for extraction in key_sync_extractions:
            on_key_sync(extraction)
    event: dict[str, Any] = {
        **base_event,
        **{
            "status": "translated",
            "translatedCiphertextSha256": _sha256(translated_ciphertext),
            "decryptedPayloadSha256": _sha256(plaintext),
            "decryptedProbe": probe_decrypted_payload(plaintext, outer_message_type=message_type),
            "sourceAesKeySha256": _sha256(source_key),
            "targetAesKeySha256": _sha256(target_key),
        },
    }
    if key_sync_extractions:
        event["keySyncExtractions"] = [extraction.safe_summary for extraction in key_sync_extractions]
    return ReliablePayloadTranslationResult(
        payload=payload[:2] + translated_ciphertext,
        translated=True,
        events=[event],
    )


def find_encrypted_message_targets(payload: bytes) -> list[EncryptedMessageTarget]:
    targets: list[EncryptedMessageTarget] = []
    for command in _iter_commands(payload):
        message = _message_from_command(command, payload)
        if message is None or message.message_type not in ENCRYPTED_MESSAGE_TYPES:
            continue
        targets.append(
            EncryptedMessageTarget(
                message_type=message.message_type,
                encrypted_payload_offset=message.payload_offset,
                encrypted_payload_length=message.payload_length,
                command_index=command.command_index,
                command_offset=command.command_offset,
                command_length=command.command_length,
            )
        )
    return targets


def probe_decrypted_payload(payload: bytes, *, outer_message_type: int) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    candidates.extend(_probe_direct_payload(payload))
    if payload:
        candidates.extend(_probe_inner_message(payload))
    key_sync_observed = any(
        item.get("kind") == "event" and is_key_sync_event_code(item.get("realEventCode")) for item in candidates
    )
    return {
        "outerMessageType": int(outer_message_type),
        "payloadLength": len(payload),
        "candidateCount": len(candidates),
        "keySyncCandidateObserved": key_sync_observed,
        "candidates": candidates[:8],
    }


def extract_key_sync_codes(payload: bytes, *, outer_message_type: int) -> list[KeySyncExtraction]:
    extracted: list[KeySyncExtraction] = []
    extracted.extend(_extract_key_sync_from_event("direct_event", payload, outer_message_type=outer_message_type))
    if payload and payload[0] == 4:
        extracted.extend(_extract_key_sync_from_event("inner_event", payload[1:], outer_message_type=outer_message_type))
    return extracted


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


def _probe_direct_payload(payload: bytes) -> list[dict[str, Any]]:
    return [
        *_probe_event("direct_event", payload),
        *_probe_request("direct_request", payload),
        *_probe_response("direct_response", payload),
    ]


def _probe_inner_message(payload: bytes) -> list[dict[str, Any]]:
    inner_type = payload[0]
    inner_payload = payload[1:]
    if inner_type == 2:
        return _probe_request("inner_request", inner_payload)
    if inner_type in frozenset({3, 7}):
        return _probe_response("inner_response", inner_payload)
    if inner_type == 4:
        return _probe_event("inner_event", inner_payload)
    return []


def _probe_event(shape: str, payload: bytes) -> list[dict[str, Any]]:
    try:
        event = deserialize_event_live(payload)
    except Exception:
        return []
    return [
        {
            "shape": shape,
            "kind": "event",
            "eventCode": int(event.code),
            "realEventCode": _int_or_none(event.parameters.get(252)),
            "parameterKeys": _parameter_keys(event.parameters),
            "byteArrayParameterLengths": _byte_array_lengths(event.parameters),
        }
    ]


def _extract_key_sync_from_event(shape: str, payload: bytes, *, outer_message_type: int) -> list[KeySyncExtraction]:
    try:
        event = deserialize_event_live(payload)
    except Exception:
        return []
    real_event_code = _int_or_none(event.parameters.get(252))
    routed_event_code = real_event_code if real_event_code is not None else int(event.code)
    if not is_key_sync_event_code(routed_event_code):
        return []
    xor_code = _raw_bytes(event.parameters.get(0))
    if len(xor_code) != 8:
        return []
    return [
        KeySyncExtraction(
            xor_code=xor_code,
            safe_summary={
                "shape": shape,
                "kind": "event",
                "outerMessageType": int(outer_message_type),
                "eventCode": int(event.code),
                "realEventCode": routed_event_code,
                "parameterKeys": _parameter_keys(event.parameters),
                "byteArrayParameterLengths": _byte_array_lengths(event.parameters),
                "xorCodeParameterKey": 0,
                "xorCodeLength": len(xor_code),
                "xorCodeSha256": _sha256(xor_code),
            },
        )
    ]


def _probe_request(shape: str, payload: bytes) -> list[dict[str, Any]]:
    try:
        request = deserialize_request_live(payload)
    except Exception:
        return []
    return [
        {
            "shape": shape,
            "kind": "request",
            "operationCode": int(request.operation_code),
            "realOperationCode": _int_or_none(request.parameters.get(253)),
            "parameterKeys": _parameter_keys(request.parameters),
            "byteArrayParameterLengths": _byte_array_lengths(request.parameters),
        }
    ]


def _probe_response(shape: str, payload: bytes) -> list[dict[str, Any]]:
    try:
        response = deserialize_response_live(payload)
    except Exception:
        return []
    routed_code = _int_or_none(response.parameters.get(253))
    candidate: dict[str, Any] = {
        "shape": shape,
        "kind": "response",
        "operationCode": int(response.operation_code),
        "realOperationCode": routed_code,
        "returnCode": int(response.return_code),
        "parameterKeys": _parameter_keys(response.parameters),
        "byteArrayParameterLengths": _byte_array_lengths(response.parameters),
    }
    change_cluster = _change_cluster_summary(response)
    if change_cluster:
        candidate["changeCluster"] = change_cluster
    return [candidate]


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
    reliable_offset = command.command_offset + 12
    reliable_length = command.command_length - 12
    if command.command_type == CMD_SEND_UNRELIABLE:
        if reliable_length < 4:
            return None
        reliable_offset += 4
        reliable_length -= 4
    elif command.command_type != CMD_SEND_RELIABLE:
        return None
    if reliable_length < 2:
        return None
    if reliable_offset + reliable_length > len(payload):
        return None
    return _Message(
        message_type=int(payload[reliable_offset + 1]),
        payload_offset=reliable_offset + 2,
        payload_length=reliable_length - 2,
    )


def _parameter_keys(parameters: dict[int, Any]) -> list[int]:
    return sorted(int(key) for key in parameters.keys())[:32]


def _byte_array_lengths(parameters: dict[int, Any]) -> dict[str, int]:
    lengths: dict[str, int] = {}
    for key, value in parameters.items():
        if isinstance(value, (bytes, bytearray, ByteArray)):
            lengths[str(int(key))] = len(value)
    return dict(sorted(lengths.items(), key=lambda item: int(item[0])))


def _change_cluster_summary(response: Any) -> dict[str, Any]:
    routed_code = _int_or_none(response.parameters.get(253))
    if routed_code is None:
        routed_code = int(response.operation_code)
    if routed_code != 41:
        return {}
    map_id = response.parameters.get(0)
    parameter_three = _raw_bytes(response.parameters.get(3))
    summary: dict[str, Any] = {}
    if isinstance(map_id, str):
        summary["mapIdLength"] = len(map_id)
        summary["mapIdKind"] = _map_id_kind(map_id)
    if parameter_three:
        summary["parameter3Length"] = len(parameter_three)
        summary["parameter3Sha256"] = _sha256(parameter_three)
        summary["parameter3LastByte"] = int(parameter_three[-1])
    return summary


def _map_id_kind(value: str) -> str:
    normalized = value.strip().upper()
    if normalized.startswith("@RANDOMDUNGEON@"):
        return "random_dungeon"
    if normalized.startswith("@MISTS@"):
        return "mists"
    if normalized.startswith("TNL-"):
        return "tunnel"
    if normalized:
        return "regular"
    return "empty"


def _raw_bytes(value: object) -> bytes:
    if isinstance(value, (bytes, bytearray, ByteArray)):
        return bytes(value)
    return b""


def _int_or_none(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _event_base(*, direction: str, target: EncryptedMessageTarget, ciphertext: bytes) -> dict[str, Any]:
    return {
        "eventType": "encrypted_translate",
        "direction": str(direction),
        "messageType": target.message_type,
        "encryptedPayloadOffset": target.encrypted_payload_offset,
        "encryptedPayloadLength": target.encrypted_payload_length,
        "commandIndex": target.command_index,
        "commandOffset": target.command_offset,
        "commandLength": target.command_length,
        "ciphertextSha256": _sha256(ciphertext),
    }


def _require_aes_key(key: bytes, *, name: str) -> None:
    if len(key) != 32:
        raise ValueError(f"{name} must be a 32-byte AES-256 key")


def _aes_cbc_zero_iv_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv=bytes(AES_BLOCK_SIZE)).decrypt(ciphertext)


def _aes_cbc_zero_iv_encrypt(key: bytes, plaintext: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv=bytes(AES_BLOCK_SIZE)).encrypt(plaintext)


def _sha256(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"
