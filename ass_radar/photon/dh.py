from __future__ import annotations

import hashlib
from dataclasses import dataclass

MODP_768_PRIME_HEX = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF'
MODP_768_PRIME = int(MODP_768_PRIME_HEX, 16)
MODP_768_BYTE_LENGTH = 96
ALBION_DH_GENERATOR = 22


@dataclass(frozen=True)
class PublicValueValidation:
    valid: bool
    reason: str
    bit_length: int


@dataclass(frozen=True)
class SplitHandshakeSimulation:
    public_for_client: bytes
    public_for_server: bytes
    client_side_secret: bytes
    server_side_secret: bytes
    client_side_aes_key: bytes
    server_side_aes_key: bytes


def public_from_private(private_value: int, *, generator: int = ALBION_DH_GENERATOR) -> bytes:
    private_int = _valid_private(private_value)
    public_int = pow(int(generator), private_int, MODP_768_PRIME)
    return _int_to_fixed(public_int)


def shared_secret_from_public(public_value: bytes, private_value: int) -> bytes:
    validation = validate_public_value(public_value)
    if not validation.valid:
        raise ValueError(f'Invalid DH public value: {validation.reason}')
    private_int = _valid_private(private_value)
    public_int = int.from_bytes(public_value, 'big')
    return _int_to_fixed(pow(public_int, private_int, MODP_768_PRIME))


def derive_aes_key(shared_secret: bytes) -> bytes:
    return hashlib.sha256(shared_secret).digest()


def validate_public_value(public_value: bytes) -> PublicValueValidation:
    if len(public_value) != MODP_768_BYTE_LENGTH:
        return PublicValueValidation(valid=False, reason=f'expected {MODP_768_BYTE_LENGTH} bytes', bit_length=len(public_value) * 8)
    value = int.from_bytes(public_value, 'big')
    bit_length = value.bit_length()
    if value <= 1:
        return PublicValueValidation(valid=False, reason='value must be greater than 1', bit_length=bit_length)
    if value >= MODP_768_PRIME - 1:
        return PublicValueValidation(valid=False, reason='value must be less than p - 1', bit_length=bit_length)
    return PublicValueValidation(valid=True, reason='ok', bit_length=bit_length)


def simulate_split_handshake(*, observed_client_public: bytes, observed_server_public: bytes, proxy_client_side_private: int, proxy_server_side_private: int) -> SplitHandshakeSimulation:
    client_side_secret = shared_secret_from_public(observed_client_public, proxy_client_side_private)
    server_side_secret = shared_secret_from_public(observed_server_public, proxy_server_side_private)
    return SplitHandshakeSimulation(
        public_for_client=public_from_private(proxy_client_side_private),
        public_for_server=public_from_private(proxy_server_side_private),
        client_side_secret=client_side_secret,
        server_side_secret=server_side_secret,
        client_side_aes_key=derive_aes_key(client_side_secret),
        server_side_aes_key=derive_aes_key(server_side_secret),
    )


def _valid_private(private_value: int) -> int:
    value = int(private_value)
    if value <= 1 or value >= MODP_768_PRIME - 1:
        raise ValueError('DH private value must be between 2 and p - 2.')
    return value


def _int_to_fixed(value: int) -> bytes:
    return int(value).to_bytes(MODP_768_BYTE_LENGTH, 'big')
