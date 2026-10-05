"""Strict and live deserialization for the Photon value model.

This module understands the custom type tags used by the Photon protocol: small
integers, strings, arrays, dictionaries, and operation payloads. The reader is
split into a permissive runtime path for live decoding and a stricter path used
for validation and safety checks around message limits.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from typing import Any

from ass_radar.photon.types import ByteArray, EventData, OperationRequest, OperationResponse

TYPE_UNKNOWN = 0
TYPE_BOOLEAN = 2
TYPE_BYTE = 3
TYPE_SHORT = 4
TYPE_FLOAT = 5
TYPE_DOUBLE = 6
TYPE_STRING = 7
TYPE_NULL = 8
TYPE_COMPRESSED_INT = 9
TYPE_COMPRESSED_LONG = 10
TYPE_INT1 = 11
TYPE_INT1_NEG = 12
TYPE_INT2 = 13
TYPE_INT2_NEG = 14
TYPE_LONG1 = 15
TYPE_LONG1_NEG = 16
TYPE_LONG2 = 17
TYPE_LONG2_NEG = 18
TYPE_CUSTOM = 19
TYPE_DICTIONARY = 20
TYPE_HASHTABLE = 21
TYPE_OBJECT_ARRAY = 23
TYPE_OPERATION_REQUEST = 24
TYPE_OPERATION_RESPONSE = 25
TYPE_EVENT_DATA = 26
TYPE_BOOL_FALSE = 27
TYPE_BOOL_TRUE = 28
TYPE_SHORT_ZERO = 29
TYPE_INT_ZERO = 30
TYPE_LONG_ZERO = 31
TYPE_FLOAT_ZERO = 32
TYPE_DOUBLE_ZERO = 33
TYPE_BYTE_ZERO = 34
TYPE_ARRAY = 64
CUSTOM_TYPE_SLIM_BASE = 128
MAX_ARRAY_SIZE = 65536
MAX_STRICT_DECODE_DEPTH = 64


class PhotonDecodeError(ValueError):
    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code if code else message


@dataclass(frozen=True)
class PhotonDecodeLimits:
    max_message_bytes: int = 1048576
    max_values: int = 4096
    max_depth: int = 64

    def __post_init__(self) -> None:
        values = (self.max_message_bytes, self.max_values, self.max_depth)
        if any(type(value) is not int or value < 0 for value in values):
            raise ValueError('Photon decode limits must be non-negative integers')
        if self.max_depth > MAX_STRICT_DECODE_DEPTH:
            raise ValueError(f'max_depth must not exceed {MAX_STRICT_DECODE_DEPTH}')


LIVE_DECODE_LIMITS = PhotonDecodeLimits()


class _Reader:
    def __init__(self, data: bytes, limits: PhotonDecodeLimits | None = None) -> None:
        if limits is not None and len(data) > limits.max_message_bytes:
            raise _strict_decode_error('message_size_limit')
        self._data = memoryview(data)
        self.offset = 0
        self._limits = limits
        self._values_claimed = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self.offset

    def read(self, count: int) -> bytes:
        if count <= 0:
            return b''
        end = min(len(self._data), self.offset + count)
        chunk = self._data[self.offset:end].tobytes()
        self.offset = end
        return chunk

    def read_byte(self) -> int:
        if self.remaining <= 0:
            return 0
        value = self._data[self.offset]
        self.offset += 1
        return int(value)

    def claim_values(self, count: int) -> None:
        if self._limits is None:
            return
        if count < 0 or count > self._limits.max_values - self._values_claimed:
            raise _strict_decode_error('value_limit')
        self._values_claimed += count

    def check_depth(self, depth: int) -> None:
        if self._limits is not None and depth > self._limits.max_depth:
            raise _strict_decode_error('depth_limit')


class _StrictReader:
    def __init__(self, data: bytes) -> None:
        self._data = memoryview(data)
        self.offset = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self.offset

    def read_exact(self, count: int) -> bytes:
        if count < 0 or count > self.remaining:
            raise _strict_decode_error('truncated_value')
        end = self.offset + count
        chunk = self._data[self.offset:end].tobytes()
        self.offset = end
        return chunk

    def read_byte(self) -> int:
        if self.remaining < 1:
            raise _strict_decode_error('truncated_value')
        value = self._data[self.offset]
        self.offset += 1
        return int(value)


@dataclass
class _StrictDecodeContext:
    reader: _StrictReader
    limits: PhotonDecodeLimits
    values_claimed: int = 0

    def claim_values(self, count: int) -> None:
        if count < 0 or count > self.limits.max_values - self.values_claimed:
            raise _strict_decode_error('value_limit')
        self.values_claimed += count

    def check_depth(self, depth: int) -> None:
        if depth > self.limits.max_depth:
            raise _strict_decode_error('depth_limit')


def read_compressed_uint32(reader: _Reader) -> int:
    value = 0
    shift = 0
    while True:
        if reader.remaining <= 0:
            return 0
        byte = reader.read_byte()
        value |= (byte & 127) << shift
        if byte & 128 == 0:
            return value & 0xFFFFFFFF
        shift += 7
        if shift >= 35:
            return 0


def read_compressed_uint64(reader: _Reader) -> int:
    value = 0
    shift = 0
    while True:
        if reader.remaining <= 0:
            return 0
        byte = reader.read_byte()
        value |= (byte & 127) << shift
        if byte & 128 == 0:
            return value & 0xFFFFFFFFFFFFFFFF
        shift += 7
        if shift >= 70:
            return 0


def read_compressed_int32(reader: _Reader) -> int:
    value = read_compressed_uint32(reader)
    decoded = value >> 1 ^ -(value & 1)
    return _int32(decoded)


def read_compressed_int64(reader: _Reader) -> int:
    value = read_compressed_uint64(reader)
    decoded = value >> 1 ^ -(value & 1)
    return _int64(decoded)


def read_int16(reader: _Reader) -> int:
    data = reader.read(2)
    if len(data) < 2:
        return 0
    return struct.unpack('<h', data)[0]


def read_uint16(reader: _Reader) -> int:
    data = reader.read(2)
    if len(data) < 2:
        return 0
    return struct.unpack('<H', data)[0]


def read_float32(reader: _Reader) -> float:
    data = reader.read(4)
    if len(data) < 4:
        return 0
    return struct.unpack('<f', data)[0]


def read_float64(reader: _Reader) -> float:
    data = reader.read(8)
    if len(data) < 8:
        return 0
    return struct.unpack('<d', data)[0]


def read_string(reader: _Reader) -> str:
    length = read_compressed_uint32(reader)
    if length <= 0 or length > reader.remaining:
        return ''
    return reader.read(length).decode('utf-8', errors='replace')


def deserialize_value(reader: _Reader, type_code: int, *, depth: int = 0) -> Any:
    """Decode one Photon-typed value from the current reader position.

    The function resolves the raw type code into Python objects while enforcing the
    configured depth and value limits so malformed payloads fail safely instead of
    exhausting memory or recursing deeply.
    """
    reader.check_depth(depth)
    if type_code >= CUSTOM_TYPE_SLIM_BASE:
        return _deserialize_custom(reader, type_code)
    if type_code in (TYPE_UNKNOWN, TYPE_NULL):
        return None
    if type_code == TYPE_BOOLEAN:
        return reader.read_byte() != 0
    if type_code == TYPE_BYTE:
        return reader.read_byte()
    if type_code == TYPE_SHORT:
        return read_int16(reader)
    if type_code == TYPE_FLOAT:
        return read_float32(reader)
    if type_code == TYPE_DOUBLE:
        return read_float64(reader)
    if type_code == TYPE_STRING:
        return read_string(reader)
    if type_code == TYPE_COMPRESSED_INT:
        return read_compressed_int32(reader)
    if type_code == TYPE_COMPRESSED_LONG:
        return read_compressed_int64(reader)
    if type_code == TYPE_INT1:
        return _int32(reader.read_byte())
    if type_code == TYPE_INT1_NEG:
        return _int32(-reader.read_byte())
    if type_code == TYPE_INT2:
        return _int32(read_uint16(reader))
    if type_code == TYPE_INT2_NEG:
        return _int32(-read_uint16(reader))
    if type_code == TYPE_LONG1:
        return _int64(reader.read_byte())
    if type_code == TYPE_LONG1_NEG:
        return _int64(-reader.read_byte())
    if type_code == TYPE_LONG2:
        return _int64(read_uint16(reader))
    if type_code == TYPE_LONG2_NEG:
        return _int64(-read_uint16(reader))
    if type_code == TYPE_CUSTOM:
        return _deserialize_custom(reader, 0)
    if type_code == TYPE_DICTIONARY:
        return _deserialize_dictionary(reader, depth=depth)
    if type_code == TYPE_HASHTABLE:
        return _deserialize_dictionary(reader, depth=depth)
    if type_code == TYPE_OBJECT_ARRAY:
        return _deserialize_object_array(reader, depth=depth)
    if type_code == TYPE_OPERATION_REQUEST:
        return _deserialize_operation_request_inner(reader, depth=depth)
    if type_code == TYPE_OPERATION_RESPONSE:
        return _deserialize_operation_response_inner(reader, depth=depth)
    if type_code == TYPE_EVENT_DATA:
        return _deserialize_event_data_inner(reader, depth=depth)
    if type_code == TYPE_BOOL_FALSE:
        return False
    if type_code == TYPE_BOOL_TRUE:
        return True
    if type_code == TYPE_SHORT_ZERO:
        return 0
    if type_code == TYPE_INT_ZERO:
        return 0
    if type_code == TYPE_LONG_ZERO:
        return 0
    if type_code == TYPE_FLOAT_ZERO:
        return 0.0
    if type_code == TYPE_DOUBLE_ZERO:
        return 0.0
    if type_code == TYPE_BYTE_ZERO:
        return 0
    if type_code == TYPE_ARRAY:
        return _deserialize_nested_array(reader, depth=depth)
    if type_code & TYPE_ARRAY == TYPE_ARRAY:
        return _deserialize_typed_array(reader, type_code & ~TYPE_ARRAY, depth=depth)
    return None


def deserialize_event(data: bytes, limits: PhotonDecodeLimits | None = None) -> EventData:
    if len(data) < 1:
        raise PhotonDecodeError(f'event payload too short: {len(data)}')
    reader = _Reader(data, limits)
    code = reader.read_byte()
    return EventData(code=code, parameters=_read_parameter_table(reader, depth=0))


def deserialize_request(data: bytes, limits: PhotonDecodeLimits | None = None) -> OperationRequest:
    if len(data) < 1:
        raise PhotonDecodeError(f'request payload too short: {len(data)}')
    reader = _Reader(data, limits)
    operation_code = reader.read_byte()
    return OperationRequest(operation_code=operation_code, parameters=_read_parameter_table(reader, depth=0))


def deserialize_response(data: bytes, limits: PhotonDecodeLimits | None = None) -> OperationResponse:
    if len(data) < 3:
        raise PhotonDecodeError(f'response payload too short: {len(data)}')
    reader = _Reader(data, limits)
    operation_code = reader.read_byte()
    return_code = read_int16(reader)
    debug_message = ''
    market_orders = None
    if reader.remaining > 0:
        reader.claim_values(1)
        debug_type = reader.read_byte()
        debug_value = deserialize_value(reader, debug_type, depth=1)
        if isinstance(debug_value, str):
            debug_message = debug_value
        elif isinstance(debug_value, list) and all(isinstance(item, str) for item in debug_value):
            market_orders = debug_value
    parameters = _read_parameter_table(reader, depth=0)
    if market_orders is not None:
        parameters[0] = market_orders
    return OperationResponse(operation_code=operation_code, return_code=return_code, debug_message=debug_message, parameters=parameters)


def deserialize_event_live(data: bytes) -> EventData:
    return deserialize_event(data, LIVE_DECODE_LIMITS)


def deserialize_request_live(data: bytes) -> OperationRequest:
    return deserialize_request(data, LIVE_DECODE_LIMITS)


def deserialize_response_live(data: bytes) -> OperationResponse:
    return deserialize_response(data, LIVE_DECODE_LIMITS)


def deserialize_event_strict(data: bytes, limits: PhotonDecodeLimits | None = None) -> EventData:
    context = _strict_context(data, limits)
    code = context.reader.read_byte()
    event = EventData(code=code, parameters=_read_parameter_table_strict(context, depth=0))
    _require_strict_end(context.reader)
    return event


def deserialize_request_strict(data: bytes, limits: PhotonDecodeLimits | None = None) -> OperationRequest:
    context = _strict_context(data, limits)
    operation_code = context.reader.read_byte()
    request = OperationRequest(operation_code=operation_code, parameters=_read_parameter_table_strict(context, depth=0))
    _require_strict_end(context.reader)
    return request


def deserialize_response_strict(data: bytes, limits: PhotonDecodeLimits | None = None) -> OperationResponse:
    context = _strict_context(data, limits)
    operation_code = context.reader.read_byte()
    return_code = _read_int16_strict(context.reader)
    context.claim_values(1)
    debug_value = _deserialize_value_strict(context, context.reader.read_byte(), depth=1)
    debug_message = debug_value if isinstance(debug_value, str) else ''
    market_orders = None
    if isinstance(debug_value, list) and all(isinstance(item, str) for item in debug_value):
        market_orders = debug_value
    parameters = _read_parameter_table_strict(context, depth=0)
    if market_orders is not None:
        if 0 in parameters:
            raise _strict_decode_error('duplicate_key')
        parameters[0] = market_orders
    response = OperationResponse(operation_code=operation_code, return_code=return_code, debug_message=debug_message, parameters=parameters)
    _require_strict_end(context.reader)
    return response


def to_jsonable(value: Any) -> Any:
    if isinstance(value, ByteArray):
        return value.to_json_value()
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    return value


def _deserialize_custom(reader: _Reader, gp_type: int) -> ByteArray | None:
    if gp_type < CUSTOM_TYPE_SLIM_BASE:
        reader.read_byte()
    size = read_compressed_uint32(reader)
    if size < 0 or size > reader.remaining or size > MAX_ARRAY_SIZE:
        return None
    return ByteArray(reader.read(size))


def _deserialize_dictionary(reader: _Reader, *, depth: int) -> dict[Any, Any]:
    key_type = reader.read_byte()
    value_type = reader.read_byte()
    count = read_compressed_uint32(reader)
    if count < 0 or count > MAX_ARRAY_SIZE or count > reader.remaining:
        return {}
    reader.claim_values(2 * count)
    if count:
        reader.check_depth(depth + 1)
    result: dict[Any, Any] = {}
    for index in range(count):
        if reader.remaining <= 0:
            break
        if not key_type:
            item_key_type = reader.read_byte()
        else:
            item_key_type = key_type
        if not value_type:
            item_value_type = reader.read_byte()
        else:
            item_value_type = value_type
        key = deserialize_value(reader, item_key_type, depth=depth + 1)
        value = deserialize_value(reader, item_value_type, depth=depth + 1)
        try:
            hash(key)
        except TypeError:
            key = f'UNHASHABLE_{index}_{type(key).__name__}'
        result[key] = value
    return result


def _deserialize_object_array(reader: _Reader, *, depth: int) -> list[Any] | None:
    size = read_compressed_uint32(reader)
    if size < 0 or size > MAX_ARRAY_SIZE or size > reader.remaining:
        return None
    reader.claim_values(size)
    if size:
        reader.check_depth(depth + 1)
    result: list[Any] = []
    for _ in range(size):
        if reader.remaining <= 0:
            break
        result.append(deserialize_value(reader, reader.read_byte(), depth=depth + 1))
    return result


def _deserialize_operation_request_inner(reader: _Reader, *, depth: int) -> dict[str, Any]:
    operation_code = reader.read_byte()
    return {'operationCode': operation_code, 'parameters': _read_parameter_table(reader, depth=depth)}


def _deserialize_operation_response_inner(reader: _Reader, *, depth: int) -> dict[str, Any] | None:
    if reader.remaining < 3:
        return None
    operation_code = reader.read_byte()
    return_code = read_int16(reader)
    debug_message = ''
    if reader.remaining > 0:
        reader.claim_values(1)
        value = deserialize_value(reader, reader.read_byte(), depth=depth + 1)
        if isinstance(value, str):
            debug_message = value
    return {'operationCode': operation_code, 'returnCode': return_code, 'debugMessage': debug_message, 'parameters': _read_parameter_table(reader, depth=depth)}


def _deserialize_event_data_inner(reader: _Reader, *, depth: int) -> dict[str, Any]:
    code = reader.read_byte()
    return {'code': code, 'parameters': _read_parameter_table(reader, depth=depth)}


def _deserialize_nested_array(reader: _Reader, *, depth: int) -> list[Any] | None:
    size = read_compressed_uint32(reader)
    if size < 0 or size > MAX_ARRAY_SIZE or size > reader.remaining:
        return None
    reader.claim_values(size)
    if size:
        reader.check_depth(depth + 1)
    return [deserialize_value(reader, reader.read_byte(), depth=depth + 1) for _ in range(size)]


def _deserialize_typed_array(reader: _Reader, element_type: int, *, depth: int) -> Any:
    size = read_compressed_uint32(reader)
    if size < 0 or size > MAX_ARRAY_SIZE:
        return None
    reader.claim_values(size)
    if size:
        reader.check_depth(depth + 1)
    if element_type == TYPE_BOOLEAN:
        packed = reader.read((size + 7) // 8)
        return [bool((packed[index // 8] & (1 << (index % 8))) != 0) for index in range(size)]
    if element_type == TYPE_BYTE:
        return ByteArray(reader.read(size))
    if element_type == TYPE_SHORT:
        return [read_int16(reader) for _ in range(size)]
    if element_type == TYPE_FLOAT:
        return [read_float32(reader) for _ in range(size)]
    if element_type == TYPE_DOUBLE:
        return [read_float64(reader) for _ in range(size)]
    if element_type == TYPE_STRING:
        return [read_string(reader) for _ in range(size)]
    if element_type == TYPE_COMPRESSED_INT:
        return [read_compressed_int32(reader) for _ in range(size)]
    if element_type == TYPE_COMPRESSED_LONG:
        return [read_compressed_int64(reader) for _ in range(size)]
    if element_type == TYPE_DICTIONARY:
        return [_deserialize_dictionary(reader, depth=depth + 1) for _ in range(size)]
    if element_type == TYPE_HASHTABLE:
        return [_deserialize_dictionary(reader, depth=depth + 1) for _ in range(size)]
    if element_type == TYPE_CUSTOM:
        reader.read_byte()
        result: list[ByteArray] = []
        for _ in range(size):
            item_size = read_compressed_uint32(reader)
            if item_size < 0 or item_size > reader.remaining or item_size > MAX_ARRAY_SIZE:
                return None
            result.append(ByteArray(reader.read(item_size)))
        return result
    return [deserialize_value(reader, element_type, depth=depth + 1) for _ in range(size)]


def _read_parameter_table(reader: _Reader, *, depth: int) -> dict[int, Any]:
    count = read_compressed_uint32(reader)
    if count < 0 or count > MAX_ARRAY_SIZE or count > reader.remaining:
        return {}
    reader.claim_values(count)
    if count:
        reader.check_depth(depth + 1)
    parameters: dict[int, Any] = {}
    for _ in range(count):
        if reader.remaining <= 0:
            break
        key = reader.read_byte()
        if reader.remaining <= 0:
            break
        type_code = reader.read_byte()
        parameters[key] = deserialize_value(reader, type_code, depth=depth + 1)
    return parameters


_STRICT_DIRECT_TYPES = frozenset({
    TYPE_UNKNOWN,
    TYPE_BOOLEAN,
    TYPE_BYTE,
    TYPE_SHORT,
    TYPE_FLOAT,
    TYPE_DOUBLE,
    TYPE_STRING,
    TYPE_NULL,
    TYPE_COMPRESSED_INT,
    TYPE_COMPRESSED_LONG,
    TYPE_INT1,
    TYPE_INT1_NEG,
    TYPE_INT2,
    TYPE_INT2_NEG,
    TYPE_LONG1,
    TYPE_LONG1_NEG,
    TYPE_LONG2,
    TYPE_LONG2_NEG,
    TYPE_CUSTOM,
    TYPE_DICTIONARY,
    TYPE_HASHTABLE,
    TYPE_OBJECT_ARRAY,
    TYPE_OPERATION_REQUEST,
    TYPE_OPERATION_RESPONSE,
    TYPE_EVENT_DATA,
    TYPE_BOOL_FALSE,
    TYPE_BOOL_TRUE,
    TYPE_SHORT_ZERO,
    TYPE_INT_ZERO,
    TYPE_LONG_ZERO,
    TYPE_FLOAT_ZERO,
    TYPE_DOUBLE_ZERO,
    TYPE_BYTE_ZERO,
})


def _strict_decode_error(code: str) -> PhotonDecodeError:
    return PhotonDecodeError(code, code=code)


def _strict_context(data: bytes, limits: PhotonDecodeLimits | None = None) -> _StrictDecodeContext:
    resolved_limits = limits if limits is not None else PhotonDecodeLimits()
    if len(data) > resolved_limits.max_message_bytes:
        raise _strict_decode_error('message_size_limit')
    return _StrictDecodeContext(reader=_StrictReader(data), limits=resolved_limits)


def _require_strict_end(reader: _StrictReader) -> None:
    if reader.remaining != 0:
        raise _strict_decode_error('trailing_bytes')


def _require_supported_type(type_code: int) -> None:
    if type_code >= CUSTOM_TYPE_SLIM_BASE:
        return
    if type_code in _STRICT_DIRECT_TYPES:
        return
    if type_code == TYPE_ARRAY:
        return
    if type_code & TYPE_ARRAY == TYPE_ARRAY and (type_code & ~TYPE_ARRAY) in _STRICT_DIRECT_TYPES:
        return
    raise _strict_decode_error('unsupported_type')


def _read_bounded_varint(reader: _StrictReader, max_bytes: int, final_byte_mask: int) -> int:
    value = 0
    for index in range(max_bytes):
        if reader.remaining == 0:
            raise _strict_decode_error('invalid_varint')
        byte = reader.read_byte()
        if index == max_bytes - 1 and (byte & ~final_byte_mask) != 0:
            raise _strict_decode_error('invalid_varint')
        value |= (byte & 127) << (index * 7)
        if byte & 128 == 0:
            return value
    raise _strict_decode_error('invalid_varint')


def _read_compressed_uint32_strict(reader: _StrictReader) -> int:
    return _read_bounded_varint(reader, max_bytes=5, final_byte_mask=15)


def _read_compressed_uint64_strict(reader: _StrictReader) -> int:
    return _read_bounded_varint(reader, max_bytes=10, final_byte_mask=1)


def _read_compressed_int32_strict(reader: _StrictReader) -> int:
    value = _read_compressed_uint32_strict(reader)
    return _int32(value >> 1 ^ -(value & 1))


def _read_compressed_int64_strict(reader: _StrictReader) -> int:
    value = _read_compressed_uint64_strict(reader)
    return _int64(value >> 1 ^ -(value & 1))


def _read_int16_strict(reader: _StrictReader) -> int:
    return struct.unpack('<h', reader.read_exact(2))[0]


def _read_uint16_strict(reader: _StrictReader) -> int:
    return struct.unpack('<H', reader.read_exact(2))[0]


def _read_float32_strict(reader: _StrictReader) -> float:
    return struct.unpack('<f', reader.read_exact(4))[0]


def _read_float64_strict(reader: _StrictReader) -> float:
    return struct.unpack('<d', reader.read_exact(8))[0]


def _read_string_strict(reader: _StrictReader) -> str:
    length = _read_compressed_uint32_strict(reader)
    encoded = reader.read_exact(length)
    try:
        return encoded.decode('utf-8')
    except UnicodeDecodeError:
        raise _strict_decode_error('invalid_utf8')


def _deserialize_value_strict(context: _StrictDecodeContext, type_code: int, *, depth: int) -> Any:
    context.check_depth(depth)
    _require_supported_type(type_code)
    reader = context.reader
    if type_code >= CUSTOM_TYPE_SLIM_BASE:
        return _deserialize_custom_strict(reader, gp_type=type_code)
    if type_code in (TYPE_UNKNOWN, TYPE_NULL):
        return None
    if type_code == TYPE_BOOLEAN:
        return reader.read_byte() != 0
    if type_code == TYPE_BYTE:
        return reader.read_byte()
    if type_code == TYPE_SHORT:
        return _read_int16_strict(reader)
    if type_code == TYPE_FLOAT:
        return _read_float32_strict(reader)
    if type_code == TYPE_DOUBLE:
        return _read_float64_strict(reader)
    if type_code == TYPE_STRING:
        return _read_string_strict(reader)
    if type_code == TYPE_COMPRESSED_INT:
        return _read_compressed_int32_strict(reader)
    if type_code == TYPE_COMPRESSED_LONG:
        return _read_compressed_int64_strict(reader)
    if type_code == TYPE_INT1:
        return _int32(reader.read_byte())
    if type_code == TYPE_INT1_NEG:
        return _int32(-reader.read_byte())
    if type_code == TYPE_INT2:
        return _int32(_read_uint16_strict(reader))
    if type_code == TYPE_INT2_NEG:
        return _int32(-_read_uint16_strict(reader))
    if type_code == TYPE_LONG1:
        return _int64(reader.read_byte())
    if type_code == TYPE_LONG1_NEG:
        return _int64(-reader.read_byte())
    if type_code == TYPE_LONG2:
        return _int64(_read_uint16_strict(reader))
    if type_code == TYPE_LONG2_NEG:
        return _int64(-_read_uint16_strict(reader))
    if type_code == TYPE_CUSTOM:
        return _deserialize_custom_strict(reader, gp_type=0)
    if type_code in (TYPE_DICTIONARY, TYPE_HASHTABLE):
        return _deserialize_dictionary_strict(context, depth=depth)
    if type_code == TYPE_OBJECT_ARRAY:
        return _deserialize_object_array_strict(context, depth=depth)
    if type_code == TYPE_OPERATION_REQUEST:
        return _deserialize_operation_request_inner_strict(context, depth=depth)
    if type_code == TYPE_OPERATION_RESPONSE:
        return _deserialize_operation_response_inner_strict(context, depth=depth)
    if type_code == TYPE_EVENT_DATA:
        return _deserialize_event_data_inner_strict(context, depth=depth)
    if type_code == TYPE_BOOL_FALSE:
        return False
    if type_code == TYPE_BOOL_TRUE:
        return True
    if type_code in (TYPE_SHORT_ZERO, TYPE_INT_ZERO, TYPE_LONG_ZERO, TYPE_BYTE_ZERO):
        return 0
    if type_code in (TYPE_FLOAT_ZERO, TYPE_DOUBLE_ZERO):
        return 0.0
    if type_code == TYPE_ARRAY:
        return _deserialize_nested_array_strict(context, depth=depth)
    return _deserialize_typed_array_strict(context, element_type=type_code & ~TYPE_ARRAY, depth=depth)


def _deserialize_custom_strict(reader: _StrictReader, gp_type: int) -> ByteArray:
    if gp_type < CUSTOM_TYPE_SLIM_BASE:
        reader.read_byte()
    size = _read_compressed_uint32_strict(reader)
    return ByteArray(reader.read_exact(size))


def _deserialize_dictionary_strict(context: _StrictDecodeContext, *, depth: int) -> dict[Any, Any]:
    reader = context.reader
    key_type = reader.read_byte()
    value_type = reader.read_byte()
    if key_type:
        _require_supported_type(key_type)
    if value_type:
        _require_supported_type(value_type)
    count = _read_compressed_uint32_strict(reader)
    context.claim_values(2 * count)
    if count:
        context.check_depth(depth + 1)
    result: dict[Any, Any] = {}
    for _ in range(count):
        if not key_type:
            item_key_type = reader.read_byte()
        else:
            item_key_type = key_type
        if not value_type:
            item_value_type = reader.read_byte()
        else:
            item_value_type = value_type
        key = _deserialize_value_strict(context, item_key_type, depth=depth + 1)
        try:
            hash(key)
        except TypeError:
            raise _strict_decode_error('invalid_dictionary_key')
        if key in result:
            raise _strict_decode_error('duplicate_key')
        value = _deserialize_value_strict(context, item_value_type, depth=depth + 1)
        result[key] = value
    return result


def _deserialize_object_array_strict(context: _StrictDecodeContext, *, depth: int) -> list[Any]:
    size = _read_compressed_uint32_strict(context.reader)
    context.claim_values(size)
    if size:
        context.check_depth(depth + 1)
    result: list[Any] = []
    for _ in range(size):
        type_code = context.reader.read_byte()
        result.append(_deserialize_value_strict(context, type_code, depth=depth + 1))
    return result


def _deserialize_operation_request_inner_strict(context: _StrictDecodeContext, *, depth: int) -> dict[str, Any]:
    operation_code = context.reader.read_byte()
    return {'operationCode': operation_code, 'parameters': _read_parameter_table_strict(context, depth=depth)}


def _deserialize_operation_response_inner_strict(context: _StrictDecodeContext, *, depth: int) -> dict[str, Any]:
    operation_code = context.reader.read_byte()
    return_code = _read_int16_strict(context.reader)
    context.claim_values(1)
    debug_value = _deserialize_value_strict(context, context.reader.read_byte(), depth=depth + 1)
    debug_message = debug_value if isinstance(debug_value, str) else ''
    return {'operationCode': operation_code, 'returnCode': return_code, 'debugMessage': debug_message, 'parameters': _read_parameter_table_strict(context, depth=depth)}


def _deserialize_event_data_inner_strict(context: _StrictDecodeContext, *, depth: int) -> dict[str, Any]:
    code = context.reader.read_byte()
    return {'code': code, 'parameters': _read_parameter_table_strict(context, depth=depth)}


def _deserialize_nested_array_strict(context: _StrictDecodeContext, *, depth: int) -> list[Any]:
    size = _read_compressed_uint32_strict(context.reader)
    context.claim_values(size)
    if size:
        context.check_depth(depth + 1)
    return [_deserialize_value_strict(context, context.reader.read_byte(), depth=depth + 1) for _ in range(size)]


def _deserialize_typed_array_strict(context: _StrictDecodeContext, element_type: int, *, depth: int) -> Any:
    reader = context.reader
    size = _read_compressed_uint32_strict(reader)
    context.claim_values(size)
    if size:
        context.check_depth(depth + 1)
    _require_supported_type(element_type)
    if element_type == TYPE_BOOLEAN:
        packed = reader.read_exact((size + 7) // 8)
        return [bool((packed[index // 8] & (1 << (index % 8))) != 0) for index in range(size)]
    if element_type == TYPE_BYTE:
        return ByteArray(reader.read_exact(size))
    if element_type == TYPE_SHORT:
        return [_read_int16_strict(reader) for _ in range(size)]
    if element_type == TYPE_FLOAT:
        return [_read_float32_strict(reader) for _ in range(size)]
    if element_type == TYPE_DOUBLE:
        return [_read_float64_strict(reader) for _ in range(size)]
    if element_type == TYPE_STRING:
        return [_read_string_strict(reader) for _ in range(size)]
    if element_type == TYPE_COMPRESSED_INT:
        return [_read_compressed_int32_strict(reader) for _ in range(size)]
    if element_type == TYPE_COMPRESSED_LONG:
        return [_read_compressed_int64_strict(reader) for _ in range(size)]
    if element_type == TYPE_CUSTOM:
        reader.read_byte()
        return [ByteArray(reader.read_exact(_read_compressed_uint32_strict(reader))) for _ in range(size)]
    return [_deserialize_value_strict(context, element_type, depth=depth + 1) for _ in range(size)]


def _read_parameter_table_strict(context: _StrictDecodeContext, *, depth: int) -> dict[int, Any]:
    count = _read_compressed_uint32_strict(context.reader)
    context.claim_values(count)
    if count:
        context.check_depth(depth + 1)
    parameters: dict[int, Any] = {}
    for _ in range(count):
        key = context.reader.read_byte()
        if key in parameters:
            raise _strict_decode_error('duplicate_key')
        type_code = context.reader.read_byte()
        parameters[key] = _deserialize_value_strict(context, type_code, depth=depth + 1)
    return parameters


def _int32(value: int) -> int:
    value &= 0xFFFFFFFF
    if value & 0x80000000:
        value -= 0x100000000
    return value


def _int64(value: int) -> int:
    value &= 0xFFFFFFFFFFFFFFFF
    if value & 0x8000000000000000:
        value -= 0x10000000000000000
    return value


def is_finite_float(value: float) -> bool:
    return not math.isnan(value) and not math.isinf(value)
