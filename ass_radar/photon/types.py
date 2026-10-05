from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class ByteArray(bytes):
    def __new__(cls, value: bytes | bytearray | list[int] | tuple[int, ...] = b"") -> "ByteArray":
        return super().__new__(cls, bytes(value))

    def to_json_value(self) -> dict[str, Any]:
        return {"type": "Buffer", "data": list(self)}


Buffer = ByteArray


@dataclass
class EventData:
    code: int
    parameters: dict[int, Any] = field(default_factory=dict)


@dataclass
class OperationRequest:
    operation_code: int
    parameters: dict[int, Any] = field(default_factory=dict)


@dataclass
class OperationResponse:
    operation_code: int
    return_code: int
    debug_message: str = ""
    parameters: dict[int, Any] = field(default_factory=dict)
