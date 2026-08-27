"""Small immutable SDK exposed to Agent-authored traffic transforms.

The SDK deliberately contains no networking, filesystem, process, or dynamic
code helpers. The parent runner and the Go gateway still validate every result.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple


@dataclass(frozen=True)
class Header:
    name: str
    value: str


def _headers(values: Iterable[Header | tuple[str, str]]) -> Tuple[Header, ...]:
    result = []
    for value in values:
        if isinstance(value, Header):
            result.append(value)
        else:
            name, header_value = value
            result.append(Header(str(name), str(header_value)))
    return tuple(result)


@dataclass(frozen=True)
class Message:
    kind: str
    body: bytes
    headers: Tuple[Header, ...] = ()
    method: str = ""
    path: str = ""
    status: int = 0
    complete: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "body", bytes(self.body))
        object.__setattr__(self, "headers", _headers(self.headers))

    def header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        for header in reversed(self.headers):
            if header.name.lower() == name.lower():
                return header.value
        return default

    def header_values(self, name: str) -> Tuple[str, ...]:
        return tuple(header.value for header in self.headers if header.name.lower() == name.lower())

    def header_base64(self, name: str) -> bytes:
        value = self.header(name)
        if value is None:
            raise ValueError(f"missing header {name}")
        return base64.b64decode(value, validate=True)

    def with_body(self, body: bytes, content_type: Optional[str] = None) -> "Message":
        updated = replace(self, body=bytes(body), complete=True)
        if content_type is not None:
            updated = updated.set_header("Content-Type", content_type)
        return updated

    def set_header(self, name: str, value: str) -> "Message":
        kept = tuple(header for header in self.headers if header.name.lower() != name.lower())
        return replace(self, headers=kept + (Header(name, value),))

    def add_header(self, name: str, value: str) -> "Message":
        return replace(self, headers=self.headers + (Header(name, value),))

    def remove_header(self, name: str) -> "Message":
        return replace(self, headers=tuple(header for header in self.headers if header.name.lower() != name.lower()))


class Context:
    __slots__ = (
        "transaction_id", "conversation_id", "direction", "scheme", "host",
        "port", "method", "path", "content_type", "timestamp", "_config", "_state",
    )

    def __init__(self, raw: Mapping[str, Any], state: Mapping[str, Any]) -> None:
        self.transaction_id = str(raw.get("transactionId", ""))
        self.conversation_id = str(raw.get("conversationId", ""))
        self.direction = str(raw.get("direction", ""))
        self.scheme = str(raw.get("scheme", ""))
        self.host = str(raw.get("host", ""))
        self.port = int(raw.get("port", 0))
        self.method = str(raw.get("method", ""))
        self.path = str(raw.get("path", ""))
        self.content_type = str(raw.get("contentType", ""))
        self.timestamp = str(raw.get("timestamp", ""))
        self._config = MappingProxyType(dict(raw.get("config") or {}))
        self._state = MappingProxyType(dict(state or {}))

    @property
    def config(self) -> Mapping[str, Any]:
        return self._config

    @property
    def state(self) -> Mapping[str, Any]:
        return self._state

    def config_value(self, name: str, default: Any = None) -> Any:
        return self._config.get(name, default)

    def config_bytes(self, name: str, default: Optional[bytes] = None, encoding: str = "base64") -> bytes:
        value = self._config.get(name)
        if value is None:
            if default is None:
                raise ValueError(f"missing transform config {name}")
            return bytes(default)
        if isinstance(value, bytes):
            return bytes(value)
        if not isinstance(value, str):
            raise TypeError(f"transform config {name} must be a string")
        if encoding == "base64":
            return base64.b64decode(value, validate=True)
        if encoding == "hex":
            return bytes.fromhex(value)
        if encoding == "utf8":
            return value.encode("utf-8")
        raise ValueError(f"unsupported config encoding {encoding}")


@dataclass(frozen=True)
class Annotation:
    key: str
    value: str


@dataclass(frozen=True)
class Result:
    action: str = "pass"
    message: Optional[Message] = None
    annotations: Tuple[Annotation, ...] = ()
    state_patch: Optional[Mapping[str, Any]] = None
    error_code: str = ""
    error_message: str = ""

    @classmethod
    def replace(
        cls,
        message: Message,
        annotations: Sequence[Annotation] = (),
        state_patch: Optional[Mapping[str, Any]] = None,
    ) -> "Result":
        return cls("replace", message, tuple(annotations), state_patch)

    @classmethod
    def block(cls, annotations: Sequence[Annotation] = ()) -> "Result":
        return cls("block", None, tuple(annotations))

    @classmethod
    def error(cls, code: str, message: str) -> "Result":
        return cls("error", None, (), None, code, message)


def message_from_wire(raw: Mapping[str, Any]) -> Message:
    body = raw.get("body") or {}
    if body.get("encoding") != "base64":
        raise ValueError("wire body encoding must be base64")
    content = base64.b64decode(body.get("data", ""), validate=True)
    if len(content) != int(body.get("length", -1)):
        raise ValueError("wire body length mismatch")
    if hashlib.sha256(content).hexdigest() != body.get("sha256"):
        raise ValueError("wire body digest mismatch")
    return Message(
        kind=str(raw.get("kind", "")),
        method=str(raw.get("method", "")),
        path=str(raw.get("path", "")),
        status=int(raw.get("status", 0)),
        headers=tuple(Header(str(item.get("name", "")), str(item.get("value", ""))) for item in raw.get("headers") or []),
        body=content,
        complete=bool(body.get("complete", False)),
    )


def message_to_wire(message: Message) -> dict[str, Any]:
    content = bytes(message.body)
    return {
        "kind": message.kind,
        "method": message.method,
        "path": message.path,
        "status": message.status,
        "headers": [{"name": item.name, "value": item.value} for item in message.headers],
        "body": {
            "encoding": "base64",
            "data": base64.b64encode(content).decode("ascii"),
            "length": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "complete": message.complete,
        },
    }


def result_to_wire(value: Any, protocol_version: str, invocation_id: str) -> dict[str, Any]:
    if value is None:
        result = Result()
    elif isinstance(value, Message):
        result = Result.replace(value)
    elif isinstance(value, Result):
        result = value
    else:
        raise TypeError("transform hook must return Message, Result, or None")

    wire: dict[str, Any] = {
        "protocolVersion": protocol_version,
        "invocationId": invocation_id,
        "action": result.action,
    }
    if result.message is not None:
        wire["message"] = message_to_wire(result.message)
    if result.annotations:
        wire["annotations"] = [{"key": item.key, "value": item.value} for item in result.annotations]
    if result.state_patch is not None:
        wire["statePatch"] = dict(result.state_patch)
    if result.action == "error":
        wire["error"] = {"code": result.error_code, "message": result.error_message}
    return wire
