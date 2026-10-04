"""Custom Command broker protocol v2 over AF_UNIX.

Frame (request):  !II  metadata_length, payload_length
                  metadata  UTF-8 JSON object with exactly
                            protocol_version, request_kind, codename, arguments
                  payload   raw bytes
Frame (response): !I   body_length, then a UTF-8 JSON object

The peer's identity is never read from the frame. It is derived from the
kernel with SO_PEERCRED.
"""

from __future__ import annotations

import json
import os
import socket
import struct
from typing import Any

from .custom_commands import (
    CommandInvocation,
    CustomCommandError,
    LocalCustomCommandAdapter,
)
from .participants import LocalAdapterError, MAX_ARTIFACT_BYTES


PROTOCOL_VERSION = 2
_FRAME = struct.Struct("!I")
_COMMAND_FRAME = struct.Struct("!II")
MAX_COMMAND_METADATA_BYTES = 8_192
MAX_RESPONSE_BYTES = 65_536


class BrokerProtocolError(ValueError):
    pass


def recv_exact(conn: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = conn.recv(remaining)
        if not chunk:
            raise BrokerProtocolError("unexpected end of local broker frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_command_invocation(conn: socket.socket) -> CommandInvocation:
    header = recv_exact(conn, _COMMAND_FRAME.size)
    metadata_length, payload_length = _COMMAND_FRAME.unpack(header)

    if metadata_length < 2 or metadata_length > MAX_COMMAND_METADATA_BYTES:
        raise BrokerProtocolError("Custom Command metadata length is invalid")
    if payload_length > MAX_ARTIFACT_BYTES:
        raise BrokerProtocolError(
            f"Custom Command payload exceeds {MAX_ARTIFACT_BYTES} byte limit"
        )

    raw_metadata = recv_exact(conn, metadata_length)
    payload = recv_exact(conn, payload_length)

    try:
        metadata = json.loads(raw_metadata.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerProtocolError("Custom Command metadata is invalid JSON") from exc

    if not isinstance(metadata, dict):
        raise BrokerProtocolError("Custom Command metadata must be an object")
    if set(metadata) != {
        "protocol_version",
        "request_kind",
        "codename",
        "arguments",
    }:
        raise BrokerProtocolError("Custom Command metadata fields are invalid")
    if metadata["protocol_version"] != PROTOCOL_VERSION:
        raise BrokerProtocolError("unsupported Custom Command protocol version")

    request_kind = metadata["request_kind"]
    if request_kind not in {"list", "help", "invoke"}:
        raise BrokerProtocolError("unsupported Custom Command request kind")

    codename = metadata["codename"]
    if request_kind == "list":
        if codename is not None:
            raise BrokerProtocolError(
                "list request must not include a codename"
            )
    elif not isinstance(codename, str):
        raise BrokerProtocolError(
            "help/invoke request requires a codename"
        )

    if not isinstance(metadata["arguments"], dict):
        raise BrokerProtocolError("Custom Command arguments must be an object")

    if request_kind in {"list", "help"}:
        if metadata["arguments"]:
            raise BrokerProtocolError(
                "list/help requests do not accept arguments"
            )
        if payload:
            raise BrokerProtocolError(
                "list/help requests do not accept a payload"
            )

    return CommandInvocation(
        codename=codename,
        arguments=metadata["arguments"],
        payload=payload,
        request_kind=request_kind,
    )


def send_json(conn: socket.socket, value: dict[str, Any]) -> None:
    body = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(body) > MAX_RESPONSE_BYTES:
        raise BrokerProtocolError("local broker response is too large")
    conn.sendall(_FRAME.pack(len(body)))
    conn.sendall(body)


def peer_credentials(conn: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise BrokerProtocolError("SO_PEERCRED is unavailable")
    raw = conn.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        struct.calcsize("3i"),
    )
    return struct.unpack("3i", raw)


def handle_command_connection(
    conn: socket.socket,
    adapter: LocalCustomCommandAdapter,
) -> None:
    try:
        _pid, uid, _gid = peer_credentials(conn)
        invocation = recv_command_invocation(conn)
        response = adapter.handle(uid, invocation)
    except (BrokerProtocolError, LocalAdapterError, CustomCommandError) as exc:
        response = {
            "status": "rejected",
            "remote_dispatch": False,
            "side_effects": False,
            "error": str(exc)[:500],
        }
    except Exception:
        response = {
            "status": "rejected",
            "remote_dispatch": False,
            "side_effects": False,
            "error": "internal local broker error",
        }

    send_json(conn, response)


def systemd_listener() -> socket.socket:
    try:
        listen_pid = int(os.environ.get("LISTEN_PID", "0"))
        listen_fds = int(os.environ.get("LISTEN_FDS", "0"))
    except ValueError as exc:
        raise RuntimeError("invalid systemd socket activation environment") from exc

    if listen_pid != os.getpid() or listen_fds != 1:
        raise RuntimeError(
            "exactly one systemd-activated socket is required"
        )

    return socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)
