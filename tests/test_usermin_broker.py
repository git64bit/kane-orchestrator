import json
import os
import socket
import struct
import threading
import unittest

from civic_orchestrator.usermin_adapter import MAX_ARTIFACT_BYTES
from civic_orchestrator.usermin_broker import (
    handle_command_connection,
    handle_connection,
    recv_exact,
)


_FRAME = struct.Struct("!I")


class RecordingAdapter:
    def __init__(self):
        self.calls = []

    def handle(self, peer_uid, payload):
        self.calls.append((peer_uid, payload))
        return {
            "status": "validated",
            "remote_dispatch": False,
            "size": len(payload),
        }


def receive_json(conn):
    header = recv_exact(conn, _FRAME.size)
    (length,) = _FRAME.unpack(header)
    body = recv_exact(conn, length)
    return json.loads(body.decode("utf-8"))


class RecordingCommandAdapter:
    def __init__(self):
        self.calls = []

    def handle(self, peer_uid, invocation):
        self.calls.append((peer_uid, invocation))
        return {
            "status": "stub",
            "remote_dispatch": False,
            "side_effects": False,
            "command": invocation.codename,
            "size": len(invocation.payload),
        }


def command_frame(
    codename="water-ants",
    payload=b"",
    arguments=None,
    version=2,
    request_kind="invoke",
):
    if arguments is None:
        arguments = {}
    metadata = json.dumps(
        {
            "protocol_version": version,
            "request_kind": request_kind,
            "codename": codename,
            "arguments": arguments,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return struct.Struct("!II").pack(len(metadata), len(payload)) + metadata + payload


class UserminBrokerTests(unittest.TestCase):
    def exchange(self, frame_bytes, adapter=None):
        if adapter is None:
            adapter = RecordingAdapter()
        server, client = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )

        thread = threading.Thread(
            target=handle_connection,
            args=(server, adapter),
        )
        thread.start()
        try:
            client.sendall(frame_bytes)
            result = receive_json(client)
        finally:
            client.close()
            thread.join(timeout=2)
            server.close()
        return result, adapter

    def test_kernel_peer_uid_is_used_with_byte_payload(self):
        payload = b'{"caller":{"subject":"operator:root"}}'
        result, adapter = self.exchange(
            _FRAME.pack(len(payload)) + payload
        )

        self.assertEqual(result["status"], "validated")
        self.assertEqual(len(adapter.calls), 1)
        peer_uid, observed_payload = adapter.calls[0]
        self.assertEqual(peer_uid, os.getuid())
        self.assertEqual(observed_payload, payload)

    def test_oversize_frame_is_rejected_before_payload_read(self):
        result, adapter = self.exchange(
            _FRAME.pack(MAX_ARTIFACT_BYTES + 1)
        )

        self.assertEqual(result["status"], "rejected")
        self.assertFalse(result["remote_dispatch"])
        self.assertIn("exceeds", result["error"])
        self.assertEqual(adapter.calls, [])

    def test_empty_file_is_valid_local_frame(self):
        result, adapter = self.exchange(_FRAME.pack(0))

        self.assertEqual(result["status"], "validated")
        self.assertEqual(adapter.calls[0][1], b"")

    def test_truncated_payload_is_rejected(self):
        server, client = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )
        adapter = RecordingAdapter()
        thread = threading.Thread(
            target=handle_connection,
            args=(server, adapter),
        )
        thread.start()
        try:
            client.sendall(_FRAME.pack(5) + b"abc")
            client.shutdown(socket.SHUT_WR)
            result = receive_json(client)
        finally:
            client.close()
            thread.join(timeout=2)
            server.close()

        self.assertEqual(result["status"], "rejected")
        self.assertIn("unexpected end", result["error"])
        self.assertEqual(adapter.calls, [])

    def test_generic_command_frame_carries_codename_not_identity(self):
        adapter = RecordingCommandAdapter()
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        thread = threading.Thread(
            target=handle_command_connection,
            args=(server, adapter),
        )
        thread.start()
        try:
            client.sendall(command_frame("water-ants", b"abc"))
            result = receive_json(client)
        finally:
            client.close()
            thread.join(timeout=2)
            server.close()

        self.assertEqual(result["status"], "stub")
        self.assertEqual(result["command"], "water-ants")
        self.assertEqual(len(adapter.calls), 1)
        peer_uid, invocation = adapter.calls[0]
        self.assertEqual(peer_uid, os.getuid())
        self.assertEqual(invocation.codename, "water-ants")
        self.assertEqual(invocation.arguments, {})
        self.assertEqual(invocation.payload, b"abc")
        self.assertEqual(invocation.request_kind, "invoke")

    def test_generic_command_frame_rejects_extra_metadata_fields(self):
        metadata = json.dumps(
            {
                "protocol_version": 2,
                "request_kind": "invoke",
                "codename": "water-ants",
                "arguments": {},
                "participant_id": "participant:forged",
            },
            separators=(",", ":"),
        ).encode("utf-8")
        frame = struct.Struct("!II").pack(len(metadata), 0) + metadata
        adapter = RecordingCommandAdapter()
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        thread = threading.Thread(
            target=handle_command_connection,
            args=(server, adapter),
        )
        thread.start()
        try:
            client.sendall(frame)
            result = receive_json(client)
        finally:
            client.close()
            thread.join(timeout=2)
            server.close()

        self.assertEqual(result["status"], "rejected")
        self.assertFalse(result["remote_dispatch"])
        self.assertFalse(result["side_effects"])
        self.assertIn("metadata fields", result["error"])
        self.assertEqual(adapter.calls, [])

    def test_generic_list_frame_has_no_participant_identity(self):
        adapter = RecordingCommandAdapter()
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        thread = threading.Thread(
            target=handle_command_connection,
            args=(server, adapter),
        )
        thread.start()
        try:
            client.sendall(
                command_frame(
                    codename=None,
                    request_kind="list",
                )
            )
            result = receive_json(client)
        finally:
            client.close()
            thread.join(timeout=2)
            server.close()

        self.assertEqual(result["status"], "stub")
        self.assertEqual(len(adapter.calls), 1)
        peer_uid, invocation = adapter.calls[0]
        self.assertEqual(peer_uid, os.getuid())
        self.assertEqual(invocation.request_kind, "list")
        self.assertIsNone(invocation.codename)
        self.assertEqual(invocation.arguments, {})
        self.assertEqual(invocation.payload, b"")

    def test_generic_list_frame_rejects_payload(self):
        adapter = RecordingCommandAdapter()
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        thread = threading.Thread(
            target=handle_command_connection,
            args=(server, adapter),
        )
        thread.start()
        try:
            client.sendall(
                command_frame(
                    codename=None,
                    request_kind="list",
                    payload=b"x",
                )
            )
            result = receive_json(client)
        finally:
            client.close()
            thread.join(timeout=2)
            server.close()

        self.assertEqual(result["status"], "rejected")
        self.assertIn("do not accept a payload", result["error"])
        self.assertEqual(adapter.calls, [])

    def test_generic_command_frame_rejects_wrong_protocol_version(self):
        adapter = RecordingCommandAdapter()
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        thread = threading.Thread(
            target=handle_command_connection,
            args=(server, adapter),
        )
        thread.start()
        try:
            client.sendall(command_frame("water-ants", version=1))
            result = receive_json(client)
        finally:
            client.close()
            thread.join(timeout=2)
            server.close()

        self.assertEqual(result["status"], "rejected")
        self.assertIn("protocol version", result["error"])
        self.assertEqual(adapter.calls, [])


if __name__ == "__main__":
    unittest.main()
