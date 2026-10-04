import json
import os
import socket
import struct
import threading
import unittest

from civic_orchestrator.broker_protocol import (
    handle_command_connection,
    recv_exact,
)
from civic_orchestrator.participants import MAX_ARTIFACT_BYTES


_FRAME = struct.Struct("!I")
_COMMAND_FRAME = struct.Struct("!II")


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


def command_metadata(
    codename="water-ants",
    arguments=None,
    version=2,
    request_kind="invoke",
):
    if arguments is None:
        arguments = {}
    return json.dumps(
        {
            "protocol_version": version,
            "request_kind": request_kind,
            "codename": codename,
            "arguments": arguments,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def command_frame(
    codename="water-ants",
    payload=b"",
    arguments=None,
    version=2,
    request_kind="invoke",
):
    metadata = command_metadata(codename, arguments, version, request_kind)
    return _COMMAND_FRAME.pack(len(metadata), len(payload)) + metadata + payload


class BrokerProtocolTests(unittest.TestCase):
    def exchange(self, frame_bytes, *, shutdown=False):
        adapter = RecordingCommandAdapter()
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        thread = threading.Thread(
            target=handle_command_connection,
            args=(server, adapter),
        )
        thread.start()
        try:
            client.sendall(frame_bytes)
            if shutdown:
                client.shutdown(socket.SHUT_WR)
            result = receive_json(client)
        finally:
            client.close()
            thread.join(timeout=2)
            server.close()
        return result, adapter

    def test_identity_comes_from_kernel_not_payload(self):
        payload = b'{"caller":{"subject":"operator:root"}}'
        result, adapter = self.exchange(command_frame("water-ants", payload))

        self.assertEqual(result["status"], "stub")
        peer_uid, invocation = adapter.calls[0]
        self.assertEqual(peer_uid, os.getuid())
        self.assertEqual(invocation.payload, payload)

    def test_oversize_payload_is_rejected_before_payload_read(self):
        metadata = command_metadata()
        frame = _COMMAND_FRAME.pack(len(metadata), MAX_ARTIFACT_BYTES + 1)
        result, adapter = self.exchange(frame + metadata)

        self.assertEqual(result["status"], "rejected")
        self.assertFalse(result["remote_dispatch"])
        self.assertFalse(result["side_effects"])
        self.assertIn("exceeds", result["error"])
        self.assertEqual(adapter.calls, [])

    def test_exact_ceiling_payload_is_accepted(self):
        payload = b"\0" * MAX_ARTIFACT_BYTES
        result, adapter = self.exchange(command_frame("water-ants", payload))

        self.assertEqual(result["status"], "stub")
        self.assertEqual(len(adapter.calls[0][1].payload), MAX_ARTIFACT_BYTES)

    def test_empty_payload_is_a_valid_invocation(self):
        result, adapter = self.exchange(command_frame("water-ants", b""))

        self.assertEqual(result["status"], "stub")
        self.assertEqual(adapter.calls[0][1].payload, b"")

    def test_truncated_payload_is_rejected(self):
        metadata = command_metadata()
        frame = _COMMAND_FRAME.pack(len(metadata), 5) + metadata + b"abc"
        result, adapter = self.exchange(frame, shutdown=True)

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
