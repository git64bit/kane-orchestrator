"""Lock the broker protocol v2 responses that kane-civicmin v0.4.0 consumes.

These shapes may change only through a coordinated decision recorded in
both repositories (RFC-0002). Each test drives the real broker connection
handler over an AF_UNIX socket pair with the repository's contracts.
"""

import hashlib
import json
import os
import pwd
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from civic_orchestrator.broker_protocol import handle_command_connection, recv_exact
from civic_orchestrator.custom_command_access import CustomCommandAccessPolicy
from civic_orchestrator.custom_commands import (
    CustomCommandRegistry,
    LocalCustomCommandAdapter,
)
from civic_orchestrator.participants import ParticipantRegistry


ROOT = Path(__file__).resolve().parents[1]
GRANTED = "participant:550e8400-e29b-41d4-a716-446655440000"
_FRAME = struct.Struct("!I")
_COMMAND_FRAME = struct.Struct("!II")

LIST_KEYS = {"status", "remote_dispatch", "side_effects", "participant_id", "commands"}
COMMAND_KEYS = {"codename", "display_name", "lifecycle", "summary", "available_to_run"}
HELP_KEYS = {
    "status", "remote_dispatch", "side_effects", "participant_id",
    "command", "available_to_run", "help",
}
WATER_ANTS_KEYS = {
    "status", "remote_dispatch", "side_effects", "command",
    "operation", "participant_id", "artifact",
}
ARTIFACT_KEYS = {"media_type", "size_bytes", "sha256"}
REJECTED_KEYS = {"status", "remote_dispatch", "side_effects", "error"}


def frame(request_kind, codename=None, payload=b"", arguments=None):
    metadata = json.dumps({
        "protocol_version": 2,
        "request_kind": request_kind,
        "codename": codename,
        "arguments": arguments or {},
    }).encode("utf-8")
    return _COMMAND_FRAME.pack(len(metadata), len(payload)) + metadata + payload


class CivicminContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        uid = os.getuid()
        username = pwd.getpwuid(uid).pw_name
        registry_path = Path(self.tmp.name) / "participants-v1.json"
        registry_path.write_text(json.dumps({
            "version": 1,
            "participants": [{
                "username": username,
                "uid": uid,
                "participant_id": GRANTED,
                "active": True,
            }],
        }))
        self.adapter = LocalCustomCommandAdapter(
            ParticipantRegistry(registry_path, require_secure_file=False),
            CustomCommandRegistry.load(
                ROOT / "contracts" / "custom-command-registry-v1.yaml",
                ROOT / "schemas" / "custom-command-registry-v1.schema.json",
                ROOT / "contracts" / "custom-command-help-v1.yaml",
                ROOT / "schemas" / "custom-command-help-v1.schema.json",
            ),
            CustomCommandAccessPolicy.load(
                ROOT / "INSTALL" / "examples" / "custom-command-access-v1.example.yaml",
                ROOT / "schemas" / "custom-command-access-v1.schema.json",
                require_secure_file=False,
            ),
        )
        account = pwd.getpwuid(uid)
        self.patches = [
            patch("civic_orchestrator.participants.grp.getgrnam",
                  return_value=SimpleNamespace(gr_gid=424242)),
            patch("civic_orchestrator.participants.os.getgrouplist",
                  return_value=[account.pw_gid, 424242]),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in self.patches:
            item.stop()
        self.tmp.cleanup()

    def exchange(self, frame_bytes):
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        thread = threading.Thread(
            target=handle_command_connection, args=(server, self.adapter)
        )
        thread.start()
        try:
            client.sendall(frame_bytes)
            (length,) = _FRAME.unpack(recv_exact(client, _FRAME.size))
            return json.loads(recv_exact(client, length))
        finally:
            client.close()
            thread.join(timeout=2)
            server.close()

    def test_list_shape(self):
        result = self.exchange(frame("list"))
        self.assertEqual(set(result), LIST_KEYS)
        self.assertEqual(result["status"], "ok")
        self.assertIs(result["remote_dispatch"], False)
        self.assertIs(result["side_effects"], False)
        self.assertEqual(result["participant_id"], GRANTED)
        self.assertEqual([c["codename"] for c in result["commands"]], ["water-ants"])
        for command in result["commands"]:
            self.assertEqual(set(command), COMMAND_KEYS)
        self.assertIs(result["commands"][0]["available_to_run"], True)

    def test_help_shape(self):
        result = self.exchange(frame("help", "water-ants"))
        self.assertEqual(set(result), HELP_KEYS)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["command"], "water-ants")
        self.assertIs(result["remote_dispatch"], False)
        self.assertIs(result["side_effects"], False)
        self.assertIsInstance(result["help"], str)

    def test_water_ants_stub_shape(self):
        payload = b"\0" * 262_144
        result = self.exchange(frame("invoke", "water-ants", payload))
        self.assertEqual(set(result), WATER_ANTS_KEYS)
        self.assertEqual(result["status"], "stub")
        self.assertIs(result["remote_dispatch"], False)
        self.assertIs(result["side_effects"], False)
        self.assertEqual(result["command"], "water-ants")
        self.assertEqual(result["operation"], "publication.publish")
        self.assertEqual(result["participant_id"], GRANTED)
        self.assertEqual(set(result["artifact"]), ARTIFACT_KEYS)
        self.assertEqual(result["artifact"]["size_bytes"], 262_144)
        self.assertEqual(result["artifact"]["media_type"], "application/octet-stream")
        # Civicmin v0.4.0 acceptance used this exact all-zero ceiling artifact.
        self.assertEqual(
            result["artifact"]["sha256"],
            "8a39d2abd3999ab73c34db2476849cddf303ce389b35826850f9a700589b4a90",
        )

    def test_water_ants_digest_matches_bytes(self):
        payload = b"civicmin contract bytes"
        result = self.exchange(frame("invoke", "water-ants", payload))
        self.assertEqual(result["artifact"]["sha256"], hashlib.sha256(payload).hexdigest())

    def test_water_ants_rejects_typed_arguments(self):
        result = self.exchange(
            frame("invoke", "water-ants", b"x", arguments={"confirmed": True})
        )
        self.assertEqual(set(result), REJECTED_KEYS)
        self.assertEqual(result["status"], "rejected")
        self.assertIs(result["remote_dispatch"], False)
        self.assertIs(result["side_effects"], False)

    def test_ungranted_command_rejection_shape(self):
        result = self.exchange(frame("help", "navy-roots"))
        self.assertEqual(set(result), REJECTED_KEYS)
        self.assertEqual(result["status"], "rejected")

    def test_water_ants_remains_a_stub_in_the_registry(self):
        registry = self.adapter.command_registry
        command = registry.lookup("water-ants")
        self.assertEqual(command["lifecycle"], "stub")
        self.assertIs(command["side_effects_enabled"], False)


if __name__ == "__main__":
    unittest.main()
