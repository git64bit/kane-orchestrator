import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from civic_orchestrator.usermin_adapter import (
    DEFAULT_MEDIA_TYPE,
    LocalAdapterError,
    LocalPublicationAdapter,
    MAX_ARTIFACT_BYTES,
    ParticipantRegistry,
    derive_artifact,
)


class UserminAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.registry_path = Path(self.tmp.name) / "participants.json"

    def tearDown(self):
        self.tmp.cleanup()

    def write_registry(self, participants):
        self.registry_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "participants": participants,
                }
            ),
            encoding="utf-8",
        )

    def registry(self):
        return ParticipantRegistry(
            self.registry_path,
            require_secure_file=False,
        )

    def account_patches(self, uid=1002, username="participant1"):
        account = SimpleNamespace(
            pw_name=username,
            pw_gid=1003,
        )
        group = SimpleNamespace(gr_gid=1004)
        return (
            patch(
                "civic_orchestrator.usermin_adapter.pwd.getpwuid",
                return_value=account,
            ),
            patch(
                "civic_orchestrator.usermin_adapter.grp.getgrnam",
                return_value=group,
            ),
            patch(
                "civic_orchestrator.usermin_adapter.os.getgrouplist",
                return_value=[1003, 1004],
            ),
        )

    def test_derive_artifact_is_mechanical_and_content_only(self):
        payload = b"participant bytes\n"
        artifact = derive_artifact(payload)

        self.assertEqual(artifact["media_type"], DEFAULT_MEDIA_TYPE)
        self.assertEqual(artifact["size_bytes"], len(payload))
        self.assertEqual(
            artifact["sha256"],
            hashlib.sha256(payload).hexdigest(),
        )
        self.assertEqual(
            base64.b64decode(artifact["content"]),
            payload,
        )
        self.assertEqual(
            set(artifact),
            {
                "media_type",
                "size_bytes",
                "sha256",
                "encoding",
                "content",
            },
        )

    def test_derive_artifact_rejects_oversize_bytes(self):
        with self.assertRaisesRegex(
            LocalAdapterError,
            "exceeds",
        ):
            derive_artifact(b"x" * (MAX_ARTIFACT_BYTES + 1))

    def test_registry_maps_current_unix_account_to_stable_identity(self):
        self.write_registry(
            [
                {
                    "username": "participant1",
                    "uid": 1002,
                    "participant_id": "participant:550e8400-e29b-41d4-a716-446655440000",
                    "active": True,
                }
            ]
        )
        p1, p2, p3 = self.account_patches()
        with p1, p2, p3:
            identity = self.registry().resolve(1002)

        self.assertEqual(identity.uid, 1002)
        self.assertEqual(identity.username, "participant1")
        self.assertEqual(
            identity.participant_id,
            "participant:550e8400-e29b-41d4-a716-446655440000",
        )

    def test_registry_requires_participant_group_membership(self):
        self.write_registry(
            [
                {
                    "username": "participant1",
                    "uid": 1002,
                    "participant_id": "participant:stable-a",
                    "active": True,
                }
            ]
        )
        account = SimpleNamespace(pw_name="participant1", pw_gid=1003)
        group = SimpleNamespace(gr_gid=1004)
        with (
            patch(
                "civic_orchestrator.usermin_adapter.pwd.getpwuid",
                return_value=account,
            ),
            patch(
                "civic_orchestrator.usermin_adapter.grp.getgrnam",
                return_value=group,
            ),
            patch(
                "civic_orchestrator.usermin_adapter.os.getgrouplist",
                return_value=[1003],
            ),
        ):
            with self.assertRaisesRegex(
                LocalAdapterError,
                "authorized participant group",
            ):
                self.registry().resolve(1002)

    def test_registry_rejects_reused_stable_participant_id(self):
        self.write_registry(
            [
                {
                    "username": "old-account",
                    "uid": 1001,
                    "participant_id": "participant:never-recycle",
                    "active": False,
                },
                {
                    "username": "new-account",
                    "uid": 1002,
                    "participant_id": "participant:never-recycle",
                    "active": True,
                },
            ]
        )
        with self.assertRaisesRegex(
            LocalAdapterError,
            "reused participant_id",
        ):
            self.registry()._load_entries()

    def test_inactive_mapping_is_not_accepted(self):
        self.write_registry(
            [
                {
                    "username": "participant1",
                    "uid": 1002,
                    "participant_id": "participant:retired",
                    "active": False,
                }
            ]
        )
        p1, p2, p3 = self.account_patches()
        with p1, p2, p3:
            with self.assertRaisesRegex(
                LocalAdapterError,
                "no unique active stable participant mapping",
            ):
                self.registry().resolve(1002)

    def test_validation_only_adapter_dispatches_nothing_remote(self):
        self.write_registry(
            [
                {
                    "username": "participant1",
                    "uid": 1002,
                    "participant_id": "participant:stable-a",
                    "active": True,
                }
            ]
        )
        p1, p2, p3 = self.account_patches()
        with p1, p2, p3:
            result = LocalPublicationAdapter(
                self.registry()
            ).handle(1002, b"public bytes")

        self.assertEqual(result["status"], "validated")
        self.assertFalse(result["remote_dispatch"])
        self.assertEqual(
            result["participant_id"],
            "participant:stable-a",
        )
        self.assertEqual(
            result["artifact"]["sha256"],
            hashlib.sha256(b"public bytes").hexdigest(),
        )
        self.assertNotIn("caller", result)
        self.assertNotIn("client", result)
        self.assertNotIn("path", result)


if __name__ == "__main__":
    unittest.main()
