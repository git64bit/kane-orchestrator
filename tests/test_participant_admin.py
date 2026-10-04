import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from civic_orchestrator.participant_admin import (
    BROKER_SERVICE,
    AdminError,
    AdminPaths,
    ParticipantAdmin,
)


ROOT = Path(__file__).resolve().parents[1]


class ParticipantAdminTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        etc = Path(self.tmp.name).resolve()
        self.paths = AdminPaths(
            registry=etc / "participants-v1.json",
            access_policy=etc / "custom-command-access-v1.yaml",
            access_schema=ROOT / "schemas" / "custom-command-access-v1.schema.json",
            command_registry=ROOT / "contracts" / "custom-command-registry-v1.yaml",
            command_schema=ROOT / "schemas" / "custom-command-registry-v1.schema.json",
            help_catalog=ROOT / "contracts" / "custom-command-help-v1.yaml",
            help_schema=ROOT / "schemas" / "custom-command-help-v1.schema.json",
            lock=etc / ".lock",
        )
        self.commands = []
        self.accounts = {
            "alice": SimpleNamespace(pw_uid=2001),
            "bob": SimpleNamespace(pw_uid=2002),
        }
        self.admin = ParticipantAdmin(
            self.paths,
            operator="operator:test",
            runner=self.commands.append,
        )
        self.pw = patch(
            "civic_orchestrator.participant_admin.pwd.getpwnam",
            side_effect=self.getpwnam,
        )
        self.pw.start()

    def tearDown(self):
        self.pw.stop()
        self.tmp.cleanup()

    def getpwnam(self, name):
        try:
            return self.accounts[name]
        except KeyError:
            raise KeyError(name) from None

    def registry(self):
        return json.loads(self.paths.registry.read_text())

    def access(self):
        return yaml.safe_load(self.paths.access_policy.read_text())

    def test_add_mints_permanent_identifier_with_default_deny(self):
        pid = self.admin.add("alice", qualifications=["current-resident"])

        self.assertRegex(pid, r"^participant:[0-9a-f-]{36}$")
        self.assertEqual(
            self.registry()["participants"],
            [{"username": "alice", "uid": 2001, "participant_id": pid, "active": True}],
        )
        profile = self.access()["participants"][0]
        self.assertEqual(profile["participant_id"], pid)
        self.assertEqual(profile["command_access"], [])
        self.assertEqual(profile["qualifications"][0]["name"], "current-resident")
        self.assertEqual(profile["qualifications"][0]["recorded_by"], "operator:test")
        self.assertIn(["gpasswd", "--add", "alice", "civic-participants"], self.commands)
        self.assertIn(["systemctl", "try-restart", BROKER_SERVICE], self.commands)
        self.assertEqual(os.stat(self.paths.registry).st_mode & 0o777, 0o640)
        self.assertEqual(os.stat(self.paths.access_policy).st_mode & 0o777, 0o640)

    def test_missing_account_requires_explicit_creation(self):
        with self.assertRaisesRegex(AdminError, "--create-account"):
            self.admin.add("carol")
        self.assertEqual(self.commands, [])
        self.assertFalse(self.paths.registry.exists())

        def create(argv):
            self.commands.append(argv)
            if argv[0] == "useradd":
                self.accounts["carol"] = SimpleNamespace(pw_uid=2003)

        self.admin.runner = create
        self.admin.add("carol", create_account=True)
        self.assertEqual(
            self.commands[0],
            ["useradd", "--create-home", "--shell", "/bin/bash", "carol"],
        )

    def test_identity_is_never_reused(self):
        first = self.admin.add("alice")
        with self.assertRaisesRegex(AdminError, "never reused"):
            self.admin.add("alice")

        self.admin.retire("alice")
        with self.assertRaisesRegex(AdminError, "retired"):
            self.admin.add("alice")

        # A different account name reusing the same uid is also refused.
        self.accounts["alice2"] = SimpleNamespace(pw_uid=2001)
        with self.assertRaisesRegex(AdminError, "never reused"):
            self.admin.add("alice2")

        ids = [p["participant_id"] for p in self.registry()["participants"]]
        self.assertEqual(ids, [first])

    def test_grant_records_who_when_why_and_is_accepted_by_broker_policy(self):
        self.admin.add("alice")
        grant = self.admin.grant("alice", "water-ants", reason="Signed SASE on file")

        self.assertEqual(grant["granted_by"], "operator:test")
        self.assertTrue(grant["discover"])
        self.assertTrue(grant["invoke"])
        self.assertEqual(grant["reason"], "Signed SASE on file")

        from civic_orchestrator.custom_command_access import CustomCommandAccessPolicy

        policy = CustomCommandAccessPolicy.load(
            self.paths.access_policy,
            self.paths.access_schema,
            require_secure_file=False,
        )
        pid = self.registry()["participants"][0]["participant_id"]
        self.assertTrue(policy.require_invoke(pid, "water-ants")["invoke"])

    def test_grant_replaces_rather_than_duplicates(self):
        self.admin.add("alice")
        self.admin.grant("alice", "water-ants", reason="first")
        self.admin.grant("alice", "water-ants", reason="second", invoke=False)
        grants = self.access()["participants"][0]["command_access"]
        self.assertEqual(len(grants), 1)
        self.assertEqual(grants[0]["reason"], "second")
        self.assertFalse(grants[0]["invoke"])

    def test_grant_rejects_unknown_command_and_missing_reason(self):
        self.admin.add("alice")
        with self.assertRaisesRegex(AdminError, "unknown Custom Command"):
            self.admin.grant("alice", "shell-exec", reason="x")
        with self.assertRaisesRegex(AdminError, "requires a reason"):
            self.admin.grant("alice", "water-ants", reason="  ")
        with self.assertRaisesRegex(AdminError, "no Participant"):
            self.admin.grant("bob", "water-ants", reason="x")

    def test_revoke(self):
        self.admin.add("alice")
        self.admin.grant("alice", "water-ants", reason="x")
        self.admin.revoke("alice", "water-ants")
        self.assertEqual(self.access()["participants"][0]["command_access"], [])
        with self.assertRaisesRegex(AdminError, "no grant"):
            self.admin.revoke("alice", "water-ants")

    def test_retire_keeps_tombstone_and_removes_access(self):
        pid = self.admin.add("alice")
        self.admin.grant("alice", "water-ants", reason="x")
        self.commands.clear()

        self.assertEqual(self.admin.retire("alice"), pid)

        entry = self.registry()["participants"][0]
        self.assertEqual(entry["participant_id"], pid)
        self.assertFalse(entry["active"])
        profile = self.access()["participants"][0]
        self.assertFalse(profile["active"])
        self.assertEqual(profile["command_access"], [])
        self.assertIn(["gpasswd", "--delete", "alice", "civic-participants"], self.commands)
        with self.assertRaisesRegex(AdminError, "retired"):
            self.admin.grant("alice", "water-ants", reason="x")

    def test_invalid_input_changes_nothing(self):
        self.admin.add("alice")
        before = (self.paths.registry.read_bytes(), self.paths.access_policy.read_bytes())
        with self.assertRaises(AdminError):
            self.admin.add("Bad Name")
        with self.assertRaises(AdminError):
            self.admin.add("bob", qualifications=["Not Valid"])
        self.assertEqual(
            (self.paths.registry.read_bytes(), self.paths.access_policy.read_bytes()),
            before,
        )

    def test_listing(self):
        self.admin.add("alice")
        self.admin.add("bob")
        self.admin.grant("alice", "water-ants", reason="x")
        self.admin.retire("bob")
        rows = {row["username"]: row for row in self.admin.listing()}
        self.assertEqual(rows["alice"]["grants"], ["water-ants"])
        self.assertTrue(rows["alice"]["active"])
        self.assertFalse(rows["bob"]["active"])


if __name__ == "__main__":
    unittest.main()
