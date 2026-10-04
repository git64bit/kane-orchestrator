import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import yaml

from civic_orchestrator.custom_commands import (
    CommandInvocation,
    CustomCommandError,
    CustomCommandRegistry,
    LocalCustomCommandAdapter,
)
from civic_orchestrator.participants import ParticipantIdentity


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "contracts" / "custom-command-registry-v1.yaml"
SCHEMA_PATH = ROOT / "schemas" / "custom-command-registry-v1.schema.json"
HELP_PATH = ROOT / "contracts" / "custom-command-help-v1.yaml"
HELP_SCHEMA_PATH = ROOT / "schemas" / "custom-command-help-v1.schema.json"


class StaticParticipantRegistry:
    def resolve(self, uid):
        return ParticipantIdentity(
            uid=uid,
            username="participant1",
            participant_id="participant:test-stable",
        )


class StaticAccessPolicy:
    def __init__(self, allowed=True, discoverable=None):
        self.allowed = allowed
        self.calls = []
        self.discoverable = (
            [
                {
                    "codename": "water-ants",
                    "discover": True,
                    "invoke": allowed,
                }
            ]
            if discoverable is None
            else discoverable
        )

    def discoverable_grants(self, participant_id):
        self.calls.append((participant_id, "list"))
        return list(self.discoverable)

    def require_discover(self, participant_id, codename):
        self.calls.append((participant_id, f"help:{codename}"))
        for grant in self.discoverable:
            if grant["codename"] == codename and grant["discover"]:
                return grant
        raise CustomCommandError("Custom Command discovery is not granted")

    def require_invoke(self, participant_id, codename):
        self.calls.append((participant_id, codename))
        if not self.allowed:
            raise CustomCommandError("Custom Command invocation is not granted")
        return {"codename": codename, "discover": True, "invoke": True}


class CustomCommandTests(unittest.TestCase):
    def registry(self):
        return CustomCommandRegistry.load(
            REGISTRY_PATH,
            SCHEMA_PATH,
            HELP_PATH,
            HELP_SCHEMA_PATH,
        )

    def test_registry_contract_loads_and_water_ants_is_only_stub(self):
        registry = self.registry()
        water = registry.lookup("water-ants")
        self.assertEqual(water["lifecycle"], "stub")
        self.assertEqual(water["binding"]["operation"], "publication.publish")

        other_stubbed = [
            item["codename"]
            for item in registry.value["commands"]
            if item["lifecycle"] == "stub" and item["codename"] != "water-ants"
        ]
        self.assertEqual(other_stubbed, [])

    def test_help_catalog_covers_every_registered_command(self):
        registry = self.registry()
        registered = {
            item["codename"]
            for item in registry.value["commands"]
        }
        helped = {
            item["codename"]
            for item in registry.help_value["commands"]
        }
        self.assertEqual(registered, helped)

    def test_catalog_discovers_callable_commands_only_by_default(self):
        registry = self.registry()
        text = registry.render_catalog()
        self.assertIn("Publish File (water-ants) [stub]", text)
        self.assertNotIn("My Publications (navy-roots)", text)
        expanded = registry.render_catalog(include_declared=True)
        self.assertIn("My Publications (navy-roots) [declared]", expanded)

    def test_water_ants_help_warns_about_effects_and_incidents(self):
        text = self.registry().render_help("water-ants")
        self.assertIn("Significant effects:", text)
        self.assertIn("Consequences to understand:", text)
        self.assertIn("If something goes wrong:", text)
        self.assertIn("explicit acknowledgement is required", text)

    def test_explicit_confirmation_is_required_for_water_ants(self):
        registry = self.registry()
        with self.assertRaisesRegex(
            CustomCommandError,
            "explicit participant confirmation",
        ):
            registry.require_confirmation("water-ants", False)
        registry.require_confirmation("water-ants", True)

    def test_declared_command_is_not_callable(self):
        with self.assertRaisesRegex(
            CustomCommandError,
            "not callable",
        ):
            self.registry().require_callable("navy-roots")

    def test_unknown_codename_is_rejected(self):
        with self.assertRaisesRegex(
            CustomCommandError,
            "unknown Custom Command",
        ):
            self.registry().require_callable("fake-name")

    def test_participant_list_is_access_resolved(self):
        access = StaticAccessPolicy(
            allowed=False,
            discoverable=[
                {
                    "codename": "water-ants",
                    "discover": True,
                    "invoke": False,
                }
            ],
        )
        adapter = LocalCustomCommandAdapter(
            StaticParticipantRegistry(),
            self.registry(),
            access,
        )
        result = adapter.handle(
            1002,
            CommandInvocation(
                codename=None,
                arguments={},
                payload=b"",
                request_kind="list",
            ),
        )

        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["commands"]), 1)
        self.assertEqual(
            result["commands"][0]["codename"],
            "water-ants",
        )
        self.assertFalse(
            result["commands"][0]["available_to_run"]
        )

    def test_participant_help_requires_discovery_grant(self):
        access = StaticAccessPolicy(
            discoverable=[],
        )
        adapter = LocalCustomCommandAdapter(
            StaticParticipantRegistry(),
            self.registry(),
            access,
        )
        with self.assertRaisesRegex(
            CustomCommandError,
            "discovery is not granted",
        ):
            adapter.handle(
                1002,
                CommandInvocation(
                    codename="water-ants",
                    arguments={},
                    payload=b"",
                    request_kind="help",
                ),
            )

    def test_water_ants_stub_binds_participant_and_derives_evidence(self):
        payload = b"bounded publication bytes"
        adapter = LocalCustomCommandAdapter(
            StaticParticipantRegistry(),
            self.registry(),
            StaticAccessPolicy(),
        )

        result = adapter.handle(
            1002,
            CommandInvocation(
                codename="water-ants",
                arguments={},
                payload=payload,
            ),
        )

        self.assertEqual(result["status"], "stub")
        self.assertFalse(result["remote_dispatch"])
        self.assertFalse(result["side_effects"])
        self.assertEqual(result["command"], "water-ants")
        self.assertEqual(result["operation"], "publication.publish")
        self.assertEqual(result["participant_id"], "participant:test-stable")
        self.assertEqual(
            result["artifact"]["sha256"],
            hashlib.sha256(payload).hexdigest(),
        )

    def test_water_ants_requires_explicit_participant_grant(self):
        access = StaticAccessPolicy(allowed=False)
        adapter = LocalCustomCommandAdapter(
            StaticParticipantRegistry(),
            self.registry(),
            access,
        )

        with self.assertRaisesRegex(
            CustomCommandError,
            "invocation is not granted",
        ):
            adapter.handle(
                1002,
                CommandInvocation(
                    codename="water-ants",
                    arguments={},
                    payload=b"x",
                ),
            )

        self.assertEqual(
            access.calls,
            [("participant:test-stable", "water-ants")],
        )

    def test_water_ants_rejects_typed_arguments(self):
        adapter = LocalCustomCommandAdapter(
            StaticParticipantRegistry(),
            self.registry(),
            StaticAccessPolicy(),
        )
        with self.assertRaisesRegex(
            CustomCommandError,
            "does not accept typed arguments",
        ):
            adapter.handle(
                1002,
                CommandInvocation(
                    codename="water-ants",
                    arguments={"operation": "shell.exec"},
                    payload=b"x",
                ),
            )

    def test_duplicate_codename_fails_closed(self):
        value = yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))
        duplicate = copy.deepcopy(value["commands"][1])
        duplicate["codename"] = "water-ants"
        value["commands"].append(duplicate)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "registry.yaml"
            path.write_text(yaml.safe_dump(value), encoding="utf-8")
            with self.assertRaisesRegex(
                CustomCommandError,
                "duplicate Custom Command codename",
            ):
                CustomCommandRegistry.load(
                    path,
                    SCHEMA_PATH,
                    HELP_PATH,
                    HELP_SCHEMA_PATH,
                )


if __name__ == "__main__":
    unittest.main()
