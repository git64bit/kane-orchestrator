import copy
import json
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, ValidationError

from civic_orchestrator.custom_command_access import (
    CustomCommandAccessError,
    CustomCommandAccessPolicy,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "custom-command-access-v1.schema.json"
EXAMPLE = ROOT / "INSTALL" / "examples" / "custom-command-access-v1.example.yaml"


class CustomCommandAccessContractTests(unittest.TestCase):
    def values(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        value = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
        return schema, value

    def test_example_validates_and_defaults_deny(self):
        schema, value = self.values()
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(
            schema,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        ).validate(value)

        self.assertEqual(
            value["defaults"],
            {"discover": False, "invoke": False},
        )
        self.assertTrue(
            value["qualification_semantics"]["descriptive_only"]
        )
        self.assertFalse(
            value["qualification_semantics"]["automatic_grants"]
        )

    def test_invoke_requires_discovery(self):
        schema, value = self.values()
        broken = copy.deepcopy(value)
        grant = broken["participants"][0]["command_access"][0]
        grant["discover"] = False
        grant["invoke"] = True

        with self.assertRaises(ValidationError):
            Draft202012Validator(
                schema,
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            ).validate(broken)

    def test_runtime_default_deny_and_explicit_grant(self):
        policy = CustomCommandAccessPolicy.load(
            EXAMPLE,
            SCHEMA,
            require_secure_file=False,
        )
        grant = policy.require_invoke(
            "participant:550e8400-e29b-41d4-a716-446655440000",
            "water-ants",
        )
        self.assertTrue(grant["invoke"])

        with self.assertRaisesRegex(
            CustomCommandAccessError,
            "not granted",
        ):
            policy.require_invoke(
                "participant:11111111-2222-3333-4444-555555555555",
                "water-ants",
            )

    def test_unknown_granted_codename_fails_registry_validation(self):
        policy = CustomCommandAccessPolicy.load(
            EXAMPLE,
            SCHEMA,
            require_secure_file=False,
        )
        with self.assertRaisesRegex(
            CustomCommandAccessError,
            "unknown codename",
        ):
            policy.validate_codenames({"navy-roots"})

    def test_qualification_does_not_create_command_access(self):
        _, value = self.values()
        participant = value["participants"][1]
        self.assertTrue(participant["qualifications"])
        self.assertEqual(participant["command_access"], [])


if __name__ == "__main__":
    unittest.main()
