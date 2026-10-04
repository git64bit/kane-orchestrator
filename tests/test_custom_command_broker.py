import unittest
from pathlib import Path
from unittest.mock import patch

from civic_orchestrator.custom_command_broker import build_adapter


ROOT = Path(__file__).resolve().parents[1]


class CustomCommandBrokerTests(unittest.TestCase):
    def test_repository_contracts_build_validation_only_adapter(self):
        with patch(
            "civic_orchestrator.usermin_adapter.ParticipantRegistry._load_entries",
            return_value=[],
        ):
            adapter = build_adapter(
                participant_registry_path=ROOT / "INSTALL" / "examples" / "participants-v1.example.json",
                participant_group="civic-participants",
                command_registry_path=ROOT / "contracts" / "custom-command-registry-v1.yaml",
                command_schema_path=ROOT / "schemas" / "custom-command-registry-v1.schema.json",
                help_catalog_path=ROOT / "contracts" / "custom-command-help-v1.yaml",
                help_schema_path=ROOT / "schemas" / "custom-command-help-v1.schema.json",
                access_policy_path=ROOT / "INSTALL" / "examples" / "custom-command-access-v1.example.yaml",
                access_schema_path=ROOT / "schemas" / "custom-command-access-v1.schema.json",
                require_secure_access_file=False,
            )

        water = adapter.command_registry.lookup("water-ants")
        self.assertEqual(water["lifecycle"], "stub")
        self.assertEqual(
            water["binding"]["operation"],
            "publication.publish",
        )
        self.assertFalse(water["side_effects_enabled"])
        grant = adapter.access_policy.require_invoke(
            "participant:550e8400-e29b-41d4-a716-446655440000",
            "water-ants",
        )
        self.assertTrue(grant["invoke"])


if __name__ == "__main__":
    unittest.main()
