import json
import tempfile
import unittest
from pathlib import Path

from civic_orchestrator.server import (
    AdapterCredentialError,
    load_systemd_adapter_authenticator,
)


class SystemdAdapterCredentialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.credentials_dir = Path(self.tmp.name).resolve()
        self.credential_name = "usermin-adapter.json"
        self.token = "A" * 48

    def tearDown(self):
        self.tmp.cleanup()

    def write_credential(self, value):
        (self.credentials_dir / self.credential_name).write_text(
            json.dumps(value),
            encoding="utf-8",
        )

    def valid_credential(self):
        return {
            "version": 1,
            "token": self.token,
            "binding": {
                "client_id": "usermin-broker",
                "client_kind": "service",
                "authenticated_by": "adapter:usermin-broker",
                "caller_authority": "portal-participant-registry",
                "subject_prefix": "participant:",
            },
        }

    def test_loads_bearer_token_and_fixed_binding(self):
        self.write_credential(self.valid_credential())

        authenticator = load_systemd_adapter_authenticator(
            self.credential_name,
            credentials_directory=str(self.credentials_dir),
        )
        binding = authenticator.authenticate(f"Bearer {self.token}")

        self.assertEqual(binding.client_id, "usermin-broker")
        self.assertEqual(binding.client_kind, "service")
        self.assertEqual(
            binding.authenticated_by,
            "adapter:usermin-broker",
        )
        self.assertEqual(
            binding.caller_authority,
            "portal-participant-registry",
        )
        self.assertEqual(binding.subject_prefix, "participant:")

    def test_wrong_bearer_token_remains_unauthorized(self):
        self.write_credential(self.valid_credential())

        authenticator = load_systemd_adapter_authenticator(
            self.credential_name,
            credentials_directory=str(self.credentials_dir),
        )

        with self.assertRaises(AdapterCredentialError):
            authenticator.authenticate("Bearer " + ("B" * 48))

    def test_credential_name_cannot_escape_systemd_directory(self):
        with self.assertRaisesRegex(
            ValueError,
            "credential name is invalid",
        ):
            load_systemd_adapter_authenticator(
                "../adapter.json",
                credentials_directory=str(self.credentials_dir),
            )

    def test_short_token_is_rejected(self):
        value = self.valid_credential()
        value["token"] = "too-short"
        self.write_credential(value)

        with self.assertRaisesRegex(
            ValueError,
            "bearer token is invalid",
        ):
            load_systemd_adapter_authenticator(
                self.credential_name,
                credentials_directory=str(self.credentials_dir),
            )

    def test_extra_binding_field_is_rejected(self):
        value = self.valid_credential()
        value["binding"]["unexpected"] = "no"
        self.write_credential(value)

        with self.assertRaisesRegex(
            ValueError,
            "binding fields are invalid",
        ):
            load_systemd_adapter_authenticator(
                self.credential_name,
                credentials_directory=str(self.credentials_dir),
            )

    def test_missing_systemd_credentials_directory_fails_closed(self):
        with self.assertRaisesRegex(
            ValueError,
            "CREDENTIALS_DIRECTORY is unavailable",
        ):
            load_systemd_adapter_authenticator(
                self.credential_name,
                credentials_directory="",
            )


if __name__ == "__main__":
    unittest.main()
