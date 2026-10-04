import json
import tempfile
import unittest
from pathlib import Path

from civic_orchestrator.publication_budget import PublicationBudgetPolicy
from civic_orchestrator.server import (
    build_runtime,
    load_systemd_publication_bearer_token,
)


ROOT = Path(__file__).resolve().parents[1]


class PublicationCredentialLoaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.credentials_dir = Path(self.tmp.name).resolve()
        self.credential_name = "publication-service.json"
        self.token = "P" * 48

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
        }

    def test_loads_publication_token_from_systemd_directory(self):
        self.write_credential(self.valid_credential())

        token = load_systemd_publication_bearer_token(
            self.credential_name,
            credentials_directory=str(self.credentials_dir),
        )

        self.assertEqual(token, self.token)

    def test_build_runtime_passes_loaded_token_to_publication_client(self):
        self.write_credential(self.valid_credential())
        token = load_systemd_publication_bearer_token(
            self.credential_name,
            credentials_directory=str(self.credentials_dir),
        )

        runtime = build_runtime(
            repo_root=ROOT,
            state_db=self.credentials_dir / "state.sqlite3",
            publication_base_url="http://publication.test:8046",
            publication_bearer_token=token,
            publication_budget_policy=PublicationBudgetPolicy(
                max_publications=10,
                max_publication_bytes=2_621_440,
            ),
        )

        self.assertIsNotNone(runtime.publication_client)
        self.assertEqual(runtime.publication_client.bearer_token, self.token)

    def test_publication_credential_name_cannot_escape_directory(self):
        with self.assertRaisesRegex(
            ValueError,
            "credential name is invalid",
        ):
            load_systemd_publication_bearer_token(
                "../publication.json",
                credentials_directory=str(self.credentials_dir),
            )

    def test_short_publication_token_is_rejected(self):
        self.write_credential(
            {
                "version": 1,
                "token": "short",
            }
        )

        with self.assertRaisesRegex(
            ValueError,
            "bearer token is invalid",
        ):
            load_systemd_publication_bearer_token(
                self.credential_name,
                credentials_directory=str(self.credentials_dir),
            )

    def test_extra_publication_credential_field_is_rejected(self):
        value = self.valid_credential()
        value["extra"] = "no"
        self.write_credential(value)

        with self.assertRaisesRegex(
            ValueError,
            "credential fields are invalid",
        ):
            load_systemd_publication_bearer_token(
                self.credential_name,
                credentials_directory=str(self.credentials_dir),
            )


if __name__ == "__main__":
    unittest.main()
