import tempfile
import unittest
from pathlib import Path

from civic_orchestrator.runtime import (
    AuthenticatedAdapterBinding,
    CivicOrchestrator,
    RuntimePaths,
)


ROOT = Path(__file__).resolve().parents[1]


class AuthenticatedAdapterBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.runtime = CivicOrchestrator(
            RuntimePaths(
                repo_root=ROOT,
                state_db=Path(self.tmp.name) / "state.sqlite3",
            )
        )
        self.binding = AuthenticatedAdapterBinding(
            client_id="usermin-broker",
            client_kind="service",
            authenticated_by="adapter:usermin-broker",
            caller_authority="portal-participant-registry",
            subject_prefix="participant:",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def request(self):
        return {
            "contract_version": 1,
            "request_id": "req:adapter-binding-001",
            "operation": "repository.fetch_exact",
            "caller": {
                "subject": "participant:stable-a",
                "authority": "portal-participant-registry",
                "authenticated_by": "adapter:usermin-broker",
            },
            "client": {
                "id": "usermin-broker",
                "kind": "service",
            },
            "submitted_at": "2026-10-02T09:00:00Z",
            "input": {},
        }

    def test_matching_transport_binding_is_accepted(self):
        status, result = self.runtime.submit_authenticated(
            self.request(),
            self.binding,
        )

        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "not-implemented")

    def test_subject_outside_bound_namespace_is_rejected(self):
        request = self.request()
        request["caller"]["subject"] = "operator:root"

        status, result = self.runtime.submit_authenticated(
            request,
            self.binding,
        )

        self.assertEqual(status, 403)
        self.assertEqual(result["failure_class"], "unauthorized")
        with self.runtime.state._connect() as conn:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM workflows").fetchone()[0],
                0,
            )

    def test_client_id_cannot_be_forged(self):
        request = self.request()
        request["client"]["id"] = "operator-console"

        status, result = self.runtime.submit_authenticated(
            request,
            self.binding,
        )

        self.assertEqual(status, 403)
        self.assertEqual(result["failure_class"], "unauthorized")

    def test_authentication_provenance_cannot_be_forged(self):
        request = self.request()
        request["caller"]["authenticated_by"] = "self-asserted"

        status, result = self.runtime.submit_authenticated(
            request,
            self.binding,
        )

        self.assertEqual(status, 403)
        self.assertEqual(result["failure_class"], "unauthorized")

    def test_caller_authority_cannot_be_forged(self):
        request = self.request()
        request["caller"]["authority"] = "operator-root"

        status, result = self.runtime.submit_authenticated(
            request,
            self.binding,
        )

        self.assertEqual(status, 403)
        self.assertEqual(result["failure_class"], "unauthorized")

    def test_identity_mismatch_is_diagnosed(self):
        request = self.request()
        request["client"]["kind"] = "operator"

        status, _ = self.runtime.submit_authenticated(
            request,
            self.binding,
        )

        self.assertEqual(status, 403)
        with self.runtime.state._connect() as conn:
            outcomes = [
                row[0]
                for row in conn.execute(
                    "SELECT outcome FROM request_diagnostics ORDER BY rowid"
                ).fetchall()
            ]
        self.assertIn("adapter-identity-mismatch", outcomes)


if __name__ == "__main__":
    unittest.main()
