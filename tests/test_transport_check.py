"""End-to-end proof of the Portal broker -> Orchestrator transport (RFC-0002).

A real Orchestrator HTTP server runs on loopback with an adapter credential
produced by the credential generator. The broker-side client loads the same
credential and the transport check verifies that Participant identity and
adapter identity arrive unchanged in the Orchestrator's workflow evidence.
"""

import io
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from civic_orchestrator import credentials, transport_check
from civic_orchestrator.orchestrator_client import (
    AdapterCredential,
    OrchestratorClient,
    load_systemd_adapter_credential,
)
from civic_orchestrator.participants import LocalAdapterError, ParticipantIdentity
from civic_orchestrator.runtime import CivicOrchestrator, RuntimePaths
from civic_orchestrator.server import (
    Handler,
    load_systemd_adapter_authenticator,
    require_specific_listen_address,
)


ROOT = Path(__file__).resolve().parents[1]
PARTICIPANT = ParticipantIdentity(
    uid=1002,
    username="participant1",
    participant_id="participant:0b7c1e2a-5d1f-4c8e-9a3b-2f6d8e4c1a90",
)


class TransportEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        tmp = Path(self.tmp.name).resolve()
        self.state_db = tmp / "state.sqlite3"

        # One generated credential, installed on both sides.
        self.credentials_dir = tmp / "credentials"
        self.credentials_dir.mkdir()
        credentials.write_exclusive(
            self.credentials_dir / "adapter.json",
            credentials.adapter_document(credentials.DEFAULT_BINDING),
        )

        Handler.runtime = CivicOrchestrator(
            RuntimePaths(repo_root=ROOT, state_db=self.state_db)
        )
        Handler.adapter_authenticator = load_systemd_adapter_authenticator(
            "adapter.json",
            credentials_directory=str(self.credentials_dir),
        )
        self.credential = load_systemd_adapter_credential(
            "adapter.json",
            credentials_directory=str(self.credentials_dir),
        )

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def client(self, credential=None):
        return OrchestratorClient(self.base_url, credential or self.credential)

    def workflows(self):
        conn = sqlite3.connect(self.state_db)
        try:
            return conn.execute(
                "SELECT operation, state, caller_subject, client_id, side_effects "
                "FROM workflows"
            ).fetchall()
        finally:
            conn.close()

    def diagnostics(self):
        conn = sqlite3.connect(self.state_db)
        try:
            return [row[0] for row in conn.execute(
                "SELECT outcome FROM request_diagnostics ORDER BY rowid"
            )]
        finally:
            conn.close()

    def test_participant_and_adapter_identity_are_preserved(self):
        report = transport_check.run_transport_check(self.client(), PARTICIPANT)

        failed = [item for item in report["checks"] if not item["passed"]]
        self.assertEqual(failed, [])
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["participant_id"], PARTICIPANT.participant_id)
        self.assertEqual(
            self.workflows(),
            [(
                transport_check.CHECK_OPERATION,
                "not-implemented",
                PARTICIPANT.participant_id,
                credentials.DEFAULT_BINDING["client_id"],
                0,
            )],
        )

    def test_wrong_token_is_unauthorized_and_creates_no_workflow(self):
        forged = AdapterCredential(
            token="F" * 64,
            client_id=self.credential.client_id,
            client_kind=self.credential.client_kind,
            authenticated_by=self.credential.authenticated_by,
            caller_authority=self.credential.caller_authority,
            subject_prefix=self.credential.subject_prefix,
        )
        _sent, reply = self.client(forged).submit(
            transport_check.CHECK_OPERATION, PARTICIPANT, {}
        )

        self.assertEqual(reply.http_status, 401)
        self.assertEqual(self.workflows(), [])

    def test_adapter_cannot_claim_a_different_identity(self):
        for field, value in (
            ("client_id", "other-client"),
            ("caller_authority", "other-authority"),
            ("authenticated_by", "adapter:other"),
        ):
            claims = dict(self.credential.__dict__)
            claims[field] = value
            _sent, reply = self.client(AdapterCredential(**claims)).submit(
                transport_check.CHECK_OPERATION, PARTICIPANT, {}
            )
            self.assertEqual(reply.http_status, 403, field)
            self.assertEqual(reply.body["failure_class"], "unauthorized")

        self.assertEqual(self.workflows(), [])
        self.assertEqual(self.diagnostics().count("adapter-identity-mismatch"), 3)

    def test_prohibited_operation_is_refused_by_the_orchestrator(self):
        # The client refuses names outside the Civic namespaces itself; a
        # registered-namespace operation that is not in the registry still
        # fails closed at the Orchestrator.
        _sent, reply = self.client().submit(
            "publication.delete_everything", PARTICIPANT, {}
        )
        self.assertEqual(reply.http_status, 400)
        self.assertEqual(reply.body["failure_class"], "unknown-operation")
        self.assertEqual(self.workflows(), [])

    def test_unreachable_orchestrator_is_a_local_error(self):
        self.server.shutdown()
        self.server.server_close()
        with self.assertRaisesRegex(LocalAdapterError, "transport is unavailable"):
            self.client().submit(transport_check.CHECK_OPERATION, PARTICIPANT, {})

    def test_command_line_reports_pass_and_exit_status(self):
        account = SimpleNamespace(pw_uid=PARTICIPANT.uid)
        out = io.StringIO()
        with patch.object(
            transport_check,
            "load_protected_adapter_credential",
            return_value=self.credential,
        ), patch.object(
            transport_check.pwd, "getpwnam", return_value=account
        ), patch.object(
            transport_check.ParticipantRegistry, "resolve", return_value=PARTICIPANT
        ), redirect_stdout(out):
            code = transport_check.main([
                "--participant", PARTICIPANT.username,
                "--orchestrator-base-url", self.base_url,
            ])

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["status"], "passed")


class CredentialGeneratorTests(unittest.TestCase):
    def test_output_is_owner_only_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "adapter.json"
            self.assertEqual(credentials.main(["adapter", "--output", str(path)]), 0)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            first = path.read_bytes()

            self.assertEqual(credentials.main(["adapter", "--output", str(path)]), 1)
            self.assertEqual(path.read_bytes(), first)

            value = json.loads(first)
            self.assertEqual(value["binding"], credentials.DEFAULT_BINDING)
            self.assertGreaterEqual(len(value["token"]), 64)

    def test_tokens_are_unique(self):
        tokens = {credentials.new_token() for _ in range(50)}
        self.assertEqual(len(tokens), 50)

    def test_publication_credential_matches_service_loader(self):
        from civic_orchestrator.server import load_systemd_publication_bearer_token

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "publication-service.json"
            self.assertEqual(
                credentials.main(["publication", "--output", str(path)]), 0
            )
            token = load_systemd_publication_bearer_token(
                "publication-service.json",
                credentials_directory=tmp,
            )
            self.assertEqual(token, json.loads(path.read_text())["token"])


class ListenAddressTests(unittest.TestCase):
    def test_wildcard_addresses_are_refused(self):
        for address in ("", "0.0.0.0", "::", "[::]", "*", "  "):
            with self.assertRaises(ValueError):
                require_specific_listen_address(address)

    def test_specific_addresses_are_allowed(self):
        for address in ("127.0.0.1", "10.0.3.20", "fd42::20"):
            self.assertEqual(require_specific_listen_address(address), address)


if __name__ == "__main__":
    unittest.main()
