import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path

from civic_orchestrator.orchestrator_client import (
    AdapterCredential,
    OrchestratorClient,
    load_protected_adapter_credential,
    load_systemd_adapter_credential,
)
from civic_orchestrator.participants import (
    LocalAdapterError,
    ParticipantIdentity,
    derive_artifact,
)


class FakeResponse:
    def __init__(self, status, value):
        self.status = status
        self.raw = json.dumps(value).encode("utf-8")
        self.closed = False

    def getcode(self):
        return self.status

    def read(self, limit=-1):
        if limit is None or limit < 0:
            return self.raw
        return self.raw[:limit]

    def close(self):
        self.closed = True


def credential_document(token="S" * 48):
    return {
        "version": 1,
        "token": token,
        "binding": {
            "client_id": "portal-broker",
            "client_kind": "service",
            "authenticated_by": "adapter:portal-broker",
            "caller_authority": "portal-participant-registry",
            "subject_prefix": "participant:",
        },
    }


class OrchestratorClientTests(unittest.TestCase):
    def setUp(self):
        self.credential = AdapterCredential(
            token="T" * 48,
            client_id="portal-broker",
            client_kind="service",
            authenticated_by="adapter:portal-broker",
            caller_authority="portal-participant-registry",
            subject_prefix="participant:",
        )
        self.participant = ParticipantIdentity(
            uid=1002,
            username="participant1",
            participant_id="participant:stable-a",
        )
        self.artifact = derive_artifact(b"public bytes")

    def test_systemd_credential_supplies_token_and_fixed_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "adapter.json"
            path.write_text(json.dumps(credential_document()), encoding="utf-8")

            credential = load_systemd_adapter_credential(
                "adapter.json",
                credentials_directory=tmp,
            )

        self.assertEqual(credential.token, "S" * 48)
        self.assertEqual(credential.client_id, "portal-broker")
        self.assertEqual(credential.subject_prefix, "participant:")

    def test_protected_credential_file_must_be_owner_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / "adapter.json"
            path.write_text(json.dumps(credential_document()), encoding="utf-8")
            os.chmod(path, 0o600)
            credential = load_protected_adapter_credential(
                path,
                required_owner_uid=os.getuid(),
            )
            self.assertEqual(credential.client_id, "portal-broker")

            os.chmod(path, 0o640)
            with self.assertRaisesRegex(LocalAdapterError, "group/world"):
                load_protected_adapter_credential(
                    path,
                    required_owner_uid=os.getuid(),
                )

            os.chmod(path, 0o600)
            with self.assertRaisesRegex(LocalAdapterError, "invalid owner"):
                load_protected_adapter_credential(
                    path,
                    required_owner_uid=os.getuid() + 1,
                )

            link = Path(tmp).resolve() / "link.json"
            link.symlink_to(path)
            with self.assertRaisesRegex(LocalAdapterError, "cannot be opened"):
                load_protected_adapter_credential(
                    link,
                    required_owner_uid=os.getuid(),
                )

    def test_request_contains_only_fixed_identity_and_given_operation(self):
        client = OrchestratorClient("http://127.0.0.1:8045", self.credential)

        request = client.build_request(
            "publication.publish",
            self.participant,
            {"artifact": self.artifact},
        )

        self.assertEqual(request["operation"], "publication.publish")
        self.assertEqual(
            request["caller"],
            {
                "subject": "participant:stable-a",
                "authority": "portal-participant-registry",
                "authenticated_by": "adapter:portal-broker",
            },
        )
        self.assertEqual(
            request["client"],
            {"id": "portal-broker", "kind": "service"},
        )
        self.assertEqual(request["input"], {"artifact": self.artifact})
        self.assertTrue(request["request_id"].startswith("req:broker:"))
        self.assertNotIn("path", request)
        self.assertNotIn("username", request)

    def test_invalid_operation_is_refused_before_dispatch(self):
        client = OrchestratorClient(
            "http://127.0.0.1:8045",
            self.credential,
            opener=lambda *a, **k: self.fail("must not dispatch"),
        )
        for operation in ("shell.exec", "kubo.rpc", "", "publication"):
            with self.assertRaisesRegex(LocalAdapterError, "operation is invalid"):
                client.submit(operation, self.participant, {})

    def test_http_request_uses_bearer_and_operations_endpoint(self):
        observed = {}

        def opener(request, *, timeout):
            observed["url"] = request.full_url
            observed["method"] = request.get_method()
            observed["authorization"] = request.get_header("Authorization")
            observed["body"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse(200, {"status": "not-implemented"})

        sent, reply = OrchestratorClient(
            "http://198.51.100.20:8045",
            self.credential,
            opener=opener,
        ).submit("participant.validate_publication", self.participant, {})

        self.assertEqual(observed["url"], "http://198.51.100.20:8045/v1/operations")
        self.assertEqual(observed["method"], "POST")
        self.assertEqual(observed["authorization"], "Bearer " + ("T" * 48))
        self.assertEqual(observed["body"], sent)
        self.assertEqual(reply.http_status, 200)
        self.assertTrue(reply.ok)

    def test_workflow_evidence_uses_bearer_get(self):
        observed = {}

        def opener(request, *, timeout):
            observed["url"] = request.full_url
            observed["method"] = request.get_method()
            observed["authorization"] = request.get_header("Authorization")
            return FakeResponse(200, {"contract_version": 1})

        reply = OrchestratorClient(
            "http://198.51.100.20:8045",
            self.credential,
            opener=opener,
        ).workflow_evidence("wf:1234")

        self.assertEqual(
            observed["url"],
            "http://198.51.100.20:8045/v1/workflows/wf:1234",
        )
        self.assertEqual(observed["method"], "GET")
        self.assertEqual(observed["authorization"], "Bearer " + ("T" * 48))
        self.assertTrue(reply.ok)

    def test_subject_outside_credential_namespace_never_dispatches(self):
        calls = []

        def opener(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("network dispatch must not occur")

        client = OrchestratorClient(
            "http://127.0.0.1:8045",
            self.credential,
            opener=opener,
        )
        for subject in ("operator:root", "participant:"):
            outsider = ParticipantIdentity(
                uid=1002,
                username="participant1",
                participant_id=subject,
            )
            with self.assertRaisesRegex(
                LocalAdapterError,
                "outside adapter subject namespace",
            ):
                client.submit("publication.publish", outsider, {})

        self.assertEqual(calls, [])

    def test_orchestrator_http_error_is_returned_as_reply(self):
        failure_value = {
            "contract_version": 1,
            "request_id": "req:test",
            "operation": "publication.publish",
            "failure_class": "backend-unavailable",
            "message": "publication backend unavailable",
            "retryable": True,
            "side_effects": False,
        }
        raw = json.dumps(failure_value).encode("utf-8")

        def opener(request, *, timeout):
            raise urllib.error.HTTPError(
                request.full_url,
                503,
                "Service Unavailable",
                {},
                io.BytesIO(raw),
            )

        _sent, reply = OrchestratorClient(
            "http://127.0.0.1:8045",
            self.credential,
            opener=opener,
        ).submit("publication.publish", self.participant, {"artifact": self.artifact})

        self.assertEqual(reply.http_status, 503)
        self.assertFalse(reply.ok)
        self.assertEqual(reply.body, failure_value)

    def test_unreachable_orchestrator_is_local_error(self):
        def opener(request, *, timeout):
            raise urllib.error.URLError(ConnectionRefusedError())

        client = OrchestratorClient(
            "http://127.0.0.1:8045",
            self.credential,
            opener=opener,
        )
        with self.assertRaisesRegex(LocalAdapterError, "transport is unavailable"):
            client.submit("publication.publish", self.participant, {})

    def test_invalid_base_urls_are_rejected(self):
        for url in (
            "file:///tmp/not-an-orchestrator",
            "http://user:pw@127.0.0.1:8045",
            "http://127.0.0.1:8045/v1",
            "http://127.0.0.1:8045?x=1",
            "http://:8045",
        ):
            with self.assertRaisesRegex(LocalAdapterError, "base URL is invalid"):
                OrchestratorClient(url, self.credential)


if __name__ == "__main__":
    unittest.main()
