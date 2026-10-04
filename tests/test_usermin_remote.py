import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path

from civic_orchestrator.usermin_adapter import (
    LocalAdapterError,
    ParticipantIdentity,
    derive_artifact,
)
from civic_orchestrator.usermin_remote import (
    AdapterCredential,
    OrchestratorPublisher,
    load_systemd_adapter_credential,
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


class UserminRemotePublisherTests(unittest.TestCase):
    def setUp(self):
        self.credential = AdapterCredential(
            token="T" * 48,
            client_id="usermin-broker",
            client_kind="service",
            authenticated_by="adapter:usermin-broker",
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
            path = Path(tmp) / "usermin-adapter.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "token": "S" * 48,
                        "binding": {
                            "client_id": "usermin-broker",
                            "client_kind": "service",
                            "authenticated_by": "adapter:usermin-broker",
                            "caller_authority": "portal-participant-registry",
                            "subject_prefix": "participant:",
                        },
                    }
                ),
                encoding="utf-8",
            )

            credential = load_systemd_adapter_credential(
                "usermin-adapter.json",
                credentials_directory=tmp,
            )

        self.assertEqual(credential.token, "S" * 48)
        self.assertEqual(credential.client_id, "usermin-broker")
        self.assertEqual(credential.subject_prefix, "participant:")

    def test_request_contains_only_fixed_identity_and_publication_operation(self):
        publisher = OrchestratorPublisher(
            "http://127.0.0.1:8045",
            self.credential,
            opener=lambda *_args, **_kwargs: FakeResponse(
                200,
                {
                    "contract_version": 1,
                    "request_id": "req:test",
                    "workflow_id": "wf:test",
                    "operation": "publication.publish",
                    "status": "accepted",
                    "completed_at": "2026-10-02T00:00:00Z",
                    "side_effects": False,
                    "result": {},
                },
            ),
        )

        request = publisher.build_request(
            self.participant,
            self.artifact,
        )

        self.assertEqual(request["operation"], "publication.publish")
        self.assertEqual(
            request["caller"],
            {
                "subject": "participant:stable-a",
                "authority": "portal-participant-registry",
                "authenticated_by": "adapter:usermin-broker",
            },
        )
        self.assertEqual(
            request["client"],
            {
                "id": "usermin-broker",
                "kind": "service",
            },
        )
        self.assertEqual(request["input"], {"artifact": self.artifact})
        self.assertNotIn("path", request)
        self.assertNotIn("username", request)

    def test_http_request_uses_bearer_and_operations_endpoint(self):
        observed = {}

        def opener(request, *, timeout):
            observed["url"] = request.full_url
            observed["authorization"] = request.get_header("Authorization")
            observed["timeout"] = timeout
            observed["body"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse(
                200,
                {
                    "contract_version": 1,
                    "request_id": observed["body"]["request_id"],
                    "workflow_id": "wf:test",
                    "operation": "publication.publish",
                    "status": "accepted",
                    "completed_at": "2026-10-02T00:00:00Z",
                    "side_effects": False,
                    "result": {},
                },
            )

        result = OrchestratorPublisher(
            "http://10.0.0.1:8045",
            self.credential,
            opener=opener,
        )(self.participant, self.artifact)

        self.assertEqual(
            observed["url"],
            "http://10.0.0.1:8045/v1/operations",
        )
        self.assertEqual(
            observed["authorization"],
            "Bearer " + ("T" * 48),
        )
        self.assertEqual(
            observed["body"]["caller"]["subject"],
            "participant:stable-a",
        )
        self.assertTrue(result["remote_dispatch"])
        self.assertEqual(result["orchestrator_http_status"], 200)
        self.assertEqual(result["status"], "accepted")

    def test_subject_outside_credential_namespace_never_dispatches(self):
        calls = []

        def opener(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("network dispatch must not occur")

        publisher = OrchestratorPublisher(
            "http://127.0.0.1:8045",
            self.credential,
            opener=opener,
        )
        outsider = ParticipantIdentity(
            uid=1002,
            username="participant1",
            participant_id="operator:root",
        )

        with self.assertRaisesRegex(
            LocalAdapterError,
            "outside adapter subject namespace",
        ):
            publisher(outsider, self.artifact)

        self.assertEqual(calls, [])

    def test_orchestrator_failure_is_local_rejection(self):
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

        result = OrchestratorPublisher(
            "http://127.0.0.1:8045",
            self.credential,
            opener=opener,
        )(self.participant, self.artifact)

        self.assertEqual(result["status"], "rejected")
        self.assertTrue(result["remote_dispatch"])
        self.assertEqual(result["orchestrator_http_status"], 503)
        self.assertIn("publication backend unavailable", result["error"])

    def test_partial_remote_configuration_is_rejected_by_constructor(self):
        with self.assertRaisesRegex(
            LocalAdapterError,
            "base URL is invalid",
        ):
            OrchestratorPublisher(
                "file:///tmp/not-an-orchestrator",
                self.credential,
            )


if __name__ == "__main__":
    unittest.main()
