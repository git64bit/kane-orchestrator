import base64
import hashlib
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from civic_orchestrator.publication import (
    CID_PROFILE,
    PublicationServiceClient,
    expected_single_raw_cid,
)
from civic_orchestrator.publication_budget import PublicationBudgetPolicy
from civic_orchestrator.runtime import CivicOrchestrator, RuntimePaths


ROOT = Path(__file__).resolve().parents[1]


class PublicationFixtureHandler(BaseHTTPRequestHandler):
    mode = "success"
    requests = []
    bearer_token = "I" * 48

    def log_message(self, format, *args):
        return

    def do_POST(self):
        if self.path != "/v1/publications":
            self.send_response(404)
            self.end_headers()
            return

        if self.headers.get("Authorization") != (
            f"Bearer {type(self).bearer_token}"
        ):
            self.send_response(401)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        value = json.loads(self.rfile.read(length).decode("utf-8"))
        type(self).requests.append(value)

        if type(self).mode == "validation-only":
            payload = {
                "contract_version": 1,
                "workflow_id": value["workflow_id"],
                "operation": "publication.publish",
                "failure_class": "service-unavailable",
                "message": (
                    "publication bytes validated; "
                    "Kubo publication is not enabled yet"
                ),
                "retryable": True,
            }
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(503)
        else:
            artifact = value["artifact"]
            payload = {
                "contract_version": 1,
                "workflow_id": value["workflow_id"],
                "operation": "publication.publish",
                "sha256": artifact["sha256"],
                "size_bytes": artifact["size_bytes"],
                "cid": expected_single_raw_cid(artifact["sha256"]),
                "cid_profile": CID_PROFILE,
                "pinned": True,
                "verified": True,
            }
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(200)

        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class PublicationIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        PublicationFixtureHandler.mode = "success"
        PublicationFixtureHandler.requests = []
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            PublicationFixtureHandler,
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()
        host, port = self.server.server_address

        runtime = CivicOrchestrator(
            RuntimePaths(
                repo_root=ROOT,
                state_db=Path(self.tmp.name) / "state.sqlite3",
            ),
            publication_budget_policy=PublicationBudgetPolicy(
                max_publications=10,
                max_publication_bytes=2_621_440,
            ),
        )
        runtime.publication_client = PublicationServiceClient(
            f"http://{host}:{port}",
            runtime.contracts.validate,
            bearer_token=PublicationFixtureHandler.bearer_token,
        )
        runtime.registry.operations["publication.publish"][
            "implementation"
        ] = "available"
        self.runtime = runtime

        payload = b"integration publication\n"
        self.artifact = {
            "media_type": "text/plain",
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "encoding": "base64",
            "content": base64.b64encode(payload).decode("ascii"),
        }

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def request(self, request_id):
        return {
            "contract_version": 1,
            "request_id": request_id,
            "operation": "publication.publish",
            "caller": {
                "subject": "participant:integration",
                "authenticated_by": "integration-test",
            },
            "client": {
                "id": "integration-client",
                "kind": "test",
            },
            "submitted_at": "2026-10-01T17:30:00Z",
            "input": {
                "artifact": self.artifact,
            },
        }

    def test_runtime_calls_exact_http_service_contract(self):
        status, result = self.runtime.submit(
            self.request("req:publication-integration-success")
        )

        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["side_effects"])
        self.assertEqual(result["result"]["sha256"], self.artifact["sha256"])
        self.assertTrue(result["result"]["pinned"])
        self.assertTrue(result["result"]["verified"])
        self.assertEqual(len(PublicationFixtureHandler.requests), 1)

        sent = PublicationFixtureHandler.requests[0]
        self.runtime.contracts.validate(
            "publication-service-request-v1.schema.json",
            sent,
        )
        self.assertEqual(sent["workflow_id"], result["workflow_id"])
        self.assertEqual(sent["artifact"], self.artifact)

    def test_current_validation_only_service_shape_fails_workflow_cleanly(self):
        PublicationFixtureHandler.mode = "validation-only"

        status, result = self.runtime.submit(
            self.request("req:publication-integration-validation-only")
        )

        self.assertEqual(status, 503)
        self.assertEqual(result["failure_class"], "backend-unavailable")
        self.assertFalse(result["side_effects"])
        self.assertTrue(result["retryable"])

        workflow_id = result["detail"]["workflow_id"]
        evidence_status, evidence = self.runtime.workflow_evidence(
            workflow_id
        )
        self.assertEqual(evidence_status, 200)
        self.assertEqual(evidence["workflow"]["state"], "waiting")
        self.assertEqual(evidence["receipts"], [])
        self.assertEqual(
            evidence["audit_events"][-1]["event_type"],
            "civic.operation.waiting",
        )


if __name__ == "__main__":
    unittest.main()
