import http.client
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from civic_orchestrator.publication_budget import PublicationBudgetPolicy
from civic_orchestrator.runtime import (
    AuthenticatedAdapterBinding,
    CivicOrchestrator,
    RuntimePaths,
)
from civic_orchestrator.server import (
    BearerAdapterAuthenticator,
    Handler,
    build_runtime,
)


ROOT = Path(__file__).resolve().parents[1]


class ServerContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.runtime = CivicOrchestrator(
            RuntimePaths(
                repo_root=ROOT,
                state_db=Path(self.tmp.name) / "state.sqlite3",
            )
        )
        Handler.runtime = self.runtime
        self.adapter_token = "test-adapter-secret"
        Handler.adapter_authenticator = BearerAdapterAuthenticator(
            [
                (
                    self.adapter_token,
                    AuthenticatedAdapterBinding(
                        client_id="test-client",
                        client_kind="test",
                        authenticated_by="test-auth",
                        caller_authority="test-authority",
                        subject_prefix="participant:",
                    ),
                )
            ]
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()
        self.host, self.port = self.server.server_address

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def request(
        self,
        method,
        path,
        body=None,
        headers=None,
        *,
        authenticate=True,
    ):
        conn = http.client.HTTPConnection(
            self.host,
            self.port,
            timeout=5,
        )
        request_headers = dict(headers or {})
        if authenticate:
            request_headers.setdefault(
                "Authorization",
                f"Bearer {self.adapter_token}",
            )
        conn.request(method, path, body=body, headers=request_headers)
        response = conn.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        status = response.status
        conn.close()
        return status, payload

    def test_health_reflects_current_available_registry(self):
        status, payload = self.request("GET", "/healthz")

        self.assertEqual(status, 200)
        self.assertEqual(
            payload,
            {
                "status": "ok",
                "available_operations": 1,
                "side_effects": True,
            },
        )

    def test_health_reflects_all_stub_registry(self):
        publication = self.runtime.registry.lookup("publication.publish")
        original = publication["implementation"]
        publication["implementation"] = "stub"
        try:
            status, payload = self.request("GET", "/healthz")
        finally:
            publication["implementation"] = original

        self.assertEqual(status, 200)
        self.assertEqual(
            payload,
            {
                "status": "ok",
                "available_operations": 0,
                "side_effects": False,
            },
        )

    def test_operation_post_requires_adapter_credential(self):
        body = json.dumps({
            "contract_version": 1,
            "request_id": "req:no-adapter-credential",
            "operation": "repository.fetch_exact",
            "caller": {
                "subject": "participant:test",
                "authority": "test-authority",
                "authenticated_by": "test-auth",
            },
            "client": {
                "id": "test-client",
                "kind": "test",
            },
            "submitted_at": "2026-10-02T10:00:00Z",
            "input": {},
        })
        status, payload = self.request(
            "POST",
            "/v1/operations",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body.encode("utf-8"))),
            },
            authenticate=False,
        )

        self.assertEqual(status, 401)
        self.assertEqual(payload["failure_class"], "unauthorized")

    def test_wrong_adapter_credential_is_rejected(self):
        body = "{}"
        status, payload = self.request(
            "POST",
            "/v1/operations",
            body=body,
            headers={
                "Authorization": "Bearer wrong-secret",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            authenticate=False,
        )

        self.assertEqual(status, 401)
        self.assertEqual(payload["failure_class"], "unauthorized")

    def test_authenticated_adapter_cannot_widen_subject_identity(self):
        request = {
            "contract_version": 1,
            "request_id": "req:http-adapter-forgery",
            "operation": "repository.fetch_exact",
            "caller": {
                "subject": "operator:root",
                "authority": "test-authority",
                "authenticated_by": "test-auth",
            },
            "client": {
                "id": "test-client",
                "kind": "test",
            },
            "submitted_at": "2026-10-02T10:01:00Z",
            "input": {},
        }
        body = json.dumps(request)
        status, payload = self.request(
            "POST",
            "/v1/operations",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body.encode("utf-8"))),
            },
        )

        self.assertEqual(status, 403)
        self.assertEqual(payload["failure_class"], "unauthorized")
        with self.runtime.state._connect() as conn:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM workflows").fetchone()[0],
                0,
            )

    def test_bad_json_returns_failure_envelope(self):
        status, payload = self.request(
            "POST",
            "/v1/operations",
            body="{not-json",
            headers={
                "Content-Type": "application/json",
                "Content-Length": "9",
            },
        )
        self.assertEqual(status, 400)
        self.runtime.contracts.validate(
            "failure-envelope-v1.schema.json",
            payload,
        )
        self.assertEqual(payload["failure_class"], "invalid-contract")

        with self.runtime.state._connect() as conn:
            outcomes = {
                row[0]
                for row in conn.execute(
                    "SELECT outcome FROM request_diagnostics"
                ).fetchall()
            }
        self.assertIn("http-invalid-contract", outcomes)

    def test_wrong_post_path_returns_failure_envelope(self):
        status, payload = self.request(
            "POST",
            "/v1/not-an-operation-endpoint",
            body="{}",
            headers={
                "Content-Type": "application/json",
                "Content-Length": "2",
            },
        )
        self.assertEqual(status, 404)
        self.runtime.contracts.validate(
            "failure-envelope-v1.schema.json",
            payload,
        )
        self.assertFalse(payload["side_effects"])

    def test_unexpected_submit_exception_returns_internal_failure(self):
        original = self.runtime.submit_authenticated

        def explode(_request, _binding):
            raise RuntimeError("synthetic server test")

        self.runtime.submit_authenticated = explode
        try:
            body = json.dumps({
                "contract_version": 1,
                "request_id": "req:server-exception",
                "operation": "publication.publish",
                "caller": {
                    "subject": "participant:test",
                    "authority": "test-authority",
                    "authenticated_by": "test-auth",
                },
                "client": {
                    "id": "test-client",
                    "kind": "test",
                },
                "submitted_at": "2026-10-01T08:00:00Z",
                "input": {},
            })
            status, payload = self.request(
                "POST",
                "/v1/operations",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body.encode("utf-8"))),
                },
            )
        finally:
            self.runtime.submit_authenticated = original

        self.assertEqual(status, 500)
        self.runtime.contracts.validate(
            "failure-envelope-v1.schema.json",
            payload,
        )
        self.assertEqual(payload["failure_class"], "internal")
        self.assertFalse(payload["side_effects"])


    def test_workflow_evidence_requires_adapter_credential(self):
        request = {
            "contract_version": 1,
            "request_id": "req:workflow-auth-boundary",
            "operation": "repository.fetch_exact",
            "caller": {
                "subject": "participant:test",
                "authenticated_by": "test-auth",
            },
            "client": {
                "id": "test-client",
                "kind": "test",
            },
            "submitted_at": "2026-10-01T08:09:00Z",
            "input": {},
        }
        _, result = self.runtime.submit(request)

        status, payload = self.request(
            "GET",
            f"/v1/workflows/{result['workflow_id']}",
            authenticate=False,
        )
        self.assertEqual(status, 401)
        self.assertEqual(payload["failure_class"], "unauthorized")

    def test_percent_encoded_workflow_id_is_resolved(self):
        request = {
            "contract_version": 1,
            "request_id": "req:encoded-workflow",
            "operation": "repository.fetch_exact",
            "caller": {
                "subject": "participant:test",
                "authenticated_by": "test-auth",
            },
            "client": {
                "id": "test-client",
                "kind": "test",
            },
            "submitted_at": "2026-10-01T08:10:00Z",
            "input": {},
        }
        _, result = self.runtime.submit(request)
        encoded = result["workflow_id"].replace(":", "%3A")

        status, payload = self.request(
            "GET",
            f"/v1/workflows/{encoded}",
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            payload["workflow"]["workflow_id"],
            result["workflow_id"],
        )

    def test_nonstandard_json_nan_is_rejected_over_http(self):
        body = (
            '{"contract_version":1,'
            '"request_id":"req:http-nan",'
            '"operation":"publication.publish",'
            '"caller":{"subject":"participant:test",'
            '"authority":"test-authority",'
            '"authenticated_by":"test-auth"},'
            '"client":{"id":"test-client","kind":"test"},'
            '"submitted_at":"2026-10-01T08:00:00Z",'
            '"input":{"value":NaN}}'
        )
        status, payload = self.request(
            "POST",
            "/v1/operations",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body.encode("utf-8"))),
            },
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["failure_class"], "invalid-contract")

    def test_oversize_publication_reaches_runtime_contract_boundary(self):
        import base64
        import hashlib

        payload = b"x" * 300_000
        artifact = {
            "media_type": "application/octet-stream",
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "encoding": "base64",
            "content": base64.b64encode(payload).decode("ascii"),
        }
        request = {
            "contract_version": 1,
            "request_id": "req:http-oversize-publication",
            "operation": "publication.publish",
            "caller": {
                "subject": "participant:test",
                "authority": "test-authority",
                "authenticated_by": "test-auth",
            },
            "client": {
                "id": "test-client",
                "kind": "test",
            },
            "submitted_at": "2026-10-01T17:10:00Z",
            "input": {
                "artifact": artifact,
            },
        }
        body_bytes = json.dumps(
            request,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertLess(len(body_bytes), 1_500_000)

        status, response = self.request(
            "POST",
            "/v1/operations",
            body=body_bytes,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body_bytes)),
            },
        )

        self.assertEqual(status, 400)
        self.assertEqual(response["failure_class"], "invalid-contract")
        self.assertFalse(response["side_effects"])

    def test_publication_base_url_requires_budget_policy(self):
        with self.assertRaisesRegex(
            ValueError,
            "publication budget policy is required",
        ):
            build_runtime(
                repo_root=ROOT,
                state_db=Path(self.tmp.name) / "missing-budget.sqlite3",
                publication_base_url="http://198.51.100.20:8046",
            )

    def test_publication_base_url_builds_available_service_client(self):
        policy = PublicationBudgetPolicy(
            max_publications=10,
            max_publication_bytes=2_621_440,
        )
        runtime = build_runtime(
            repo_root=ROOT,
            state_db=Path(self.tmp.name) / "configured.sqlite3",
            publication_base_url="http://198.51.100.20:8046",
            publication_budget_policy=policy,
        )

        self.assertIsNotNone(runtime.publication_client)
        self.assertEqual(
            runtime.publication_client.base_url,
            "http://198.51.100.20:8046",
        )
        publication = runtime.registry.lookup("publication.publish")
        self.assertEqual(publication["implementation"], "available")
        self.assertIs(runtime.publication_budget_policy, policy)


if __name__ == "__main__":
    unittest.main()
