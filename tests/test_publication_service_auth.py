import http.client
import importlib.util
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVICE_PATH = ROOT / "services" / "publication" / "publication_service.py"
SPEC = importlib.util.spec_from_file_location(
    "civic_publication_service_test",
    SERVICE_PATH,
)
publication_service = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(publication_service)


class PublicationServiceCredentialLoaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.credentials_dir = Path(self.tmp.name).resolve()
        self.credential_name = "publication-service.json"
        self.token = "S" * 48

    def tearDown(self):
        self.tmp.cleanup()

    def write_credential(self, value):
        (self.credentials_dir / self.credential_name).write_text(
            json.dumps(value),
            encoding="utf-8",
        )

    def test_loads_service_token_from_systemd_directory(self):
        self.write_credential(
            {
                "version": 1,
                "token": self.token,
            }
        )

        token = publication_service.load_systemd_bearer_token(
            self.credential_name,
            credentials_directory=str(self.credentials_dir),
        )

        self.assertEqual(token, self.token.encode("utf-8"))

    def test_service_credential_name_cannot_escape_directory(self):
        with self.assertRaisesRegex(
            ValueError,
            "credential name is invalid",
        ):
            publication_service.load_systemd_bearer_token(
                "../publication.json",
                credentials_directory=str(self.credentials_dir),
            )

    def test_service_short_token_is_rejected(self):
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
            publication_service.load_systemd_bearer_token(
                self.credential_name,
                credentials_directory=str(self.credentials_dir),
            )



class PublicationServiceArgumentTests(unittest.TestCase):
    def test_default_bind_is_loopback(self):
        args = publication_service.parse_args([])

        self.assertEqual(args.listen, "127.0.0.1")
        self.assertEqual(args.port, 8046)

    def test_bind_can_be_set_by_deployment(self):
        args = publication_service.parse_args(
            ["--listen", "192.0.2.10", "--port", "9000"]
        )

        self.assertEqual(args.listen, "192.0.2.10")
        self.assertEqual(args.port, 9000)


class PublicationServiceAuthenticationTests(unittest.TestCase):
    def start_server(self, bearer_token):
        class TestHandler(publication_service.Handler):
            pass

        TestHandler.bearer_token = bearer_token
        server = ThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
        thread = threading.Thread(
            target=server.serve_forever,
            daemon=True,
        )
        thread.start()
        return server, thread

    def request(self, server, authorization=None):
        host, port = server.server_address
        conn = http.client.HTTPConnection(host, port, timeout=5)
        body = b"{}"
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }
        if authorization is not None:
            headers["Authorization"] = authorization
        conn.request("POST", "/v1/publications", body=body, headers=headers)
        response = conn.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        status = response.status
        conn.close()
        return status, payload

    def stop_server(self, server, thread):
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    def test_missing_credential_is_rejected_before_request_validation(self):
        token = b"S" * 48
        server, thread = self.start_server(token)
        try:
            status, payload = self.request(server)
        finally:
            self.stop_server(server, thread)

        self.assertEqual(status, 401)
        self.assertEqual(payload["failure_class"], "invalid-request")
        self.assertIn("authentication failed", payload["message"])

    def test_wrong_credential_is_rejected_before_request_validation(self):
        token = b"S" * 48
        server, thread = self.start_server(token)
        try:
            status, payload = self.request(
                server,
                "Bearer " + ("W" * 48),
            )
        finally:
            self.stop_server(server, thread)

        self.assertEqual(status, 401)
        self.assertEqual(payload["failure_class"], "invalid-request")

    def test_valid_credential_reaches_request_validation(self):
        token_text = "S" * 48
        server, thread = self.start_server(token_text.encode("utf-8"))
        try:
            status, payload = self.request(
                server,
                f"Bearer {token_text}",
            )
        finally:
            self.stop_server(server, thread)

        self.assertEqual(status, 400)
        self.assertEqual(payload["failure_class"], "invalid-request")
        self.assertNotIn("authentication failed", payload["message"])

    def test_unconfigured_service_authentication_fails_closed(self):
        server, thread = self.start_server(None)
        try:
            status, payload = self.request(
                server,
                "Bearer " + ("S" * 48),
            )
        finally:
            self.stop_server(server, thread)

        self.assertEqual(status, 503)
        self.assertEqual(payload["failure_class"], "service-unavailable")
        self.assertIn("not configured", payload["message"])


if __name__ == "__main__":
    unittest.main()
