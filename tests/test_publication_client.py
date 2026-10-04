import base64
import hashlib
import json
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from civic_orchestrator.publication import (
    CID_PROFILE,
    PublicationServiceClient,
    PublicationServiceFailure,
    PublicationServiceProtocolError,
    PublicationServiceUnavailable,
    expected_single_raw_cid,
)
from civic_orchestrator.runtime import ContractStore


ROOT = Path(__file__).resolve().parents[1]


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def getcode(self):
        return self.status_code

    def read(self):
        return self.payload


class PublicationServiceClientTests(unittest.TestCase):
    def setUp(self):
        self.contracts = ContractStore(ROOT)
        self.token = "T" * 48
        self.client = PublicationServiceClient(
            "http://publication.test:8046",
            self.contracts.validate,
            timeout_seconds=2.0,
            bearer_token=self.token,
        )
        self.workflow_id = "wf:test-publication-client"
        self.payload = b"civic publication\n"
        self.artifact = {
            "media_type": "text/plain",
            "size_bytes": len(self.payload),
            "sha256": hashlib.sha256(self.payload).hexdigest(),
            "encoding": "base64",
            "content": base64.b64encode(self.payload).decode("ascii"),
        }

    def success_result(self):
        return {
            "contract_version": 1,
            "workflow_id": self.workflow_id,
            "operation": "publication.publish",
            "sha256": self.artifact["sha256"],
            "size_bytes": self.artifact["size_bytes"],
            "cid": expected_single_raw_cid(self.artifact["sha256"]),
            "cid_profile": CID_PROFILE,
            "pinned": True,
            "verified": True,
        }

    @staticmethod
    def encoded(value):
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def test_success_uses_frozen_service_request_and_verifies_result(self):
        response = FakeResponse(200, self.encoded(self.success_result()))

        with patch(
            "civic_orchestrator.publication.urlopen",
            return_value=response,
        ) as mocked:
            result = self.client.publish(self.workflow_id, self.artifact)

        self.assertEqual(result, self.success_result())
        request = mocked.call_args.args[0]
        self.assertEqual(
            request.full_url,
            "http://publication.test:8046/v1/publications",
        )
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(
            request.get_header("Authorization"),
            f"Bearer {self.token}",
        )
        sent = json.loads(request.data.decode("utf-8"))
        self.assertEqual(
            sent,
            {
                "contract_version": 1,
                "workflow_id": self.workflow_id,
                "operation": "publication.publish",
                "artifact": self.artifact,
            },
        )
        self.contracts.validate(
            "publication-service-request-v1.schema.json",
            sent,
        )

    def test_known_single_raw_cid_vector(self):
        digest = hashlib.sha256(b"hello civic").hexdigest()
        self.assertEqual(
            expected_single_raw_cid(digest),
            "bafkreibqfrpsjusanrs6tthjrxvgutdlldbwtjr5zer2uvzfkfj3xsnh5e",
        )

    def test_declared_sha256_must_match_submitted_bytes_before_network(self):
        artifact = dict(self.artifact)
        artifact["sha256"] = "0" * 64

        with patch("civic_orchestrator.publication.urlopen") as mocked:
            with self.assertRaisesRegex(
                ValueError,
                "bytes do not match declared sha256",
            ):
                self.client.publish(self.workflow_id, artifact)

        mocked.assert_not_called()

    def test_result_cid_must_match_submitted_artifact(self):
        result = self.success_result()
        result["cid"] = "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        with patch(
            "civic_orchestrator.publication.urlopen",
            return_value=FakeResponse(200, self.encoded(result)),
        ):
            with self.assertRaisesRegex(
                PublicationServiceProtocolError,
                "CID that does not match",
            ):
                self.client.publish(self.workflow_id, self.artifact)

    def test_result_cid_profile_must_match_frozen_profile(self):
        result = self.success_result()
        result["cid_profile"] = "other-profile"

        with patch(
            "civic_orchestrator.publication.urlopen",
            return_value=FakeResponse(200, self.encoded(result)),
        ):
            with self.assertRaisesRegex(
                PublicationServiceProtocolError,
                "invalid publication service result",
            ):
                self.client.publish(self.workflow_id, self.artifact)

    def test_missing_service_credential_fails_before_network(self):
        client = PublicationServiceClient(
            "http://publication.test:8046",
            self.contracts.validate,
            timeout_seconds=2.0,
        )

        with patch("civic_orchestrator.publication.urlopen") as mocked:
            with self.assertRaises(PublicationServiceUnavailable) as caught:
                client.publish(self.workflow_id, self.artifact)

        mocked.assert_not_called()
        self.assertFalse(caught.exception.side_effects_possible)
        self.assertEqual(caught.exception.side_effects_certainty, "known")

    def test_service_authentication_failure_is_known_no_effect(self):
        http_error = HTTPError(
            "http://publication.test:8046/v1/publications",
            401,
            "Unauthorized",
            hdrs=None,
            fp=BytesIO(b"{}"),
        )

        with patch(
            "civic_orchestrator.publication.urlopen",
            side_effect=http_error,
        ):
            with self.assertRaises(PublicationServiceUnavailable) as caught:
                self.client.publish(self.workflow_id, self.artifact)

        self.assertFalse(caught.exception.side_effects_possible)
        self.assertEqual(caught.exception.side_effects_certainty, "known")
        self.assertIn("authentication failed", str(caught.exception))

    def test_service_failure_is_validated_and_preserved(self):
        failure = {
            "contract_version": 1,
            "workflow_id": self.workflow_id,
            "operation": "publication.publish",
            "failure_class": "service-unavailable",
            "message": "publication backend unavailable",
            "retryable": True,
        }
        http_error = HTTPError(
            "http://publication.test:8046/v1/publications",
            503,
            "Service Unavailable",
            hdrs=None,
            fp=BytesIO(self.encoded(failure)),
        )

        with patch(
            "civic_orchestrator.publication.urlopen",
            side_effect=http_error,
        ):
            with self.assertRaises(PublicationServiceFailure) as caught:
                self.client.publish(self.workflow_id, self.artifact)

        self.assertEqual(caught.exception.status_code, 503)
        self.assertEqual(
            caught.exception.failure_class,
            "service-unavailable",
        )
        self.assertTrue(caught.exception.retryable)
        self.assertEqual(caught.exception.response, failure)

    def test_malformed_failure_is_protocol_error(self):
        http_error = HTTPError(
            "http://publication.test:8046/v1/publications",
            503,
            "Service Unavailable",
            hdrs=None,
            fp=BytesIO(b"not-json"),
        )

        with patch(
            "civic_orchestrator.publication.urlopen",
            side_effect=http_error,
        ):
            with self.assertRaises(PublicationServiceProtocolError):
                self.client.publish(self.workflow_id, self.artifact)

    def test_transport_failure_is_service_unavailable(self):
        with patch(
            "civic_orchestrator.publication.urlopen",
            side_effect=URLError(ConnectionRefusedError("connection refused")),
        ):
            with self.assertRaises(PublicationServiceUnavailable) as caught:
                self.client.publish(self.workflow_id, self.artifact)

        self.assertFalse(caught.exception.side_effects_possible)
        self.assertEqual(caught.exception.side_effects_certainty, "known")

    def test_transport_timeout_has_unknown_side_effects(self):
        with patch(
            "civic_orchestrator.publication.urlopen",
            side_effect=TimeoutError("timed out after dispatch"),
        ):
            with self.assertRaises(PublicationServiceUnavailable) as caught:
                self.client.publish(self.workflow_id, self.artifact)

        self.assertTrue(caught.exception.side_effects_possible)
        self.assertEqual(caught.exception.side_effects_certainty, "unknown")

    def test_result_sha256_must_match_submitted_artifact(self):
        result = self.success_result()
        result["sha256"] = "0" * 64

        with patch(
            "civic_orchestrator.publication.urlopen",
            return_value=FakeResponse(200, self.encoded(result)),
        ):
            with self.assertRaisesRegex(
                PublicationServiceProtocolError,
                "different sha256",
            ):
                self.client.publish(self.workflow_id, self.artifact)

    def test_result_size_must_match_submitted_artifact(self):
        result = self.success_result()
        result["size_bytes"] += 1

        with patch(
            "civic_orchestrator.publication.urlopen",
            return_value=FakeResponse(200, self.encoded(result)),
        ):
            with self.assertRaisesRegex(
                PublicationServiceProtocolError,
                "different size_bytes",
            ):
                self.client.publish(self.workflow_id, self.artifact)

    def test_result_workflow_must_match_request(self):
        result = self.success_result()
        result["workflow_id"] = "wf:other"

        with patch(
            "civic_orchestrator.publication.urlopen",
            return_value=FakeResponse(200, self.encoded(result)),
        ):
            with self.assertRaisesRegex(
                PublicationServiceProtocolError,
                "different workflow_id",
            ):
                self.client.publish(self.workflow_id, self.artifact)

    def test_invalid_result_contract_is_protocol_error(self):
        result = self.success_result()
        result["pinned"] = False

        with patch(
            "civic_orchestrator.publication.urlopen",
            return_value=FakeResponse(200, self.encoded(result)),
        ):
            with self.assertRaisesRegex(
                PublicationServiceProtocolError,
                "invalid publication service result",
            ):
                self.client.publish(self.workflow_id, self.artifact)

    def test_invalid_service_request_fails_before_network_call(self):
        artifact = dict(self.artifact)
        artifact["encoding"] = "hex"

        with patch("civic_orchestrator.publication.urlopen") as mocked:
            with self.assertRaises(Exception):
                self.client.publish(self.workflow_id, artifact)

        mocked.assert_not_called()


if __name__ == "__main__":
    unittest.main()
