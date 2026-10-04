import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from civic_orchestrator.publication_budget import PublicationBudgetPolicy
from civic_orchestrator.publication import (
    CID_PROFILE,
    PublicationServiceFailure,
    PublicationServiceProtocolError,
    PublicationServiceUnavailable,
    expected_single_raw_cid,
)
from civic_orchestrator.runtime import CivicOrchestrator, RuntimePaths


ROOT = Path(__file__).resolve().parents[1]


class FakePublicationClient:
    def __init__(self, mode="success"):
        self.mode = mode
        self.calls = []

    def publish(self, workflow_id, artifact):
        self.calls.append((workflow_id, artifact))
        if self.mode == "service-failure":
            raise PublicationServiceFailure(
                status_code=503,
                failure_class="service-unavailable",
                message="publication backend unavailable",
                retryable=True,
                response={
                    "contract_version": 1,
                    "workflow_id": workflow_id,
                    "operation": "publication.publish",
                    "failure_class": "service-unavailable",
                    "message": "publication backend unavailable",
                    "retryable": True,
                },
            )
        if self.mode == "transport-failure":
            raise PublicationServiceUnavailable(
                "connection refused",
                side_effects_possible=False,
                side_effects_certainty="known",
            )
        if self.mode == "transport-timeout":
            raise PublicationServiceUnavailable(
                "timed out after dispatch",
                side_effects_possible=True,
                side_effects_certainty="unknown",
            )
        if self.mode == "protocol-failure":
            raise PublicationServiceProtocolError("invalid service result")
        if self.mode == "unexpected-failure":
            raise RuntimeError("unexpected adapter defect")

        return {
            "contract_version": 1,
            "workflow_id": workflow_id,
            "operation": "publication.publish",
            "sha256": artifact["sha256"],
            "size_bytes": artifact["size_bytes"],
            "cid": expected_single_raw_cid(artifact["sha256"]),
            "cid_profile": CID_PROFILE,
            "pinned": True,
            "verified": True,
        }


class PublicationRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.client = FakePublicationClient()
        self.policy = PublicationBudgetPolicy(
            max_publications=10,
            max_publication_bytes=2_621_440,
        )
        self.runtime = CivicOrchestrator(
            RuntimePaths(
                repo_root=ROOT,
                state_db=Path(self.tmp.name) / "state.sqlite3",
            ),
            publication_client=self.client,
            publication_budget_policy=self.policy,
        )
        self.runtime.registry.operations["publication.publish"][
            "implementation"
        ] = "available"
        self.payload = b"civic publication\n"
        self.artifact = {
            "media_type": "text/plain",
            "size_bytes": len(self.payload),
            "sha256": hashlib.sha256(self.payload).hexdigest(),
            "encoding": "base64",
            "content": base64.b64encode(self.payload).decode("ascii"),
        }

    def tearDown(self):
        self.tmp.cleanup()

    def request(self):
        return {
            "contract_version": 1,
            "request_id": "req:publication-runtime-001",
            "operation": "publication.publish",
            "caller": {
                "subject": "participant:test",
                "authority": "test-authority",
                "authenticated_by": "test-authenticator",
            },
            "client": {
                "id": "test-client",
                "kind": "test",
            },
            "submitted_at": "2026-10-01T17:00:00Z",
            "idempotency_key": "idem:publication-runtime-001",
            "input": {
                "artifact": self.artifact,
            },
        }

    def test_publication_success_completes_existing_workflow_model(self):
        status, result = self.runtime.submit(self.request())

        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["side_effects"])
        self.assertEqual(result["result"]["sha256"], self.artifact["sha256"])
        self.assertEqual(
            result["result"]["cid"],
            expected_single_raw_cid(self.artifact["sha256"]),
        )
        self.assertEqual(result["result"]["cid_profile"], CID_PROFILE)
        self.assertTrue(result["result"]["pinned"])
        self.assertTrue(result["result"]["verified"])
        self.assertEqual(result["result"]["side_effects_certainty"], "known")
        self.assertTrue(result["result"]["publication_id"].startswith("pub:"))
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(self.client.calls[0][1], self.artifact)

        evidence_status, evidence = self.runtime.workflow_evidence(
            result["workflow_id"]
        )
        self.assertEqual(evidence_status, 200)
        self.assertEqual(evidence["workflow"]["state"], "completed")
        self.assertTrue(evidence["workflow"]["side_effects"])
        self.assertEqual(
            evidence["workflow"]["side_effects_certainty"],
            "known",
        )
        self.assertTrue(evidence["side_effects"])
        self.assertEqual(evidence["side_effects_certainty"], "known")
        self.assertEqual(
            [event["event_type"] for event in evidence["audit_events"]],
            [
                "civic.authorization.allowed",
                "civic.operation.accepted",
                "civic.service.selected",
                "civic.operation.completed",
            ],
        )
        self.assertEqual(
            evidence["authorization_decisions"][0]["policy"],
            "publication-policy-v1",
        )
        self.assertEqual(evidence["receipts"][0]["outcome"], "completed")
        self.assertTrue(evidence["receipts"][0]["side_effects"])
        self.assertEqual(
            evidence["receipts"][0]["evidence"]["cid"],
            result["result"]["cid"],
        )

        with self.runtime.state._connect() as conn:
            publication = conn.execute(
                """
                SELECT publication_id, participant_id, sha256, size_bytes,
                       media_type, cid, cid_profile, workflow_id, receipt_id,
                       client_id, authenticated_by, verified
                  FROM publications
                 WHERE workflow_id=?
                """,
                (result["workflow_id"],),
            ).fetchone()
        self.assertIsNotNone(publication)
        self.assertEqual(publication[0], result["result"]["publication_id"])
        self.assertEqual(publication[1], "participant:test")
        self.assertEqual(publication[2], self.artifact["sha256"])
        self.assertEqual(publication[5], result["result"]["cid"])
        self.assertEqual(publication[6], CID_PROFILE)
        self.assertEqual(publication[10], "test-authenticator")
        self.assertEqual(publication[11], 1)

        usage = self.runtime.state.publication_budget_usage(
            "participant:test"
        )
        self.assertEqual(usage.completed_publications, 1)
        self.assertEqual(usage.held_publications, 0)
        self.assertEqual(usage.charged_bytes, len(self.payload))

    def test_budget_denial_is_terminal_replayable_and_never_dispatched(self):
        self.runtime.publication_budget_policy = PublicationBudgetPolicy(
            max_publications=0,
            max_publication_bytes=0,
        )
        request = self.request()

        status, result = self.runtime.submit(request)

        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "rejected")
        self.assertFalse(result["side_effects"])
        self.assertEqual(self.client.calls, [])

        _, evidence = self.runtime.workflow_evidence(result["workflow_id"])
        self.assertEqual(evidence["workflow"]["state"], "rejected")
        self.assertEqual(
            evidence["authorization_decisions"][0]["decision"],
            "deny",
        )
        self.assertEqual(
            evidence["audit_events"][0]["event_type"],
            "civic.authorization.denied",
        )
        self.assertEqual(evidence["receipts"][0]["outcome"], "rejected")

        retry = self.request()
        retry["request_id"] = "req:publication-budget-retry"
        status, replay = self.runtime.submit(retry)
        self.assertEqual(status, 200)
        self.assertEqual(replay["status"], "rejected")
        self.assertTrue(replay["result"]["replayed"])
        self.assertEqual(replay["workflow_id"], result["workflow_id"])
        self.assertEqual(self.client.calls, [])

    def test_missing_budget_policy_fails_before_workflow(self):
        self.runtime.publication_budget_policy = None

        status, result = self.runtime.submit(self.request())

        self.assertEqual(status, 503)
        self.assertEqual(result["failure_class"], "backend-unavailable")
        self.assertIn("budget policy", result["message"])
        self.assertEqual(self.client.calls, [])
        with self.runtime.state._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM workflows"
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_publication_specific_input_is_validated_before_backend_call(self):
        request = self.request()
        request["input"]["artifact"]["encoding"] = "hex"

        status, result = self.runtime.submit(request)

        self.assertEqual(status, 400)
        self.assertEqual(result["failure_class"], "invalid-contract")
        self.assertFalse(result["side_effects"])
        self.assertEqual(self.client.calls, [])

    def test_artifact_integrity_failure_creates_no_workflow_or_backend_call(self):
        request = self.request()
        request["input"]["artifact"]["sha256"] = "0" * 64

        status, result = self.runtime.submit(request)

        self.assertEqual(status, 400)
        self.assertEqual(result["failure_class"], "invalid-contract")
        self.assertFalse(result["side_effects"])
        self.assertEqual(self.client.calls, [])
        with self.runtime.state._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM workflows"
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_retryable_service_failure_waits_and_can_resume(self):
        self.client.mode = "service-failure"

        status, failure = self.runtime.submit(self.request())

        self.assertEqual(status, 503)
        self.assertEqual(failure["failure_class"], "backend-unavailable")
        self.assertFalse(failure["side_effects"])
        self.assertTrue(failure["retryable"])
        workflow_id = failure["detail"]["workflow_id"]
        self.assertEqual(failure["detail"]["workflow_state"], "waiting")
        self.assertEqual(
            failure["detail"]["side_effects_certainty"],
            "known",
        )

        _, evidence = self.runtime.workflow_evidence(workflow_id)
        self.assertEqual(evidence["workflow"]["state"], "waiting")
        self.assertFalse(evidence["workflow"]["side_effects"])
        self.assertEqual(
            evidence["workflow"]["side_effects_certainty"],
            "known",
        )
        self.assertEqual(evidence["receipts"], [])
        self.assertEqual(
            evidence["audit_events"][-1]["event_type"],
            "civic.operation.waiting",
        )

        usage = self.runtime.state.publication_budget_usage(
            "participant:test"
        )
        self.assertEqual(usage.held_publications, 1)
        self.assertEqual(usage.completed_publications, 0)

        self.client.mode = "success"
        retry = self.request()
        retry["request_id"] = "req:publication-runtime-retry"
        retry["submitted_at"] = "2026-10-01T17:01:00Z"
        status, result = self.runtime.submit(retry)

        self.assertEqual(status, 200)
        self.assertEqual(result["workflow_id"], workflow_id)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(self.client.calls), 2)

        _, evidence = self.runtime.workflow_evidence(workflow_id)
        self.assertEqual(evidence["workflow"]["state"], "completed")
        self.assertEqual(len(evidence["receipts"]), 1)
        self.assertIn(
            "civic.operation.resumed",
            [event["event_type"] for event in evidence["audit_events"]],
        )

    def test_verification_failure_is_conservatively_side_effecting(self):
        def fail_after_publication(workflow_id, artifact):
            raise PublicationServiceFailure(
                status_code=500,
                failure_class="verification-failed",
                message="read-back verification failed",
                retryable=False,
                response={
                    "contract_version": 1,
                    "workflow_id": workflow_id,
                    "operation": "publication.publish",
                    "failure_class": "verification-failed",
                    "message": "read-back verification failed",
                    "retryable": False,
                },
            )

        self.client.publish = fail_after_publication

        status, result = self.runtime.submit(self.request())

        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["side_effects"])
        self.assertEqual(
            result["result"]["failure_class"],
            "verification-failed",
        )
        usage = self.runtime.state.publication_budget_usage(
            "participant:test"
        )
        self.assertEqual(usage.held_publications, 1)
        with self.runtime.state._connect() as conn:
            hold_state = conn.execute(
                """
                SELECT hold_state
                  FROM publication_budget_holds
                 WHERE participant_id=?
                """,
                ("participant:test",),
            ).fetchone()[0]
        self.assertEqual(hold_state, "uncertain")

    def test_connection_refused_is_known_no_effect_waiting_failure(self):
        self.client.mode = "transport-failure"

        status, failure = self.runtime.submit(self.request())

        self.assertEqual(status, 503)
        self.assertEqual(failure["failure_class"], "backend-unavailable")
        self.assertFalse(failure["side_effects"])
        self.assertTrue(failure["retryable"])
        self.assertEqual(
            failure["detail"]["side_effects_certainty"],
            "known",
        )

        _, evidence = self.runtime.workflow_evidence(
            failure["detail"]["workflow_id"]
        )
        self.assertEqual(evidence["workflow"]["state"], "waiting")
        self.assertFalse(evidence["workflow"]["side_effects"])
        self.assertEqual(
            evidence["workflow"]["side_effects_certainty"],
            "known",
        )

    def test_transport_timeout_is_unknown_possible_effect_waiting_failure(self):
        self.client.mode = "transport-timeout"

        status, failure = self.runtime.submit(self.request())

        self.assertEqual(status, 503)
        self.assertTrue(failure["side_effects"])
        self.assertEqual(
            failure["detail"]["side_effects_certainty"],
            "unknown",
        )

        _, evidence = self.runtime.workflow_evidence(
            failure["detail"]["workflow_id"]
        )
        self.assertTrue(evidence["workflow"]["side_effects"])
        self.assertEqual(
            evidence["workflow"]["side_effects_certainty"],
            "unknown",
        )

    def test_protocol_failure_waits_with_unknown_effects(self):
        self.client.mode = "protocol-failure"

        status, failure = self.runtime.submit(self.request())

        self.assertEqual(status, 502)
        self.assertEqual(failure["failure_class"], "internal")
        self.assertTrue(failure["side_effects"])
        self.assertTrue(failure["retryable"])
        self.assertEqual(
            failure["detail"]["side_effects_certainty"],
            "unknown",
        )

    def test_unexpected_adapter_failure_waits_for_operator_recovery(self):
        self.client.mode = "unexpected-failure"

        status, failure = self.runtime.submit(self.request())

        self.assertEqual(status, 500)
        self.assertEqual(failure["failure_class"], "internal")
        self.assertTrue(failure["side_effects"])
        self.assertFalse(failure["retryable"])
        self.assertIn(
            "unexpected publication adapter failure",
            failure["message"],
        )

        _, evidence = self.runtime.workflow_evidence(
            failure["detail"]["workflow_id"]
        )
        self.assertEqual(evidence["workflow"]["state"], "waiting")
        self.assertEqual(evidence["receipts"], [])

    def test_restart_reconciles_accepted_publication_for_same_workflow_retry(self):
        request = self.request()
        descriptor = self.runtime.registry.lookup("publication.publish")
        start, replayed = self.runtime.state.begin_external_operation(
            request,
            descriptor,
            "publication-policy-v1",
            "test crash boundary",
            self.runtime.contracts.validate,
            publication_budget_policy=self.policy,
        )
        self.assertFalse(replayed)
        workflow_id = start["workflow_id"]

        restarted_client = FakePublicationClient()
        restarted = CivicOrchestrator(
            RuntimePaths(
                repo_root=ROOT,
                state_db=Path(self.tmp.name) / "state.sqlite3",
            ),
            publication_client=restarted_client,
            publication_budget_policy=self.policy,
        )

        _, evidence = restarted.workflow_evidence(workflow_id)
        self.assertEqual(evidence["workflow"]["state"], "waiting")
        self.assertTrue(evidence["workflow"]["side_effects"])
        self.assertEqual(
            evidence["workflow"]["side_effects_certainty"],
            "unknown",
        )
        self.assertEqual(
            evidence["audit_events"][-1]["event_type"],
            "civic.operation.recovery-pending",
        )

        status, result = restarted.submit(request)
        self.assertEqual(status, 200)
        self.assertEqual(result["workflow_id"], workflow_id)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(restarted_client.calls), 1)

    def test_restart_after_backend_success_redispatches_same_workflow(self):
        request = self.request()
        descriptor = self.runtime.registry.lookup("publication.publish")
        start, replayed = self.runtime.state.begin_external_operation(
            request,
            descriptor,
            "publication-policy-v1",
            "test crash after backend success",
            self.runtime.contracts.validate,
            publication_budget_policy=self.policy,
        )
        self.assertFalse(replayed)
        workflow_id = start["workflow_id"]

        # Simulate the exact crash window: the publication service accepted the
        # workflow and returned success, but the Orchestrator died before terminal evidence
        # was committed.
        service_result = self.client.publish(workflow_id, self.artifact)
        self.assertEqual(service_result["workflow_id"], workflow_id)
        self.assertEqual(len(self.client.calls), 1)

        restarted_client = FakePublicationClient()
        restarted = CivicOrchestrator(
            RuntimePaths(
                repo_root=ROOT,
                state_db=Path(self.tmp.name) / "state.sqlite3",
            ),
            publication_client=restarted_client,
            publication_budget_policy=self.policy,
        )

        _, evidence = restarted.workflow_evidence(workflow_id)
        self.assertEqual(evidence["workflow"]["state"], "waiting")
        self.assertTrue(evidence["workflow"]["side_effects"])
        self.assertEqual(
            evidence["workflow"]["side_effects_certainty"],
            "unknown",
        )

        status, result = restarted.submit(request)

        self.assertEqual(status, 200)
        self.assertEqual(result["workflow_id"], workflow_id)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(restarted_client.calls), 1)
        self.assertEqual(restarted_client.calls[0][0], workflow_id)

    def test_publication_replay_does_not_call_backend_twice(self):
        request = self.request()
        status, first = self.runtime.submit(request)
        self.assertEqual(status, 200)

        retry = self.request()
        retry["request_id"] = "req:publication-runtime-002"
        retry["submitted_at"] = "2026-10-01T17:01:00Z"
        status, second = self.runtime.submit(retry)

        self.assertEqual(status, 200)
        self.assertEqual(second["workflow_id"], first["workflow_id"])
        self.assertEqual(second["receipt_id"], first["receipt_id"])
        self.assertTrue(second["result"]["replayed"])
        self.assertEqual(
            second["result"]["original_request_id"],
            first["request_id"],
        )
        self.assertEqual(len(self.client.calls), 1)

    def test_other_operations_remain_on_stub_path(self):
        request = self.request()
        request["request_id"] = "req:repository-stub"
        request["operation"] = "repository.fetch_exact"
        request["idempotency_key"] = "idem:repository-stub"
        request["input"] = {}

        status, result = self.runtime.submit(request)

        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "not-implemented")
        self.assertFalse(result["side_effects"])
        self.assertEqual(result["result"]["implementation"], "stub")
        self.assertEqual(len(self.client.calls), 0)

    def test_available_publication_without_client_fails_before_workflow(self):
        runtime = CivicOrchestrator(
            RuntimePaths(
                repo_root=ROOT,
                state_db=Path(self.tmp.name) / "no-client.sqlite3",
            ),
            publication_budget_policy=self.policy,
        )
        runtime.registry.operations["publication.publish"][
            "implementation"
        ] = "available"

        status, result = runtime.submit(self.request())

        self.assertEqual(status, 500)
        self.assertEqual(result["failure_class"], "backend-unavailable")
        self.assertFalse(result["side_effects"])

        with runtime.state._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM workflows"
            ).fetchone()[0]
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
