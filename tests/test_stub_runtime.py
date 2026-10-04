import tempfile
import threading
import unittest
from pathlib import Path

from civic_orchestrator.runtime import CivicOrchestrator, RuntimePaths


ROOT = Path(__file__).resolve().parents[1]


class StubRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.runtime = CivicOrchestrator(
            RuntimePaths(
                repo_root=ROOT,
                state_db=Path(self.tmp.name) / "state.sqlite3",
            )
        )

    def tearDown(self):
        self.tmp.cleanup()

    def request(self, operation="repository.fetch_exact"):
        return {
            "contract_version": 1,
            "request_id": "req:test-001",
            "operation": operation,
            "caller": {
                "subject": "participant:test",
                "authority": "test-authority",
                "authenticated_by": "test-authenticator",
            },
            "client": {
                "id": "test-client",
                "kind": "test",
            },
            "submitted_at": "2026-10-01T06:00:00Z",
            "input": {},
        }

    def test_known_operation_is_stubbed_without_side_effects(self):
        status, result = self.runtime.submit(self.request())
        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "not-implemented")
        self.assertFalse(result["side_effects"])
        self.assertTrue(result["workflow_id"].startswith("wf:"))
        self.assertTrue(result["receipt_id"].startswith("rcpt:"))

    def test_unknown_operation_fails_closed(self):
        status, result = self.runtime.submit(
            self.request("publication.unknown")
        )
        self.assertEqual(status, 400)
        self.assertEqual(result["failure_class"], "unknown-operation")
        self.assertEqual(result["operation"], "publication.unknown")
        self.assertFalse(result["side_effects"])

    def test_prohibited_operation_fails_at_schema_boundary(self):
        request = self.request()
        request["operation"] = "shell.exec"
        status, result = self.runtime.submit(request)
        self.assertEqual(status, 400)
        self.assertEqual(result["failure_class"], "invalid-contract")
        self.assertEqual(result["operation"], "audit.invalid_request")
        self.assertFalse(result["side_effects"])

    def test_invalid_contract_fails_closed(self):
        request = self.request()
        del request["caller"]
        status, result = self.runtime.submit(request)
        self.assertEqual(status, 400)
        self.assertEqual(result["failure_class"], "invalid-contract")
        self.assertFalse(result["side_effects"])

    def test_timestamp_format_is_enforced(self):
        request = self.request()
        request["submitted_at"] = "yesterday"
        status, result = self.runtime.submit(request)
        self.assertEqual(status, 400)
        self.assertEqual(result["failure_class"], "invalid-contract")

    def test_authentication_provenance_is_required(self):
        request = self.request()
        del request["caller"]["authenticated_by"]
        status, result = self.runtime.submit(request)
        self.assertEqual(status, 400)
        self.assertEqual(result["failure_class"], "invalid-contract")

    def test_client_identity_is_extensible(self):
        request = self.request()
        request["request_id"] = "req:cjdns-client"
        request["client"] = {
            "id": "cjdns-neighbor-service",
            "kind": "service",
        }
        status, result = self.runtime.submit(request)
        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "not-implemented")

        _, evidence = self.runtime.workflow_evidence(result["workflow_id"])
        accepted = evidence["audit_events"][1]
        self.assertEqual(
            accepted["data"]["client_id"],
            "cjdns-neighbor-service",
        )
        self.assertEqual(accepted["data"]["client_kind"], "service")

    def test_capability_advertisement_contains_activation_and_effect_scope(self):
        caps = self.runtime.capabilities()
        publication = next(
            item
            for item in caps["capabilities"]
            if item["operation"] == "publication.publish"
        )
        self.assertEqual(publication["implementation"], "available")
        self.assertEqual(
            publication["effect_scope"],
            "external-bounded",
        )
        available = {
            item["operation"]
            for item in caps["capabilities"]
            if item["implementation"] == "available"
        }
        self.assertEqual(available, {"publication.publish"})

    def test_incident_operations_are_bounded_stubs(self):
        caps = self.runtime.capabilities()
        operations = {item["operation"] for item in caps["capabilities"]}
        self.assertIn("incident.report", operations)
        self.assertIn("incident.get", operations)
        self.assertIn("incident.acknowledge", operations)
        self.assertIn("incident.resolve", operations)

        request = self.request("incident.report")
        request["request_id"] = "req:incident-test"
        status, result = self.runtime.submit(request)
        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "not-implemented")
        self.assertFalse(result["side_effects"])
        self.assertEqual(
            result["result"]["service_capability"],
            "incident.report",
        )
        self.assertEqual(
            result["result"]["effect_scope"],
            "orchestrator-state",
        )

    def test_workflow_evidence_is_ordered_and_schema_valid(self):
        status, result = self.runtime.submit(self.request())
        self.assertEqual(status, 200)

        evidence_status, evidence = self.runtime.workflow_evidence(
            result["workflow_id"]
        )
        self.assertEqual(evidence_status, 200)
        self.assertEqual(
            evidence["workflow"]["workflow_id"],
            result["workflow_id"],
        )
        self.assertEqual(
            evidence["workflow"]["state"],
            "not-implemented",
        )
        self.assertFalse(evidence["side_effects"])
        self.assertEqual(len(evidence["authorization_decisions"]), 1)
        self.assertEqual(len(evidence["audit_events"]), 4)
        self.assertEqual(
            [event["sequence"] for event in evidence["audit_events"]],
            [1, 2, 3, 4],
        )
        self.assertEqual(
            [event["event_type"] for event in evidence["audit_events"]],
            [
                "civic.authorization.allowed",
                "civic.operation.accepted",
                "civic.service.selected",
                "civic.operation.not-implemented",
            ],
        )
        self.assertEqual(len(evidence["receipts"]), 1)
        self.assertEqual(
            evidence["receipts"][0]["receipt_id"],
            result["receipt_id"],
        )

    def test_authorization_and_service_selection_are_evidenced(self):
        status, result = self.runtime.submit(self.request())
        self.assertEqual(status, 200)

        _, evidence = self.runtime.workflow_evidence(
            result["workflow_id"]
        )
        decision = evidence["authorization_decisions"][0]
        self.assertEqual(decision["decision"], "allow")
        self.assertEqual(decision["policy"], "stub-policy")

        selected = evidence["audit_events"][2]
        self.assertEqual(selected["event_type"], "civic.service.selected")
        self.assertEqual(
            selected["data"]["service_capability"],
            "repository.fetch_exact",
        )
        self.assertEqual(selected["data"]["implementation"], "stub")
        self.assertEqual(
            selected["data"]["effect_scope"],
            "none",
        )

    def test_idempotency_key_replays_original_result(self):
        request = self.request()
        request["idempotency_key"] = "idem:test-001"
        status, first = self.runtime.submit(request)
        self.assertEqual(status, 200)

        retry = self.request()
        retry["request_id"] = "req:test-001-retry"
        retry["submitted_at"] = "2026-10-01T06:01:00Z"
        retry["idempotency_key"] = "idem:test-001"
        status, second = self.runtime.submit(retry)

        self.assertEqual(status, 200)
        self.assertEqual(second["workflow_id"], first["workflow_id"])
        self.assertEqual(second["receipt_id"], first["receipt_id"])
        self.assertTrue(second["result"]["replayed"])

    def test_idempotency_key_conflict_fails_closed(self):
        request = self.request()
        request["idempotency_key"] = "idem:conflict"
        status, _ = self.runtime.submit(request)
        self.assertEqual(status, 200)

        conflicting = self.request()
        conflicting["request_id"] = "req:conflict-other"
        conflicting["idempotency_key"] = "idem:conflict"
        conflicting["input"] = {"different": True}
        status, result = self.runtime.submit(conflicting)

        self.assertEqual(status, 409)
        self.assertEqual(result["failure_class"], "conflict")
        self.assertFalse(result["side_effects"])

        with self.runtime.state._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM workflows"
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_duplicate_request_id_replays_same_semantic_request(self):
        status, first = self.runtime.submit(self.request())
        self.assertEqual(status, 200)

        retry = self.request()
        retry["submitted_at"] = "2026-10-01T06:02:00Z"
        status, second = self.runtime.submit(retry)

        self.assertEqual(status, 200)
        self.assertEqual(second["workflow_id"], first["workflow_id"])
        self.assertTrue(second["result"]["replayed"])

    def test_failure_envelope_normalizes_untrusted_values(self):
        failure = self.runtime.failure(
            request_id={"not": "an id"},
            operation="not an operation",
            failure_class="invalid-contract",
            message="x" * 5003,
            retryable=False,
        )
        self.runtime.contracts.validate(
            "failure-envelope-v1.schema.json",
            failure,
        )
        self.assertEqual(failure["request_id"], "invalid:request")
        self.assertEqual(failure["operation"], "audit.invalid_request")
        self.assertEqual(len(failure["message"]), 1000)

    def test_missing_workflow_evidence_fails_closed(self):
        status, result = self.runtime.workflow_evidence(
            "wf:does-not-exist"
        )
        self.assertEqual(status, 404)
        self.assertEqual(result["error"], "workflow-not-found")
        self.assertFalse(result["side_effects"])

    def test_invalid_workflow_transition_fails_closed(self):
        workflow_id = self.runtime.state.create_workflow(
            "req:transition-test",
            "publication.publish",
        )

        with self.assertRaisesRegex(
            ValueError,
            "invalid workflow transition: validated -> completed",
        ):
            self.runtime.state.transition(workflow_id, "completed")

        status, evidence = self.runtime.workflow_evidence(workflow_id)
        self.assertEqual(status, 200)
        self.assertEqual(evidence["workflow"]["state"], "validated")
        self.assertFalse(evidence["side_effects"])

    def test_threaded_submit_uses_safe_sqlite_transactions(self):
        results = []
        errors = []

        def worker(index):
            try:
                request = self.request()
                request["request_id"] = f"req:thread-{index}"
                request["input"] = {"thread": index}
                results.append(self.runtime.submit(request))
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(i,))
            for i in range(4)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 4)
        for status, result in results:
            self.assertEqual(status, 200)
            self.assertEqual(result["status"], "not-implemented")
            self.assertFalse(result["side_effects"])


    def test_rejections_conflicts_and_replays_leave_diagnostics(self):
        unknown = self.request("publication.unknown")
        unknown["request_id"] = "req:diag-unknown"
        self.runtime.submit(unknown)

        prohibited = self.request()
        prohibited["request_id"] = "req:diag-prohibited"
        prohibited["operation"] = "shell.exec"
        self.runtime.submit(prohibited)

        initial = self.request()
        initial["request_id"] = "req:diag-replay"
        initial["idempotency_key"] = "idem:diag"
        self.runtime.submit(initial)

        replay = self.request()
        replay["request_id"] = "req:diag-replay-2"
        replay["idempotency_key"] = "idem:diag"
        replay["submitted_at"] = "2026-10-01T06:03:00Z"
        self.runtime.submit(replay)

        conflict = self.request()
        conflict["request_id"] = "req:diag-conflict"
        conflict["idempotency_key"] = "idem:diag"
        conflict["input"] = {"different": True}
        self.runtime.submit(conflict)

        with self.runtime.state._connect() as conn:
            outcomes = [
                row[0]
                for row in conn.execute(
                    "SELECT outcome FROM request_diagnostics ORDER BY rowid"
                ).fetchall()
            ]

        self.assertIn("unknown-operation", outcomes)
        self.assertIn("invalid-contract", outcomes)
        self.assertIn("replay", outcomes)
        self.assertIn("conflict", outcomes)

    def test_request_and_idempotency_keys_are_scoped_to_caller_and_client(self):
        alice = self.request()
        alice["request_id"] = "req:shared"
        alice["idempotency_key"] = "idem:shared"
        status, first = self.runtime.submit(alice)
        self.assertEqual(status, 200)

        bob = self.request()
        bob["caller"] = {
            "subject": "participant:bob",
            "authority": "test-authority",
            "authenticated_by": "test-authenticator",
        }
        bob["request_id"] = "req:shared"
        bob["idempotency_key"] = "idem:shared"
        status, second = self.runtime.submit(bob)
        self.assertEqual(status, 200)
        self.assertNotEqual(second["workflow_id"], first["workflow_id"])

        other_client = self.request()
        other_client["client"] = {
            "id": "other-client",
            "kind": "test",
        }
        other_client["request_id"] = "req:shared"
        other_client["idempotency_key"] = "idem:shared"
        status, third = self.runtime.submit(other_client)
        self.assertEqual(status, 200)
        self.assertNotEqual(third["workflow_id"], first["workflow_id"])

    def test_idempotent_replay_echoes_current_request_id(self):
        original = self.request()
        original["request_id"] = "req:original"
        original["idempotency_key"] = "idem:echo"
        status, first = self.runtime.submit(original)
        self.assertEqual(status, 200)

        retry = self.request()
        retry["request_id"] = "req:retry"
        retry["idempotency_key"] = "idem:echo"
        retry["submitted_at"] = "2026-10-01T06:04:00Z"
        status, second = self.runtime.submit(retry)

        self.assertEqual(status, 200)
        self.assertEqual(second["request_id"], "req:retry")
        self.assertEqual(
            second["result"]["original_request_id"],
            "req:original",
        )
        self.assertEqual(second["workflow_id"], first["workflow_id"])

    def test_legacy_unscoped_request_does_not_collide(self):
        with self.runtime.state._connect() as conn:
            conn.execute(
                """
                INSERT INTO workflows
                    (workflow_id, request_id, operation, state,
                     created_at, updated_at, side_effects,
                     idempotency_key, request_fingerprint, result_json,
                     caller_subject, client_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "wf:legacy",
                    "req:legacy",
                    "publication.publish",
                    "not-implemented",
                    "2026-09-30T00:00:00Z",
                    "2026-09-30T00:00:00Z",
                    0,
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
            )

        request = self.request()
        request["request_id"] = "req:legacy"
        status, result = self.runtime.submit(request)
        self.assertEqual(status, 200)
        self.assertNotEqual(result["workflow_id"], "wf:legacy")

    def test_nonstandard_json_number_is_rejected(self):
        request = self.request()
        request["request_id"] = "req:nan"
        request["input"] = {"value": float("nan")}
        status, result = self.runtime.submit(request)
        self.assertEqual(status, 400)
        self.assertEqual(result["failure_class"], "invalid-contract")

    def test_schema_catalog_maps_every_listed_urn_to_matching_file(self):
        catalog_path = ROOT / "schemas" / "catalog-v1.json"
        import json
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))

        for entry in catalog["schemas"]:
            schema_path = ROOT / "schemas" / entry["path"]
            self.assertTrue(schema_path.exists(), entry["path"])
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            self.assertEqual(schema["$id"], entry["id"])


    def test_pyproject_declares_runtime_dependencies(self):
        import tomllib
        project = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]
        dependencies = "\n".join(project["dependencies"])
        self.assertIn("referencing", dependencies)
        self.assertIn("rfc3339-validator", dependencies)

    def test_workflow_evidence_reports_persisted_side_effects(self):
        workflow_id = self.runtime.state.create_workflow(
            "req:side-effect-projection",
            "publication.publish",
        )
        with self.runtime.state._connect() as conn:
            conn.execute(
                "UPDATE workflows SET side_effects=1 WHERE workflow_id=?",
                (workflow_id,),
            )

        status, evidence = self.runtime.workflow_evidence(workflow_id)

        self.assertEqual(status, 200)
        self.assertTrue(evidence["workflow"]["side_effects"])
        self.assertTrue(evidence["side_effects"])


if __name__ == "__main__":
    unittest.main()
