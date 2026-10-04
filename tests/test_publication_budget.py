import json
import os
import tempfile
import unittest
from pathlib import Path

from civic_orchestrator.publication_budget import (
    PublicationBudgetExceeded,
    PublicationBudgetPolicy,
    load_publication_budget_policy,
)
from civic_orchestrator.runtime import StateStore


class PublicationBudgetPolicyTests(unittest.TestCase):
    def test_policy_requires_non_negative_integer_limits(self):
        with self.assertRaises(ValueError):
            PublicationBudgetPolicy(
                max_publications=-1,
                max_publication_bytes=1024,
            )
        with self.assertRaises(ValueError):
            PublicationBudgetPolicy(
                max_publications=1,
                max_publication_bytes=True,
            )




class PublicationBudgetConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = (
            Path(self.tmp.name).resolve() / "publication-budget-v1.json"
        )

    def tearDown(self):
        self.tmp.cleanup()

    def write_policy(self, value, mode=0o644):
        self.path.write_text(json.dumps(value), encoding="utf-8")
        self.path.chmod(mode)

    def valid_policy(self):
        return {
            "version": 1,
            "max_publications": 25,
            "max_publication_bytes": 5_000_000,
        }

    def load(self):
        return load_publication_budget_policy(
            self.path,
            required_owner_uid=os.geteuid(),
        )

    def test_loads_exact_policy_fields(self):
        self.write_policy(self.valid_policy())

        policy = self.load()

        self.assertEqual(policy.max_publications, 25)
        self.assertEqual(policy.max_publication_bytes, 5_000_000)

    def test_rejects_group_writable_policy(self):
        self.write_policy(self.valid_policy(), mode=0o664)

        with self.assertRaisesRegex(ValueError, "group/world writable"):
            self.load()

    def test_rejects_wrong_owner(self):
        self.write_policy(self.valid_policy())

        with self.assertRaisesRegex(ValueError, "invalid owner"):
            load_publication_budget_policy(
                self.path,
                required_owner_uid=os.geteuid() + 1,
            )

    def test_rejects_extra_policy_fields(self):
        value = self.valid_policy()
        value["extra"] = "no"
        self.write_policy(value)

        with self.assertRaisesRegex(ValueError, "fields are invalid"):
            self.load()

    def test_rejects_relative_policy_path(self):
        with self.assertRaisesRegex(ValueError, "must be absolute"):
            load_publication_budget_policy(
                Path("publication-budget-v1.json"),
                required_owner_uid=os.geteuid(),
            )

    def test_rejects_symlink_policy_path(self):
        self.write_policy(self.valid_policy())
        link = self.path.parent / "budget-link.json"
        link.symlink_to(self.path)

        with self.assertRaisesRegex(ValueError, "cannot be opened"):
            load_publication_budget_policy(
                link,
                required_owner_uid=os.geteuid(),
            )

class PublicationBudgetStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = StateStore(Path(self.tmp.name) / "state.sqlite3")
        self.policy = PublicationBudgetPolicy(
            max_publications=2,
            max_publication_bytes=100,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def workflow(self, request_id):
        return self.state.create_workflow(
            request_id,
            "publication.publish",
        )

    def test_reservation_is_charged_and_release_restores_capacity(self):
        workflow_id = self.workflow("req:budget-1")

        usage = self.state.reserve_publication_budget(
            workflow_id=workflow_id,
            participant_id="participant:test",
            size_bytes=40,
            policy=self.policy,
        )

        self.assertEqual(usage.charged_publications, 1)
        self.assertEqual(usage.charged_bytes, 40)
        self.assertEqual(
            self.state.publication_budget_usage(
                "participant:test"
            ).charged_bytes,
            40,
        )

        self.state.release_publication_budget_hold(workflow_id)

        usage = self.state.publication_budget_usage("participant:test")
        self.assertEqual(usage.charged_publications, 0)
        self.assertEqual(usage.charged_bytes, 0)

    def test_count_limit_is_enforced_before_second_excess_hold(self):
        first = self.workflow("req:budget-count-1")
        second = self.workflow("req:budget-count-2")
        third = self.workflow("req:budget-count-3")

        self.state.reserve_publication_budget(
            workflow_id=first,
            participant_id="participant:test",
            size_bytes=10,
            policy=self.policy,
        )
        self.state.reserve_publication_budget(
            workflow_id=second,
            participant_id="participant:test",
            size_bytes=10,
            policy=self.policy,
        )

        with self.assertRaises(PublicationBudgetExceeded):
            self.state.reserve_publication_budget(
                workflow_id=third,
                participant_id="participant:test",
                size_bytes=10,
                policy=self.policy,
            )

        usage = self.state.publication_budget_usage("participant:test")
        self.assertEqual(usage.charged_publications, 2)
        self.assertEqual(usage.charged_bytes, 20)

    def test_byte_limit_is_enforced_atomically(self):
        first = self.workflow("req:budget-bytes-1")
        second = self.workflow("req:budget-bytes-2")

        self.state.reserve_publication_budget(
            workflow_id=first,
            participant_id="participant:test",
            size_bytes=70,
            policy=self.policy,
        )

        with self.assertRaises(PublicationBudgetExceeded):
            self.state.reserve_publication_budget(
                workflow_id=second,
                participant_id="participant:test",
                size_bytes=31,
                policy=self.policy,
            )

        usage = self.state.publication_budget_usage("participant:test")
        self.assertEqual(usage.charged_publications, 1)
        self.assertEqual(usage.charged_bytes, 70)

    def test_uncertain_hold_remains_charged(self):
        workflow_id = self.workflow("req:budget-uncertain")
        self.state.reserve_publication_budget(
            workflow_id=workflow_id,
            participant_id="participant:test",
            size_bytes=25,
            policy=self.policy,
        )

        self.state.mark_publication_budget_hold(
            workflow_id,
            "uncertain",
        )

        usage = self.state.publication_budget_usage("participant:test")
        self.assertEqual(usage.charged_publications, 1)
        self.assertEqual(usage.charged_bytes, 25)

        with self.state._connect() as conn:
            row = conn.execute(
                """
                SELECT hold_state
                  FROM publication_budget_holds
                 WHERE workflow_id=?
                """,
                (workflow_id,),
            ).fetchone()
        self.assertEqual(row[0], "uncertain")

    def test_reconcile_no_effect_restores_reserved_hold_and_known_state(self):
        workflow_id = self.workflow("req:budget-reconcile")
        self.state.reserve_publication_budget(
            workflow_id=workflow_id,
            participant_id="participant:test",
            size_bytes=25,
            policy=self.policy,
        )
        self.state.transition(workflow_id, "authorized")
        self.state.transition(workflow_id, "accepted")
        self.state.pause_external_operation(
            workflow_id=workflow_id,
            failure_class="internal",
            message="uncertain dispatch",
            retryable=True,
            side_effects=True,
            side_effects_certainty="unknown",
            validate_contract=lambda *_: None,
        )

        event_id = self.state.reconcile_publication_no_effect(
            workflow_id,
            actor="operator:test",
            reason="backend was proved incapable of side effects",
            validate_contract=lambda *_: None,
        )

        evidence = self.state.get_workflow_evidence(workflow_id)
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["workflow"]["state"], "waiting")
        self.assertFalse(evidence["workflow"]["side_effects"])
        self.assertEqual(
            evidence["workflow"]["side_effects_certainty"],
            "known",
        )
        self.assertEqual(
            evidence["audit_events"][-1]["event_id"],
            event_id,
        )
        self.assertEqual(
            evidence["audit_events"][-1]["event_type"],
            "civic.operation.reconciled",
        )
        self.assertEqual(
            evidence["audit_events"][-1]["data"]["resolution"],
            "no-external-side-effect",
        )

        with self.state._connect() as conn:
            row = conn.execute(
                """
                SELECT hold_state
                  FROM publication_budget_holds
                 WHERE workflow_id=?
                """,
                (workflow_id,),
            ).fetchone()
        self.assertEqual(row[0], "reserved")

    def test_reconcile_no_effect_rejects_non_waiting_workflow(self):
        workflow_id = self.workflow("req:budget-reconcile-invalid")
        self.state.reserve_publication_budget(
            workflow_id=workflow_id,
            participant_id="participant:test",
            size_bytes=25,
            policy=self.policy,
        )

        with self.assertRaisesRegex(ValueError, "not waiting"):
            self.state.reconcile_publication_no_effect(
                workflow_id,
                actor="operator:test",
                reason="should fail",
                validate_contract=lambda *_: None,
            )


if __name__ == "__main__":
    unittest.main()
