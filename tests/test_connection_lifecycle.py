"""Every SQLite connection the state store opens is closed again.

The sqlite3 connection context manager commits or rolls back but does not
close. This regression test records every connection opened by StateStore and
verifies that all request, replay, conflict, rejection, evidence, and helper
paths close their connections explicitly.
"""

import gc
import sqlite3
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

from civic_orchestrator import runtime
from civic_orchestrator.runtime import CivicOrchestrator, RuntimePaths


ROOT = Path(__file__).resolve().parents[1]


def request(
    operation="repository.fetch_exact",
    request_id="req:life-001",
    input_=None,
    subject="participant:test",
):
    return {
        "contract_version": 1,
        "request_id": request_id,
        "operation": operation,
        "caller": {
            "subject": subject,
            "authenticated_by": "test-authenticator",
        },
        "client": {
            "id": "test-client",
            "kind": "test",
        },
        "submitted_at": "2026-10-01T06:00:00Z",
        "input": {} if input_ is None else input_,
    }


class ConnectionLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.opened = []
        real_connect = sqlite3.connect

        def recording_connect(*args, **kwargs):
            conn = real_connect(*args, **kwargs)
            self.opened.append(conn)
            return conn

        patcher = mock.patch.object(
            runtime.sqlite3,
            "connect",
            side_effect=recording_connect,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        self.runtime = CivicOrchestrator(
            RuntimePaths(
                repo_root=ROOT,
                state_db=Path(self.tmp.name) / "state.sqlite3",
            )
        )

    def tearDown(self):
        self.tmp.cleanup()

    def exercise_every_state_path(self):
        status, first = self.runtime.submit(request())
        self.assertEqual(status, 200)

        self.runtime.submit(request())  # replay
        self.runtime.submit(request(input_={"different": True}))  # conflict
        self.runtime.submit(
            request(
                operation="shell.exec",
                request_id="req:life-bad",
            )
        )  # rejection diagnostic

        self.runtime.workflow_evidence(first["workflow_id"])
        self.runtime.workflow_evidence("wf:missing")

        workflow_id = self.runtime.state.create_workflow(
            "req:life-helper",
            "publication.publish",
        )
        self.runtime.state.transition(workflow_id, "authorized")

        with self.assertRaises(ValueError):
            self.runtime.state.transition(workflow_id, "completed")

        self.runtime.state.audit(
            workflow_id,
            "civic.test",
            "tester",
            {},
        )

    def test_every_connection_is_closed(self):
        self.exercise_every_state_path()
        self.assertGreater(len(self.opened), 5)

        still_open = []
        for conn in self.opened:
            try:
                conn.execute("SELECT 1")
            except sqlite3.ProgrammingError:
                continue
            still_open.append(conn)

        self.assertEqual(
            still_open,
            [],
            f"{len(still_open)} of {len(self.opened)} connections left open",
        )

    def test_rolled_back_conflict_left_no_partial_workflow(self):
        self.runtime.submit(request())
        status, _ = self.runtime.submit(
            request(input_={"different": True})
        )
        self.assertEqual(status, 409)

        with self.runtime.state._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM workflows"
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_no_resource_warning(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            self.exercise_every_state_path()
            gc.collect()

        leaks = [
            warning
            for warning in caught
            if issubclass(warning.category, ResourceWarning)
            and "database" in str(warning.message)
        ]
        self.assertEqual(leaks, [])


if __name__ == "__main__":
    unittest.main()
