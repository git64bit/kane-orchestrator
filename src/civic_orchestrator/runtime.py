from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

import yaml
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource
from rfc3339_validator import validate_rfc3339

from .publication import (
    PublicationServiceFailure,
    PublicationServiceProtocolError,
    PublicationServiceUnavailable,
    validate_artifact_integrity,
)
from .publication_budget import (
    PublicationBudgetExceeded,
    PublicationBudgetPolicy,
    PublicationBudgetUsage,
)


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,159}$")
_OPERATION_RE = re.compile(
    r"^(publication|geography|participant|repository|rag|inference|edge|firmware|"
    r"signing|audit|incident)\.[a-z][a-z0-9._-]{0,159}$"
)

CIVIC_FORMAT_CHECKER = FormatChecker()

@CIVIC_FORMAT_CHECKER.checks("date-time")
def _is_rfc3339_datetime(value: object) -> bool:
    return isinstance(value, str) and bool(validate_rfc3339(value))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


class ConflictError(ValueError):
    pass


class AdapterIdentityError(ValueError):
    pass


@dataclass(frozen=True)
class AuthenticatedAdapterBinding:
    client_id: str
    client_kind: str
    authenticated_by: str
    caller_authority: str
    subject_prefix: str

    def validate_request(self, request: dict[str, Any]) -> None:
        caller = request["caller"]
        client = request["client"]

        if client["id"] != self.client_id:
            raise AdapterIdentityError(
                "client.id does not match authenticated adapter"
            )
        if client["kind"] != self.client_kind:
            raise AdapterIdentityError(
                "client.kind does not match authenticated adapter"
            )
        if caller["authenticated_by"] != self.authenticated_by:
            raise AdapterIdentityError(
                "caller.authenticated_by does not match authenticated adapter"
            )
        if caller.get("authority") != self.caller_authority:
            raise AdapterIdentityError(
                "caller.authority does not match authenticated adapter"
            )

        subject = caller["subject"]
        if (
            not subject.startswith(self.subject_prefix)
            or len(subject) <= len(self.subject_prefix)
        ):
            raise AdapterIdentityError(
                "caller.subject is outside authenticated adapter namespace"
            )


@dataclass(frozen=True)
class RuntimePaths:
    repo_root: Path
    state_db: Path


class ContractStore:
    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root
        self.schemas_dir = repo_root / "schemas"
        self._schemas: dict[str, dict[str, Any]] = {}
        self._validators: dict[str, Draft202012Validator] = {}
        self._load()

    def _load(self) -> None:
        registry = Registry()

        for path in self.schemas_dir.glob("*.schema.json"):
            schema = json.loads(path.read_text(encoding="utf-8"))
            self._schemas[path.name] = schema

        for schema in self._schemas.values():
            schema_id = schema.get("$id")
            if not schema_id:
                raise ValueError("every Civic schema must have an absolute $id")
            registry = registry.with_resource(
                schema_id,
                Resource.from_contents(schema),
            )

        for name, schema in self._schemas.items():
            self._validators[name] = Draft202012Validator(
                schema,
                registry=registry,
                format_checker=CIVIC_FORMAT_CHECKER,
            )

    def validate(self, schema_name: str, instance: Any) -> None:
        validator = self._validators[schema_name]
        errors = sorted(
            validator.iter_errors(instance),
            key=lambda e: list(e.absolute_path),
        )
        if errors:
            err = errors[0]
            path = ".".join(str(p) for p in err.absolute_path) or "$"
            raise ValidationError(f"{path}: {err.message}")


class OperationRegistry:
    def __init__(self, path: Path, contracts: ContractStore) -> None:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        contracts.validate("operation-registry-v1.schema.json", raw)

        operations = [item["operation"] for item in raw["operations"]]
        if len(operations) != len(set(operations)):
            raise ValueError("operation registry contains duplicate operations")

        self.contract_version = raw["contract_version"]
        self.operations = {item["operation"]: item for item in raw["operations"]}
        self.prohibited = set(raw.get("prohibited_generic_operations", []))

    def lookup(self, operation: str) -> dict[str, Any] | None:
        return self.operations.get(operation)


class StubWorkflowDefinition:
    def __init__(self, path: Path, contracts: ContractStore) -> None:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        contracts.validate("stub-workflow-definition-v1.schema.json", raw)
        self.authorization_policy = raw["authorization_policy"]
        self.accepted_namespaces = set(raw["accepted_namespaces"])
        self.constraints = raw["constraints"]

    def accepts(self, operation: str) -> bool:
        namespace = operation.split(".", 1)[0]
        return namespace in self.accepted_namespaces


class PublicationWorkflowDefinition:
    def __init__(self, path: Path, contracts: ContractStore) -> None:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        contracts.validate(
            "publication-workflow-definition-v1.schema.json",
            raw,
        )
        self.workflow = raw["workflow"]
        self.version = raw["version"]
        self.operation = raw["operation"]
        self.authorization_policy = raw["authorization_policy"]
        self.authorization_reason = raw["authorization_reason"]
        self.service_capability = raw["service_capability"]
        self.steps = tuple(raw["steps"])
        self.constraints = raw["constraints"]


class StateStore:
    ALLOWED_TRANSITIONS = {
        "received": {"validated", "rejected", "failed"},
        "validated": {"authorized", "rejected", "failed"},
        "authorized": {"accepted", "rejected", "failed"},
        "accepted": {"waiting", "completed", "failed", "not-implemented"},
        "waiting": {"accepted", "completed", "rejected", "failed"},
        "completed": set(),
        "rejected": set(),
        "failed": set(),
        "not-implemented": set(),
    }

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open one SQLite connection for a state operation and always close it.

        The inner connection context preserves sqlite3 commit/rollback
        semantics, including explicit BEGIN IMMEDIATE issued by callers.
        The outer finally guarantees the connection itself is closed.
        """
        conn = sqlite3.connect(self.db_path, timeout=30)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            with conn:
                yield conn
        finally:
            conn.close()

    @staticmethod
    def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS workflows (
                    workflow_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    side_effects INTEGER NOT NULL CHECK(side_effects IN (0,1))
                );

                CREATE TABLE IF NOT EXISTS authorization_decisions (
                    decision_id TEXT PRIMARY KEY,
                    workflow_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    decided_at TEXT NOT NULL,
                    policy TEXT NOT NULL,
                    reason TEXT,
                    FOREIGN KEY(workflow_id) REFERENCES workflows(workflow_id)
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    workflow_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    FOREIGN KEY(workflow_id) REFERENCES workflows(workflow_id)
                );

                CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id TEXT PRIMARY KEY,
                    workflow_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    side_effects INTEGER NOT NULL CHECK(side_effects IN (0,1)),
                    evidence_json TEXT NOT NULL,
                    FOREIGN KEY(workflow_id) REFERENCES workflows(workflow_id)
                );

                CREATE TABLE IF NOT EXISTS publications (
                    publication_id TEXT PRIMARY KEY,
                    workflow_id TEXT NOT NULL UNIQUE,
                    receipt_id TEXT NOT NULL,
                    participant_id TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    media_type TEXT NOT NULL,
                    cid TEXT NOT NULL,
                    cid_profile TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    authenticated_by TEXT NOT NULL,
                    verified INTEGER NOT NULL CHECK(verified IN (0,1)),
                    FOREIGN KEY(workflow_id) REFERENCES workflows(workflow_id),
                    FOREIGN KEY(receipt_id) REFERENCES receipts(receipt_id)
                );

                CREATE TABLE IF NOT EXISTS request_diagnostics (
                    diagnostic_id TEXT PRIMARY KEY,
                    recorded_at TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    request_id TEXT,
                    operation TEXT,
                    caller_subject TEXT,
                    client_id TEXT,
                    detail TEXT
                );

                CREATE TABLE IF NOT EXISTS publication_budget_holds (
                    workflow_id TEXT PRIMARY KEY,
                    participant_id TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
                    hold_state TEXT NOT NULL
                        CHECK(hold_state IN ('reserved','uncertain')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(workflow_id) REFERENCES workflows(workflow_id)
                );
                """
            )

            workflow_columns = self._columns(conn, "workflows")
            if "idempotency_key" not in workflow_columns:
                conn.execute("ALTER TABLE workflows ADD COLUMN idempotency_key TEXT")
            if "request_fingerprint" not in workflow_columns:
                conn.execute("ALTER TABLE workflows ADD COLUMN request_fingerprint TEXT")
            if "result_json" not in workflow_columns:
                conn.execute("ALTER TABLE workflows ADD COLUMN result_json TEXT")
            if "caller_subject" not in workflow_columns:
                conn.execute("ALTER TABLE workflows ADD COLUMN caller_subject TEXT")
            if "client_id" not in workflow_columns:
                conn.execute("ALTER TABLE workflows ADD COLUMN client_id TEXT")

            if "side_effects_certainty" not in workflow_columns:
                conn.execute(
                    "ALTER TABLE workflows ADD COLUMN "
                    "side_effects_certainty TEXT NOT NULL DEFAULT 'known'"
                )

            audit_columns = self._columns(conn, "audit_events")
            if "sequence" not in audit_columns:
                conn.execute(
                    "ALTER TABLE audit_events ADD COLUMN sequence INTEGER NOT NULL DEFAULT 0"
                )

            conn.execute(
                "CREATE INDEX IF NOT EXISTS workflows_request_scope_idx "
                "ON workflows(client_id, caller_subject, request_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS workflows_idempotency_scope_idx "
                "ON workflows(client_id, caller_subject, idempotency_key)"
            )

            conn.execute(
                "CREATE INDEX IF NOT EXISTS publications_participant_idx "
                "ON publications(participant_id, published_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS publication_budget_holds_participant_idx "
                "ON publication_budget_holds(participant_id, created_at)"
            )

            workflows = conn.execute(
                "SELECT DISTINCT workflow_id FROM audit_events WHERE sequence <= 0"
            ).fetchall()
            for (workflow_id,) in workflows:
                rows = conn.execute(
                    """
                    SELECT event_id
                      FROM audit_events
                     WHERE workflow_id=?
                     ORDER BY recorded_at, rowid
                    """,
                    (workflow_id,),
                ).fetchall()
                for sequence, (event_id,) in enumerate(rows, start=1):
                    conn.execute(
                        "UPDATE audit_events SET sequence=? WHERE event_id=?",
                        (sequence, event_id),
                    )

    @classmethod
    def _assert_transition(cls, current_state: str, next_state: str) -> None:
        allowed = cls.ALLOWED_TRANSITIONS.get(current_state, set())
        if next_state not in allowed:
            raise ValueError(
                f"invalid workflow transition: {current_state} -> {next_state}"
            )

    def create_workflow(self, request_id: str, operation: str) -> str:
        workflow_id = f"wf:{uuid.uuid4()}"
        now = utc_now()
        with self._connect() as conn:
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
                    workflow_id,
                    request_id,
                    operation,
                    "validated",
                    now,
                    now,
                    0,
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
            )
        return workflow_id

    def transition(self, workflow_id: str, state: str) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT state FROM workflows WHERE workflow_id=?",
                (workflow_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"unknown workflow: {workflow_id}")

            current_state = row[0]
            self._assert_transition(current_state, state)
            conn.execute(
                "UPDATE workflows SET state=?, updated_at=? WHERE workflow_id=?",
                (state, utc_now(), workflow_id),
            )

    def audit(
        self,
        workflow_id: str,
        event_type: str,
        actor: str,
        data: dict[str, Any],
    ) -> str:
        event_id = f"evt:{uuid.uuid4()}"
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM audit_events WHERE workflow_id=?",
                (workflow_id,),
            ).fetchone()
            sequence = int(row[0])
            conn.execute(
                """
                INSERT INTO audit_events
                    (event_id, workflow_id, sequence, event_type,
                     recorded_at, actor, data_json)
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    event_id,
                    workflow_id,
                    sequence,
                    event_type,
                    utc_now(),
                    actor,
                    canonical_json(data),
                ),
            )
        return event_id

    def record_request_diagnostic(
        self,
        outcome: str,
        request_id: Any = None,
        operation: Any = None,
        caller_subject: Any = None,
        client_id: Any = None,
        detail: Any = None,
    ) -> str:
        diagnostic_id = f"diag:{uuid.uuid4()}"

        def bounded(value: Any, limit: int = 500) -> str | None:
            if value is None:
                return None
            return str(value)[:limit]

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO request_diagnostics
                    (diagnostic_id, recorded_at, outcome, request_id,
                     operation, caller_subject, client_id, detail)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    diagnostic_id,
                    utc_now(),
                    bounded(outcome, 80),
                    bounded(request_id, 160),
                    bounded(operation, 160),
                    bounded(caller_subject, 160),
                    bounded(client_id, 160),
                    bounded(detail, 500),
                ),
            )
        return diagnostic_id

    @staticmethod
    def _publication_budget_usage_conn(
        conn: sqlite3.Connection,
        participant_id: str,
    ) -> PublicationBudgetUsage:
        completed = conn.execute(
            """
            SELECT COUNT(*), COALESCE(SUM(size_bytes), 0)
              FROM publications
             WHERE participant_id=?
            """,
            (participant_id,),
        ).fetchone()
        held = conn.execute(
            """
            SELECT COUNT(*), COALESCE(SUM(size_bytes), 0)
              FROM publication_budget_holds
             WHERE participant_id=?
            """,
            (participant_id,),
        ).fetchone()
        return PublicationBudgetUsage(
            completed_publications=int(completed[0]),
            completed_bytes=int(completed[1]),
            held_publications=int(held[0]),
            held_bytes=int(held[1]),
        )

    def publication_budget_usage(
        self,
        participant_id: str,
    ) -> PublicationBudgetUsage:
        with self._connect() as conn:
            return self._publication_budget_usage_conn(conn, participant_id)

    @classmethod
    def _reserve_publication_budget_conn(
        cls,
        conn: sqlite3.Connection,
        *,
        workflow_id: str,
        participant_id: str,
        size_bytes: int,
        policy: PublicationBudgetPolicy,
    ) -> PublicationBudgetUsage:
        if (
            not isinstance(size_bytes, int)
            or isinstance(size_bytes, bool)
            or size_bytes < 0
        ):
            raise ValueError("publication budget size_bytes is invalid")

        usage = cls._publication_budget_usage_conn(conn, participant_id)
        requested_count = usage.charged_publications + 1
        requested_bytes = usage.charged_bytes + size_bytes

        if requested_count > policy.max_publications:
            raise PublicationBudgetExceeded(
                usage=usage,
                policy=policy,
                requested_bytes=size_bytes,
                reason=(
                    "publication count budget exceeded: "
                    f"{requested_count}>{policy.max_publications}"
                ),
            )
        if requested_bytes > policy.max_publication_bytes:
            raise PublicationBudgetExceeded(
                usage=usage,
                policy=policy,
                requested_bytes=size_bytes,
                reason=(
                    "publication byte budget exceeded: "
                    f"{requested_bytes}>{policy.max_publication_bytes}"
                ),
            )

        now = utc_now()
        conn.execute(
            """
            INSERT INTO publication_budget_holds
                (workflow_id, participant_id, size_bytes, hold_state,
                 created_at, updated_at)
            VALUES (?,?,?,?,?,?)
            """,
            (
                workflow_id,
                participant_id,
                size_bytes,
                "reserved",
                now,
                now,
            ),
        )

        return PublicationBudgetUsage(
            completed_publications=usage.completed_publications,
            completed_bytes=usage.completed_bytes,
            held_publications=usage.held_publications + 1,
            held_bytes=usage.held_bytes + size_bytes,
        )

    def reserve_publication_budget(
        self,
        *,
        workflow_id: str,
        participant_id: str,
        size_bytes: int,
        policy: PublicationBudgetPolicy,
    ) -> PublicationBudgetUsage:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            return self._reserve_publication_budget_conn(
                conn,
                workflow_id=workflow_id,
                participant_id=participant_id,
                size_bytes=size_bytes,
                policy=policy,
            )

    @staticmethod
    def _mark_publication_budget_hold_conn(
        conn: sqlite3.Connection,
        workflow_id: str,
        hold_state: str,
    ) -> None:
        if hold_state not in {"reserved", "uncertain"}:
            raise ValueError("invalid publication budget hold state")
        updated = conn.execute(
            """
            UPDATE publication_budget_holds
               SET hold_state=?, updated_at=?
             WHERE workflow_id=?
            """,
            (hold_state, utc_now(), workflow_id),
        )
        if updated.rowcount != 1:
            raise ValueError(
                f"publication budget hold not found: {workflow_id}"
            )

    def mark_publication_budget_hold(
        self,
        workflow_id: str,
        hold_state: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._mark_publication_budget_hold_conn(
                conn,
                workflow_id,
                hold_state,
            )

    @staticmethod
    def _release_publication_budget_hold_conn(
        conn: sqlite3.Connection,
        workflow_id: str,
    ) -> None:
        deleted = conn.execute(
            "DELETE FROM publication_budget_holds WHERE workflow_id=?",
            (workflow_id,),
        )
        if deleted.rowcount != 1:
            raise ValueError(
                f"publication budget hold not found: {workflow_id}"
            )

    def release_publication_budget_hold(self, workflow_id: str) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._release_publication_budget_hold_conn(conn, workflow_id)

    def reconcile_publication_no_effect(
        self,
        workflow_id: str,
        *,
        actor: str,
        reason: str,
        validate_contract: Callable[[str, Any], None],
    ) -> str:
        if not actor or len(actor) > 160:
            raise ValueError("reconciliation actor is invalid")
        if not reason or len(reason) > 1000:
            raise ValueError("reconciliation reason is invalid")

        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN IMMEDIATE")

            workflow = conn.execute(
                """
                SELECT operation, state, side_effects, side_effects_certainty
                  FROM workflows
                 WHERE workflow_id=?
                """,
                (workflow_id,),
            ).fetchone()
            if workflow is None:
                raise ValueError(f"unknown workflow: {workflow_id}")
            if workflow["operation"] != "publication.publish":
                raise ValueError("workflow is not publication.publish")
            if workflow["state"] != "waiting":
                raise ValueError("publication workflow is not waiting")
            if not bool(workflow["side_effects"]):
                raise ValueError("publication workflow is not marked side-effecting")
            if workflow["side_effects_certainty"] != "unknown":
                raise ValueError("publication workflow certainty is not unknown")

            hold = conn.execute(
                """
                SELECT hold_state
                  FROM publication_budget_holds
                 WHERE workflow_id=?
                """,
                (workflow_id,),
            ).fetchone()
            if hold is None or hold["hold_state"] != "uncertain":
                raise ValueError("publication workflow has no uncertain budget hold")

            publication = conn.execute(
                "SELECT 1 FROM publications WHERE workflow_id=?",
                (workflow_id,),
            ).fetchone()
            if publication is not None:
                raise ValueError("publication workflow already has publication evidence")

            now = utc_now()
            conn.execute(
                """
                UPDATE workflows
                   SET side_effects=0,
                       side_effects_certainty='known',
                       updated_at=?
                 WHERE workflow_id=?
                """,
                (now, workflow_id),
            )
            self._mark_publication_budget_hold_conn(
                conn,
                workflow_id,
                "reserved",
            )

            sequence = int(
                conn.execute(
                    "SELECT COALESCE(MAX(sequence),0)+1 "
                    "FROM audit_events WHERE workflow_id=?",
                    (workflow_id,),
                ).fetchone()[0]
            )
            data = {
                "resolution": "no-external-side-effect",
                "reason": reason,
                "prior_side_effects": True,
                "prior_side_effects_certainty": "unknown",
                "budget_hold": "reserved",
            }
            event = {
                "event_id": f"evt:{uuid.uuid4()}",
                "workflow_id": workflow_id,
                "sequence": sequence,
                "event_type": "civic.operation.reconciled",
                "recorded_at": now,
                "actor": actor,
                "data": data,
            }
            validate_contract("audit-event-v1.schema.json", event)
            conn.execute(
                """
                INSERT INTO audit_events
                    (event_id, workflow_id, sequence, event_type,
                     recorded_at, actor, data_json)
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    event["event_id"],
                    event["workflow_id"],
                    event["sequence"],
                    event["event_type"],
                    event["recorded_at"],
                    event["actor"],
                    canonical_json(data),
                ),
            )
            return event["event_id"]

    @staticmethod
    def request_fingerprint(request: dict[str, Any]) -> str:
        semantic_request = {
            "contract_version": request["contract_version"],
            "operation": request["operation"],
            "caller": request["caller"],
            "client": request["client"],
            "input": request["input"],
        }
        return hashlib.sha256(
            canonical_json(semantic_request).encode("utf-8")
        ).hexdigest()

    def begin_external_operation(
        self,
        request: dict[str, Any],
        descriptor: dict[str, Any],
        authorization_policy: str,
        authorization_reason: str,
        validate_contract: Callable[[str, Any], None],
        publication_budget_policy: PublicationBudgetPolicy | None = None,
    ) -> tuple[dict[str, Any], bool]:
        request_id = request["request_id"]
        operation = request["operation"]
        fingerprint = self.request_fingerprint(request)
        idempotency_key = request.get("idempotency_key")
        caller_subject = request["caller"]["subject"]
        client_id = request["client"]["id"]

        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN IMMEDIATE")

            def handle_existing(
                existing: sqlite3.Row,
                key_name: str,
            ) -> tuple[dict[str, Any], bool]:
                if existing["request_fingerprint"] != fingerprint:
                    raise ConflictError(
                        f"{key_name} was already used for a different request"
                    )

                if existing["result_json"]:
                    return json.loads(existing["result_json"]), True

                state = existing["state"]
                if state == "waiting":
                    if (
                        publication_budget_policy is not None
                        and operation == "publication.publish"
                    ):
                        hold = conn.execute(
                            """
                            SELECT workflow_id
                              FROM publication_budget_holds
                             WHERE workflow_id=?
                            """,
                            (existing["workflow_id"],),
                        ).fetchone()
                        if hold is None:
                            self._reserve_publication_budget_conn(
                                conn,
                                workflow_id=existing["workflow_id"],
                                participant_id=caller_subject,
                                size_bytes=request["input"]["artifact"][
                                    "size_bytes"
                                ],
                                policy=publication_budget_policy,
                            )

                    self._assert_transition("waiting", "accepted")
                    conn.execute(
                        "UPDATE workflows SET state=?, updated_at=? "
                        "WHERE workflow_id=?",
                        ("accepted", utc_now(), existing["workflow_id"]),
                    )

                    sequence = int(
                        conn.execute(
                            "SELECT COALESCE(MAX(sequence),0)+1 "
                            "FROM audit_events WHERE workflow_id=?",
                            (existing["workflow_id"],),
                        ).fetchone()[0]
                    )
                    data = {
                        "operation": operation,
                        "original_request_id": existing["request_id"],
                        "retry_request_id": request_id,
                        "side_effects": bool(existing["side_effects"]),
                        "side_effects_certainty": existing[
                            "side_effects_certainty"
                        ],
                    }
                    event_record = {
                        "event_id": f"evt:{uuid.uuid4()}",
                        "workflow_id": existing["workflow_id"],
                        "sequence": sequence,
                        "event_type": "civic.operation.resumed",
                        "recorded_at": utc_now(),
                        "actor": "civic-orchestrator",
                        "data": data,
                    }
                    validate_contract(
                        "audit-event-v1.schema.json",
                        event_record,
                    )
                    conn.execute(
                        """
                        INSERT INTO audit_events
                            (event_id, workflow_id, sequence, event_type,
                             recorded_at, actor, data_json)
                        VALUES (?,?,?,?,?,?,?)
                        """,
                        (
                            event_record["event_id"],
                            event_record["workflow_id"],
                            event_record["sequence"],
                            event_record["event_type"],
                            event_record["recorded_at"],
                            event_record["actor"],
                            canonical_json(data),
                        ),
                    )
                    return {
                        "workflow_id": existing["workflow_id"],
                        "receipt_id": f"rcpt:{uuid.uuid4()}",
                        "resumed": True,
                    }, False

                if state == "accepted":
                    raise ConflictError(
                        f"{key_name} matches a request already in progress"
                    )

                raise ConflictError(
                    f"{key_name} matches a non-resumable workflow state: {state}"
                )

            select_fields = """
                SELECT workflow_id, request_id, state, side_effects,
                       side_effects_certainty, request_fingerprint, result_json
                  FROM workflows
            """

            if idempotency_key is not None:
                existing = conn.execute(
                    select_fields
                    + """
                     WHERE client_id=?
                       AND caller_subject=?
                       AND idempotency_key=?
                     ORDER BY rowid DESC
                     LIMIT 1
                    """,
                    (client_id, caller_subject, idempotency_key),
                ).fetchone()
                if existing is not None:
                    return handle_existing(existing, "idempotency key")

            existing = conn.execute(
                select_fields
                + """
                 WHERE client_id=?
                   AND caller_subject=?
                   AND request_id=?
                 ORDER BY rowid DESC
                 LIMIT 1
                """,
                (client_id, caller_subject, request_id),
            ).fetchone()
            if existing is not None:
                return handle_existing(existing, "request_id")

            workflow_id = f"wf:{uuid.uuid4()}"
            decision_id = f"authz:{uuid.uuid4()}"
            receipt_id = f"rcpt:{uuid.uuid4()}"
            created_at = utc_now()

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
                    workflow_id,
                    request_id,
                    operation,
                    "validated",
                    created_at,
                    created_at,
                    0,
                    idempotency_key,
                    fingerprint,
                    None,
                    caller_subject,
                    client_id,
                ),
            )

            if (
                publication_budget_policy is not None
                and operation == "publication.publish"
            ):
                try:
                    self._reserve_publication_budget_conn(
                        conn,
                        workflow_id=workflow_id,
                        participant_id=caller_subject,
                        size_bytes=request["input"]["artifact"]["size_bytes"],
                        policy=publication_budget_policy,
                    )
                except PublicationBudgetExceeded as exc:
                    reason = str(exc)[:1000]
                    budget = {
                        "charged_publications": (
                            exc.usage.charged_publications
                        ),
                        "charged_bytes": exc.usage.charged_bytes,
                        "requested_bytes": exc.requested_bytes,
                        "max_publications": exc.policy.max_publications,
                        "max_publication_bytes": (
                            exc.policy.max_publication_bytes
                        ),
                    }
                    decision_record = {
                        "decision_id": decision_id,
                        "request_id": request_id,
                        "operation": operation,
                        "decision": "deny",
                        "decided_at": utc_now(),
                        "policy": authorization_policy,
                        "reason": reason,
                    }
                    validate_contract(
                        "authorization-decision-v1.schema.json",
                        decision_record,
                    )
                    conn.execute(
                        """
                        INSERT INTO authorization_decisions
                            (decision_id, workflow_id, request_id, operation,
                             decision, decided_at, policy, reason)
                        VALUES (?,?,?,?,?,?,?,?)
                        """,
                        (
                            decision_record["decision_id"],
                            workflow_id,
                            decision_record["request_id"],
                            decision_record["operation"],
                            decision_record["decision"],
                            decision_record["decided_at"],
                            decision_record["policy"],
                            decision_record["reason"],
                        ),
                    )

                    self._assert_transition("validated", "rejected")
                    completed_at = utc_now()
                    conn.execute(
                        """
                        UPDATE workflows
                           SET state='rejected', updated_at=?,
                               side_effects=0,
                               side_effects_certainty='known'
                         WHERE workflow_id=?
                        """,
                        (completed_at, workflow_id),
                    )

                    evidence = {
                        "implementation": descriptor["implementation"],
                        "service_capability": descriptor[
                            "service_capability"
                        ],
                        "effect_scope": descriptor["effect_scope"],
                        "policy": authorization_policy,
                        "reason": reason,
                        "budget": budget,
                        "side_effects": False,
                        "side_effects_certainty": "known",
                    }
                    event_record = {
                        "event_id": f"evt:{uuid.uuid4()}",
                        "workflow_id": workflow_id,
                        "sequence": 1,
                        "event_type": "civic.authorization.denied",
                        "recorded_at": utc_now(),
                        "actor": "civic-orchestrator",
                        "data": evidence,
                    }
                    validate_contract(
                        "audit-event-v1.schema.json",
                        event_record,
                    )
                    conn.execute(
                        """
                        INSERT INTO audit_events
                            (event_id, workflow_id, sequence, event_type,
                             recorded_at, actor, data_json)
                        VALUES (?,?,?,?,?,?,?)
                        """,
                        (
                            event_record["event_id"],
                            workflow_id,
                            event_record["sequence"],
                            event_record["event_type"],
                            event_record["recorded_at"],
                            event_record["actor"],
                            canonical_json(evidence),
                        ),
                    )

                    receipt_record = {
                        "receipt_id": receipt_id,
                        "workflow_id": workflow_id,
                        "operation": operation,
                        "issued_at": utc_now(),
                        "outcome": "rejected",
                        "side_effects": False,
                        "evidence": evidence,
                    }
                    validate_contract(
                        "receipt-v1.schema.json",
                        receipt_record,
                    )
                    conn.execute(
                        """
                        INSERT INTO receipts
                            (receipt_id, workflow_id, operation, issued_at,
                             outcome, side_effects, evidence_json)
                        VALUES (?,?,?,?,?,?,?)
                        """,
                        (
                            receipt_id,
                            workflow_id,
                            operation,
                            receipt_record["issued_at"],
                            "rejected",
                            0,
                            canonical_json(evidence),
                        ),
                    )

                    result = {
                        "contract_version": 1,
                        "request_id": request_id,
                        "workflow_id": workflow_id,
                        "operation": operation,
                        "status": "rejected",
                        "completed_at": completed_at,
                        "side_effects": False,
                        "result": evidence,
                        "receipt_id": receipt_id,
                    }
                    validate_contract(
                        "result-envelope-v1.schema.json",
                        result,
                    )
                    conn.execute(
                        "UPDATE workflows SET result_json=? "
                        "WHERE workflow_id=?",
                        (canonical_json(result), workflow_id),
                    )
                    return result, False

            decision_record = {
                "decision_id": decision_id,
                "request_id": request_id,
                "operation": operation,
                "decision": "allow",
                "decided_at": utc_now(),
                "policy": authorization_policy,
                "reason": authorization_reason,
            }
            validate_contract(
                "authorization-decision-v1.schema.json",
                decision_record,
            )
            conn.execute(
                """
                INSERT INTO authorization_decisions
                    (decision_id, workflow_id, request_id, operation,
                     decision, decided_at, policy, reason)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    decision_record["decision_id"],
                    workflow_id,
                    decision_record["request_id"],
                    decision_record["operation"],
                    decision_record["decision"],
                    decision_record["decided_at"],
                    decision_record["policy"],
                    decision_record["reason"],
                ),
            )

            self._assert_transition("validated", "authorized")
            conn.execute(
                "UPDATE workflows SET state=?, updated_at=? WHERE workflow_id=?",
                ("authorized", utc_now(), workflow_id),
            )
            self._assert_transition("authorized", "accepted")
            conn.execute(
                "UPDATE workflows SET state=?, updated_at=? WHERE workflow_id=?",
                ("accepted", utc_now(), workflow_id),
            )

            events = [
                (
                    1,
                    "civic.authorization.allowed",
                    "civic-orchestrator",
                    {
                        "decision_id": decision_id,
                        "policy": authorization_policy,
                        "side_effects": False,
                    },
                ),
                (
                    2,
                    "civic.operation.accepted",
                    caller_subject,
                    {
                        "operation": operation,
                        "client_id": request["client"]["id"],
                        "client_kind": request["client"]["kind"],
                        "authenticated_by": request["caller"]["authenticated_by"],
                        "side_effects": False,
                    },
                ),
                (
                    3,
                    "civic.service.selected",
                    "civic-orchestrator",
                    {
                        "service_capability": descriptor["service_capability"],
                        "implementation": descriptor["implementation"],
                        "effect_scope": descriptor["effect_scope"],
                        "side_effects": False,
                    },
                ),
            ]

            for sequence, event_type, actor, data in events:
                event_record = {
                    "event_id": f"evt:{uuid.uuid4()}",
                    "workflow_id": workflow_id,
                    "sequence": sequence,
                    "event_type": event_type,
                    "recorded_at": utc_now(),
                    "actor": actor,
                    "data": data,
                }
                validate_contract(
                    "audit-event-v1.schema.json",
                    event_record,
                )
                conn.execute(
                    """
                    INSERT INTO audit_events
                        (event_id, workflow_id, sequence, event_type,
                         recorded_at, actor, data_json)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        event_record["event_id"],
                        workflow_id,
                        sequence,
                        event_type,
                        event_record["recorded_at"],
                        actor,
                        canonical_json(data),
                    ),
                )

            return {
                "workflow_id": workflow_id,
                "receipt_id": receipt_id,
                "resumed": False,
            }, False

    def pause_external_operation(
        self,
        workflow_id: str,
        failure_class: str,
        message: str,
        retryable: bool,
        side_effects: bool,
        side_effects_certainty: str,
        validate_contract: Callable[[str, Any], None],
    ) -> None:
        if side_effects_certainty not in {"known", "unknown"}:
            raise ValueError("invalid side-effect certainty")

        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT state, side_effects, side_effects_certainty
                  FROM workflows
                 WHERE workflow_id=?
                """,
                (workflow_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"unknown workflow: {workflow_id}")

            self._assert_transition(row["state"], "waiting")
            aggregate_side_effects = bool(row["side_effects"]) or bool(
                side_effects
            )
            aggregate_certainty = (
                "unknown"
                if row["side_effects_certainty"] == "unknown"
                or side_effects_certainty == "unknown"
                else "known"
            )
            conn.execute(
                """
                UPDATE workflows
                   SET state=?, updated_at=?, side_effects=?,
                       side_effects_certainty=?
                 WHERE workflow_id=?
                """,
                (
                    "waiting",
                    utc_now(),
                    1 if aggregate_side_effects else 0,
                    aggregate_certainty,
                    workflow_id,
                ),
            )
            if aggregate_side_effects or aggregate_certainty == "unknown":
                conn.execute(
                    """
                    UPDATE publication_budget_holds
                       SET hold_state='uncertain', updated_at=?
                     WHERE workflow_id=?
                    """,
                    (utc_now(), workflow_id),
                )

            sequence = int(
                conn.execute(
                    "SELECT COALESCE(MAX(sequence),0)+1 "
                    "FROM audit_events WHERE workflow_id=?",
                    (workflow_id,),
                ).fetchone()[0]
            )
            data = {
                "failure_class": failure_class,
                "message": message[:1000],
                "retryable": bool(retryable),
                "side_effects": bool(side_effects),
                "side_effects_certainty": side_effects_certainty,
                "aggregate_side_effects": aggregate_side_effects,
                "aggregate_side_effects_certainty": aggregate_certainty,
            }
            event_record = {
                "event_id": f"evt:{uuid.uuid4()}",
                "workflow_id": workflow_id,
                "sequence": sequence,
                "event_type": "civic.operation.waiting",
                "recorded_at": utc_now(),
                "actor": "civic-orchestrator",
                "data": data,
            }
            validate_contract(
                "audit-event-v1.schema.json",
                event_record,
            )
            conn.execute(
                """
                INSERT INTO audit_events
                    (event_id, workflow_id, sequence, event_type,
                     recorded_at, actor, data_json)
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    event_record["event_id"],
                    workflow_id,
                    sequence,
                    event_record["event_type"],
                    event_record["recorded_at"],
                    event_record["actor"],
                    canonical_json(data),
                ),
            )

    def reconcile_external_workflows(
        self,
        operations: set[str],
        validate_contract: Callable[[str, Any], None],
    ) -> list[str]:
        if not operations:
            return []

        reconciled: list[str] = []
        placeholders = ",".join("?" for _ in operations)
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                f"""
                SELECT workflow_id, operation
                  FROM workflows
                 WHERE state='accepted'
                   AND operation IN ({placeholders})
                 ORDER BY rowid
                """,
                tuple(sorted(operations)),
            ).fetchall()

            for row in rows:
                workflow_id = row["workflow_id"]
                self._assert_transition("accepted", "waiting")
                conn.execute(
                    """
                    UPDATE workflows
                       SET state='waiting', updated_at=?,
                           side_effects=1,
                           side_effects_certainty='unknown'
                     WHERE workflow_id=?
                    """,
                    (utc_now(), workflow_id),
                )
                conn.execute(
                    """
                    UPDATE publication_budget_holds
                       SET hold_state='uncertain', updated_at=?
                     WHERE workflow_id=?
                    """,
                    (utc_now(), workflow_id),
                )

                sequence = int(
                    conn.execute(
                        "SELECT COALESCE(MAX(sequence),0)+1 "
                        "FROM audit_events WHERE workflow_id=?",
                        (workflow_id,),
                    ).fetchone()[0]
                )
                data = {
                    "operation": row["operation"],
                    "reason": (
                        "process restart found an accepted external workflow "
                        "without a terminal result"
                    ),
                    "side_effects": True,
                    "side_effects_certainty": "unknown",
                }
                event_record = {
                    "event_id": f"evt:{uuid.uuid4()}",
                    "workflow_id": workflow_id,
                    "sequence": sequence,
                    "event_type": "civic.operation.recovery-pending",
                    "recorded_at": utc_now(),
                    "actor": "civic-orchestrator",
                    "data": data,
                }
                validate_contract(
                    "audit-event-v1.schema.json",
                    event_record,
                )
                conn.execute(
                    """
                    INSERT INTO audit_events
                        (event_id, workflow_id, sequence, event_type,
                         recorded_at, actor, data_json)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        event_record["event_id"],
                        workflow_id,
                        sequence,
                        event_record["event_type"],
                        event_record["recorded_at"],
                        event_record["actor"],
                        canonical_json(data),
                    ),
                )
                reconciled.append(workflow_id)

        return reconciled

    def finish_external_operation(
        self,
        request: dict[str, Any],
        descriptor: dict[str, Any],
        workflow_id: str,
        receipt_id: str,
        outcome: str,
        side_effects: bool,
        side_effects_certainty: str,
        detail: dict[str, Any],
        validate_contract: Callable[[str, Any], None],
        budget_hold_required: bool = False,
    ) -> dict[str, Any]:
        if outcome not in {"completed", "failed"}:
            raise ValueError(f"invalid external operation outcome: {outcome}")
        if side_effects_certainty not in {"known", "unknown"}:
            raise ValueError("invalid side-effect certainty")

        completed_at = utc_now()
        detail = dict(detail)
        publication_id = None
        if outcome == "completed" and request["operation"] == "publication.publish":
            publication_id = f"pub:{uuid.uuid4()}"
            detail["publication_id"] = publication_id

        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT state, side_effects, side_effects_certainty
                  FROM workflows
                 WHERE workflow_id=?
                """,
                (workflow_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"unknown workflow: {workflow_id}")

            self._assert_transition(row["state"], outcome)
            prior_side_effects = bool(row["side_effects"])
            prior_certainty = row["side_effects_certainty"]
            final_side_effects = prior_side_effects or bool(side_effects)

            if side_effects and side_effects_certainty == "known":
                final_certainty = "known"
            elif (
                prior_certainty == "unknown"
                or side_effects_certainty == "unknown"
            ):
                final_certainty = "unknown"
            else:
                final_certainty = "known"

            evidence = {
                "implementation": descriptor["implementation"],
                "service_capability": descriptor["service_capability"],
                "effect_scope": descriptor["effect_scope"],
                "side_effects": final_side_effects,
                "side_effects_certainty": final_certainty,
                **detail,
            }

            conn.execute(
                """
                UPDATE workflows
                   SET state=?, updated_at=?, side_effects=?,
                       side_effects_certainty=?
                 WHERE workflow_id=?
                """,
                (
                    outcome,
                    completed_at,
                    1 if final_side_effects else 0,
                    final_certainty,
                    workflow_id,
                ),
            )

            sequence = int(
                conn.execute(
                    "SELECT COALESCE(MAX(sequence),0)+1 "
                    "FROM audit_events WHERE workflow_id=?",
                    (workflow_id,),
                ).fetchone()[0]
            )
            event_record = {
                "event_id": f"evt:{uuid.uuid4()}",
                "workflow_id": workflow_id,
                "sequence": sequence,
                "event_type": f"civic.operation.{outcome}",
                "recorded_at": utc_now(),
                "actor": "civic-orchestrator",
                "data": evidence,
            }
            validate_contract(
                "audit-event-v1.schema.json",
                event_record,
            )
            conn.execute(
                """
                INSERT INTO audit_events
                    (event_id, workflow_id, sequence, event_type,
                     recorded_at, actor, data_json)
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    event_record["event_id"],
                    workflow_id,
                    sequence,
                    event_record["event_type"],
                    event_record["recorded_at"],
                    event_record["actor"],
                    canonical_json(evidence),
                ),
            )

            receipt_record = {
                "receipt_id": receipt_id,
                "workflow_id": workflow_id,
                "operation": request["operation"],
                "issued_at": utc_now(),
                "outcome": outcome,
                "side_effects": final_side_effects,
                "evidence": evidence,
            }
            validate_contract(
                "receipt-v1.schema.json",
                receipt_record,
            )
            conn.execute(
                """
                INSERT INTO receipts
                    (receipt_id, workflow_id, operation, issued_at,
                     outcome, side_effects, evidence_json)
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    receipt_id,
                    workflow_id,
                    request["operation"],
                    receipt_record["issued_at"],
                    outcome,
                    1 if final_side_effects else 0,
                    canonical_json(evidence),
                ),
            )

            if publication_id is not None:
                artifact = request["input"]["artifact"]
                conn.execute(
                    """
                    INSERT INTO publications
                        (publication_id, workflow_id, receipt_id,
                         participant_id, sha256, size_bytes, media_type,
                         cid, cid_profile, published_at, client_id,
                         authenticated_by, verified)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        publication_id,
                        workflow_id,
                        receipt_id,
                        request["caller"]["subject"],
                        artifact["sha256"],
                        artifact["size_bytes"],
                        artifact["media_type"],
                        detail["cid"],
                        detail["cid_profile"],
                        completed_at,
                        request["client"]["id"],
                        request["caller"]["authenticated_by"],
                        1 if detail.get("verified") else 0,
                    ),
                )

            if budget_hold_required:
                if request["operation"] != "publication.publish":
                    raise ValueError(
                        "publication budget hold used for non-publication "
                        "operation"
                    )
                if outcome == "completed" or not final_side_effects:
                    self._release_publication_budget_hold_conn(
                        conn,
                        workflow_id,
                    )
                else:
                    self._mark_publication_budget_hold_conn(
                        conn,
                        workflow_id,
                        "uncertain",
                    )

            result = {
                "contract_version": 1,
                "request_id": request["request_id"],
                "workflow_id": workflow_id,
                "operation": request["operation"],
                "status": outcome,
                "completed_at": completed_at,
                "side_effects": final_side_effects,
                "result": evidence,
                "receipt_id": receipt_id,
            }
            validate_contract(
                "result-envelope-v1.schema.json",
                result,
            )
            conn.execute(
                "UPDATE workflows SET result_json=? WHERE workflow_id=?",
                (canonical_json(result), workflow_id),
            )

        return result

    def record_stub_operation(
        self,
        request: dict[str, Any],
        descriptor: dict[str, Any],
        authorization_policy: str,
        validate_contract: Callable[[str, Any], None],
    ) -> tuple[dict[str, Any], bool]:
        request_id = request["request_id"]
        operation = request["operation"]
        fingerprint = self.request_fingerprint(request)
        idempotency_key = request.get("idempotency_key")
        caller_subject = request["caller"]["subject"]
        client_id = request["client"]["id"]

        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN IMMEDIATE")

            if idempotency_key is not None:
                existing = conn.execute(
                    """
                    SELECT request_fingerprint, result_json
                      FROM workflows
                     WHERE client_id=?
                       AND caller_subject=?
                       AND idempotency_key=?
                     ORDER BY rowid DESC
                     LIMIT 1
                    """,
                    (client_id, caller_subject, idempotency_key),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["request_fingerprint"] == fingerprint
                        and existing["result_json"]
                    ):
                        return json.loads(existing["result_json"]), True
                    raise ConflictError(
                        "idempotency key was already used for a different request"
                    )

            existing = conn.execute(
                """
                SELECT request_fingerprint, result_json
                  FROM workflows
                 WHERE client_id=?
                   AND caller_subject=?
                   AND request_id=?
                 ORDER BY rowid DESC
                 LIMIT 1
                """,
                (client_id, caller_subject, request_id),
            ).fetchone()
            if existing is not None:
                if (
                    existing["request_fingerprint"] == fingerprint
                    and existing["result_json"]
                ):
                    return json.loads(existing["result_json"]), True
                raise ConflictError(
                    "request_id was already used for a different request"
                )

            workflow_id = f"wf:{uuid.uuid4()}"
            decision_id = f"authz:{uuid.uuid4()}"
            receipt_id = f"rcpt:{uuid.uuid4()}"

            created_at = utc_now()
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
                    workflow_id,
                    request_id,
                    operation,
                    "validated",
                    created_at,
                    created_at,
                    0,
                    idempotency_key,
                    fingerprint,
                    None,
                    caller_subject,
                    client_id,
                ),
            )

            decided_at = utc_now()
            decision_record = {
                "decision_id": decision_id,
                "request_id": request_id,
                "operation": operation,
                "decision": "allow",
                "decided_at": decided_at,
                "policy": authorization_policy,
                "reason": (
                    "Phase 1H permits registered operations only as "
                    "non-side-effect stubs."
                ),
            }
            validate_contract(
                "authorization-decision-v1.schema.json",
                decision_record,
            )
            conn.execute(
                """
                INSERT INTO authorization_decisions
                    (decision_id, workflow_id, request_id, operation,
                     decision, decided_at, policy, reason)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    decision_record["decision_id"],
                    workflow_id,
                    decision_record["request_id"],
                    decision_record["operation"],
                    decision_record["decision"],
                    decision_record["decided_at"],
                    decision_record["policy"],
                    decision_record["reason"],
                ),
            )

            self._assert_transition("validated", "authorized")
            conn.execute(
                "UPDATE workflows SET state=?, updated_at=? WHERE workflow_id=?",
                ("authorized", utc_now(), workflow_id),
            )

            events = [
                (
                    1,
                    "civic.authorization.allowed",
                    "civic-orchestrator",
                    {
                        "decision_id": decision_id,
                        "policy": authorization_policy,
                        "side_effects": False,
                    },
                ),
            ]

            self._assert_transition("authorized", "accepted")
            conn.execute(
                "UPDATE workflows SET state=?, updated_at=? WHERE workflow_id=?",
                ("accepted", utc_now(), workflow_id),
            )
            events.append(
                (
                    2,
                    "civic.operation.accepted",
                    request["caller"]["subject"],
                    {
                        "operation": operation,
                        "client_id": request["client"]["id"],
                        "client_kind": request["client"]["kind"],
                        "authenticated_by": request["caller"]["authenticated_by"],
                        "side_effects": False,
                    },
                )
            )
            events.append(
                (
                    3,
                    "civic.service.selected",
                    "civic-orchestrator",
                    {
                        "service_capability": descriptor["service_capability"],
                        "implementation": descriptor["implementation"],
                        "effect_scope": descriptor["effect_scope"],
                        "side_effects": False,
                    },
                )
            )

            self._assert_transition("accepted", "not-implemented")
            completed_at = utc_now()
            conn.execute(
                "UPDATE workflows SET state=?, updated_at=? WHERE workflow_id=?",
                ("not-implemented", completed_at, workflow_id),
            )
            events.append(
                (
                    4,
                    "civic.operation.not-implemented",
                    "civic-orchestrator",
                    {
                        "service_capability": descriptor["service_capability"],
                        "side_effects": False,
                    },
                )
            )

            for sequence, event_type, actor, data in events:
                event_record = {
                    "event_id": f"evt:{uuid.uuid4()}",
                    "workflow_id": workflow_id,
                    "sequence": sequence,
                    "event_type": event_type,
                    "recorded_at": utc_now(),
                    "actor": actor,
                    "data": data,
                }
                validate_contract(
                    "audit-event-v1.schema.json",
                    event_record,
                )
                conn.execute(
                    """
                    INSERT INTO audit_events
                        (event_id, workflow_id, sequence, event_type,
                         recorded_at, actor, data_json)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        event_record["event_id"],
                        workflow_id,
                        sequence,
                        event_type,
                        event_record["recorded_at"],
                        actor,
                        canonical_json(data),
                    ),
                )

            receipt_evidence = {
                "implementation": "stub",
                "service_capability": descriptor["service_capability"],
                "effect_scope": descriptor["effect_scope"],
                "side_effects": False,
            }
            receipt_record = {
                "receipt_id": receipt_id,
                "workflow_id": workflow_id,
                "operation": operation,
                "issued_at": utc_now(),
                "outcome": "not-implemented",
                "side_effects": False,
                "evidence": receipt_evidence,
            }
            validate_contract(
                "receipt-v1.schema.json",
                receipt_record,
            )
            conn.execute(
                """
                INSERT INTO receipts
                    (receipt_id, workflow_id, operation, issued_at,
                     outcome, side_effects, evidence_json)
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    receipt_id,
                    workflow_id,
                    operation,
                    receipt_record["issued_at"],
                    "not-implemented",
                    0,
                    canonical_json(receipt_evidence),
                ),
            )

            result = {
                "contract_version": 1,
                "request_id": request_id,
                "workflow_id": workflow_id,
                "operation": operation,
                "status": "not-implemented",
                "completed_at": completed_at,
                "side_effects": False,
                "result": {
                    "implementation": "stub",
                    "service_capability": descriptor["service_capability"],
                    "effect_scope": descriptor["effect_scope"],
                    "message": (
                        "Phase 1H stub accepted the operation but performed "
                        "no backend action."
                    ),
                },
                "receipt_id": receipt_id,
            }
            validate_contract(
                "result-envelope-v1.schema.json",
                result,
            )
            conn.execute(
                "UPDATE workflows SET result_json=? WHERE workflow_id=?",
                (canonical_json(result), workflow_id),
            )

            return result, False

    def get_workflow_evidence(
        self,
        workflow_id: str,
    ) -> dict[str, Any] | None:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row

            workflow = conn.execute(
                """
                SELECT workflow_id, request_id, operation, state,
                       created_at, updated_at, side_effects,
                       side_effects_certainty
                  FROM workflows
                 WHERE workflow_id=?
                """,
                (workflow_id,),
            ).fetchone()
            if workflow is None:
                return None

            decisions = conn.execute(
                """
                SELECT decision_id, request_id, operation, decision,
                       decided_at, policy, reason
                  FROM authorization_decisions
                 WHERE workflow_id=?
                 ORDER BY decided_at, decision_id
                """,
                (workflow_id,),
            ).fetchall()

            events = conn.execute(
                """
                SELECT event_id, workflow_id, sequence, event_type,
                       recorded_at, actor, data_json
                  FROM audit_events
                 WHERE workflow_id=?
                 ORDER BY sequence
                """,
                (workflow_id,),
            ).fetchall()

            receipts = conn.execute(
                """
                SELECT receipt_id, workflow_id, operation, issued_at,
                       outcome, side_effects, evidence_json
                  FROM receipts
                 WHERE workflow_id=?
                 ORDER BY issued_at, receipt_id
                """,
                (workflow_id,),
            ).fetchall()

        workflow_obj = {
            "workflow_id": workflow["workflow_id"],
            "request_id": workflow["request_id"],
            "operation": workflow["operation"],
            "state": workflow["state"],
            "created_at": workflow["created_at"],
            "updated_at": workflow["updated_at"],
            "side_effects": bool(workflow["side_effects"]),
            "side_effects_certainty": workflow["side_effects_certainty"],
        }

        decision_objs = []
        for row in decisions:
            item = {
                "decision_id": row["decision_id"],
                "request_id": row["request_id"],
                "operation": row["operation"],
                "decision": row["decision"],
                "decided_at": row["decided_at"],
                "policy": row["policy"],
            }
            if row["reason"] is not None:
                item["reason"] = row["reason"]
            decision_objs.append(item)

        event_objs = [
            {
                "event_id": row["event_id"],
                "workflow_id": row["workflow_id"],
                "sequence": row["sequence"],
                "event_type": row["event_type"],
                "recorded_at": row["recorded_at"],
                "actor": row["actor"],
                "data": json.loads(row["data_json"]),
            }
            for row in events
        ]

        receipt_objs = [
            {
                "receipt_id": row["receipt_id"],
                "workflow_id": row["workflow_id"],
                "operation": row["operation"],
                "issued_at": row["issued_at"],
                "outcome": row["outcome"],
                "side_effects": bool(row["side_effects"]),
                "evidence": json.loads(row["evidence_json"]),
            }
            for row in receipts
        ]

        return {
            "contract_version": 1,
            "workflow": workflow_obj,
            "authorization_decisions": decision_objs,
            "audit_events": event_objs,
            "receipts": receipt_objs,
            "side_effects": bool(workflow["side_effects"]),
            "side_effects_certainty": workflow["side_effects_certainty"],
        }


class CivicOrchestrator:
    def __init__(
        self,
        paths: RuntimePaths,
        publication_client: Any | None = None,
        publication_budget_policy: PublicationBudgetPolicy | None = None,
    ) -> None:
        self.contracts = ContractStore(paths.repo_root)
        self.registry = OperationRegistry(
            paths.repo_root / "contracts" / "operation-registry-v1.yaml",
            self.contracts,
        )
        self.workflow = StubWorkflowDefinition(
            paths.repo_root / "workflows" / "stub-operation-v1.yaml",
            self.contracts,
        )
        self.publication_workflow = PublicationWorkflowDefinition(
            paths.repo_root / "workflows" / "publication-publish-v1.yaml",
            self.contracts,
        )

        publication_descriptor = self.registry.lookup(
            self.publication_workflow.operation
        )
        if publication_descriptor is None:
            raise ValueError("publication workflow operation is not registered")
        if (
            publication_descriptor["service_capability"]
            != self.publication_workflow.service_capability
        ):
            raise ValueError(
                "publication workflow service capability does not match registry"
            )

        for operation in self.registry.operations:
            if not self.workflow.accepts(operation):
                raise ValueError(
                    f"operation registry/workflow namespace drift: {operation}"
                )

        self.state = StateStore(paths.state_db)
        self.reconciled_external_workflows = (
            self.state.reconcile_external_workflows(
                {"publication.publish"},
                self.contracts.validate,
            )
        )
        self.publication_client = publication_client
        self.publication_budget_policy = publication_budget_policy

    def capabilities(self) -> dict[str, Any]:
        return {
            "contract_version": self.registry.contract_version,
            "capabilities": [
                {
                    "operation": item["operation"],
                    "implementation": item["implementation"],
                    "effect_scope": item["effect_scope"],
                }
                for item in self.registry.operations.values()
            ],
        }

    def health(self) -> dict[str, Any]:
        available = [
            item
            for item in self.registry.operations.values()
            if item["implementation"] == "available"
        ]
        return {
            "status": "ok",
            "available_operations": len(available),
            "side_effects": any(
                item["effect_scope"] != "none"
                for item in available
            ),
        }

    def submit_authenticated(
        self,
        request: dict[str, Any],
        binding: AuthenticatedAdapterBinding,
    ) -> tuple[int, dict[str, Any]]:
        """Submit through a transport-authenticated adapter identity binding."""
        try:
            canonical_json(request)
            self.contracts.validate("request-envelope-v1.schema.json", request)
        except (TypeError, ValueError, ValidationError):
            # Preserve the ordinary contract failure semantics for malformed
            # requests; identity binding is meaningful only after the envelope
            # itself is valid.
            return self.submit(request)

        try:
            binding.validate_request(request)
        except AdapterIdentityError as exc:
            request_id = request.get("request_id")
            operation = request.get("operation")
            caller = request.get("caller", {})
            client = request.get("client", {})
            self.state.record_request_diagnostic(
                "adapter-identity-mismatch",
                request_id,
                operation,
                caller.get("subject"),
                client.get("id"),
                exc,
            )
            return 403, self.failure(
                request_id,
                operation,
                "unauthorized",
                str(exc),
                False,
            )

        return self.submit(request)

    def submit(self, request: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        raw_request_id = request.get("request_id") if isinstance(request, dict) else None
        raw_operation = request.get("operation") if isinstance(request, dict) else None

        caller_subject = None
        client_id = None
        if isinstance(request, dict):
            caller = request.get("caller")
            client = request.get("client")
            if isinstance(caller, dict):
                caller_subject = caller.get("subject")
            if isinstance(client, dict):
                client_id = client.get("id")

        try:
            canonical_json(request)
            self.contracts.validate("request-envelope-v1.schema.json", request)
        except (TypeError, ValueError, ValidationError) as exc:
            self.state.record_request_diagnostic(
                "invalid-contract",
                raw_request_id,
                raw_operation,
                caller_subject,
                client_id,
                exc,
            )
            return 400, self.failure(
                request_id=raw_request_id,
                operation=raw_operation,
                failure_class="invalid-contract",
                message=str(exc),
                retryable=False,
            )

        operation = request["operation"]
        request_id = request["request_id"]

        if operation in self.registry.prohibited:
            self.state.record_request_diagnostic(
                "unauthorized",
                request_id,
                operation,
                caller_subject,
                client_id,
                "operation is explicitly prohibited",
            )
            return 403, self.failure(
                request_id,
                operation,
                "unauthorized",
                "operation is explicitly prohibited by the Civic contract",
                False,
            )

        descriptor = self.registry.lookup(operation)
        if descriptor is None or not self.workflow.accepts(operation):
            self.state.record_request_diagnostic(
                "unknown-operation",
                request_id,
                operation,
                caller_subject,
                client_id,
                "operation is not present in the bounded workflow registry",
            )
            return 400, self.failure(
                request_id,
                operation,
                "unknown-operation",
                "operation is not present in the bounded workflow registry",
                False,
            )

        if (
            operation == "publication.publish"
            and descriptor["implementation"] == "available"
        ):
            return self._submit_publication(
                request,
                descriptor,
                caller_subject,
                client_id,
            )

        try:
            result, replayed = self.state.record_stub_operation(
                request,
                descriptor,
                self.workflow.authorization_policy,
                self.contracts.validate,
            )
        except ConflictError as exc:
            self.state.record_request_diagnostic(
                "conflict",
                request_id,
                operation,
                caller_subject,
                client_id,
                exc,
            )
            return 409, self.failure(
                request_id,
                operation,
                "conflict",
                str(exc),
                False,
            )

        self.contracts.validate("result-envelope-v1.schema.json", result)
        if replayed:
            original_request_id = result["request_id"]
            result = dict(result)
            result["request_id"] = request_id
            result["result"] = dict(result["result"])
            result["result"]["replayed"] = True
            result["result"]["original_request_id"] = original_request_id
            self.state.record_request_diagnostic(
                "replay",
                request_id,
                operation,
                caller_subject,
                client_id,
                f"original_request_id={original_request_id}",
            )
            self.contracts.validate("result-envelope-v1.schema.json", result)

        return 200, result

    def _submit_publication(
        self,
        request: dict[str, Any],
        descriptor: dict[str, Any],
        caller_subject: str,
        client_id: str,
    ) -> tuple[int, dict[str, Any]]:
        request_id = request["request_id"]
        operation = request["operation"]

        try:
            self.contracts.validate(
                "publication-publish-input-v1.schema.json",
                request["input"],
            )
            validate_artifact_integrity(request["input"]["artifact"])
        except (ValidationError, ValueError) as exc:
            self.state.record_request_diagnostic(
                "invalid-contract",
                request_id,
                operation,
                caller_subject,
                client_id,
                exc,
            )
            return 400, self.failure(
                request_id,
                operation,
                "invalid-contract",
                str(exc),
                False,
            )

        if self.publication_budget_policy is None:
            message = "publication budget policy is not configured"
            self.state.record_request_diagnostic(
                "publication-budget-unconfigured",
                request_id,
                operation,
                caller_subject,
                client_id,
                message,
            )
            return 503, self.failure(
                request_id,
                operation,
                "backend-unavailable",
                message,
                False,
            )

        if self.publication_client is None:
            message = "publication service client is not configured"
            self.state.record_request_diagnostic(
                "backend-unavailable",
                request_id,
                operation,
                caller_subject,
                client_id,
                message,
            )
            return 500, self.failure(
                request_id,
                operation,
                "backend-unavailable",
                message,
                True,
            )

        try:
            start, replayed = self.state.begin_external_operation(
                request,
                descriptor,
                self.publication_workflow.authorization_policy,
                self.publication_workflow.authorization_reason,
                self.contracts.validate,
                publication_budget_policy=self.publication_budget_policy,
            )
        except PublicationBudgetExceeded as exc:
            self.state.record_request_diagnostic(
                "publication-budget-denied-recovery",
                request_id,
                operation,
                caller_subject,
                client_id,
                exc,
            )
            return 403, self.failure(
                request_id,
                operation,
                "unauthorized",
                str(exc),
                False,
                detail={
                    "charged_publications": (
                        exc.usage.charged_publications
                    ),
                    "charged_bytes": exc.usage.charged_bytes,
                    "requested_bytes": exc.requested_bytes,
                    "max_publications": exc.policy.max_publications,
                    "max_publication_bytes": (
                        exc.policy.max_publication_bytes
                    ),
                },
            )
        except ConflictError as exc:
            self.state.record_request_diagnostic(
                "conflict",
                request_id,
                operation,
                caller_subject,
                client_id,
                exc,
            )
            return 409, self.failure(
                request_id,
                operation,
                "conflict",
                str(exc),
                False,
            )

        if not replayed and start.get("status") == "rejected":
            self.state.record_request_diagnostic(
                "publication-budget-denied",
                request_id,
                operation,
                caller_subject,
                client_id,
                start["result"].get("reason"),
            )
            return 200, start

        if replayed:
            original_request_id = start["request_id"]
            result = dict(start)
            result["request_id"] = request_id
            result["result"] = dict(result["result"])
            result["result"]["replayed"] = True
            result["result"]["original_request_id"] = original_request_id
            self.state.record_request_diagnostic(
                "replay",
                request_id,
                operation,
                caller_subject,
                client_id,
                f"original_request_id={original_request_id}",
            )
            self.contracts.validate(
                "result-envelope-v1.schema.json",
                result,
            )
            return 200, result

        workflow_id = start["workflow_id"]
        receipt_id = start["receipt_id"]

        try:
            service_result = self.publication_client.publish(
                workflow_id,
                request["input"]["artifact"],
            )
        except PublicationServiceFailure as exc:
            if exc.retryable:
                possible_effect = exc.failure_class in {
                    "publication-failed",
                    "verification-failed",
                }
                certainty = "unknown" if possible_effect else "known"
                self.state.pause_external_operation(
                    workflow_id=workflow_id,
                    failure_class=exc.failure_class,
                    message=exc.message,
                    retryable=True,
                    side_effects=possible_effect,
                    side_effects_certainty=certainty,
                    validate_contract=self.contracts.validate,
                )
                envelope_class = (
                    "backend-unavailable"
                    if exc.failure_class == "service-unavailable"
                    else "internal"
                )
                return 503, self.failure(
                    request_id,
                    operation,
                    envelope_class,
                    exc.message,
                    True,
                    side_effects=possible_effect,
                    detail={
                        "workflow_id": workflow_id,
                        "workflow_state": "waiting",
                        "service_failure_class": exc.failure_class,
                        "side_effects_certainty": certainty,
                    },
                )

            side_effects = exc.failure_class in {
                "publication-failed",
                "verification-failed",
            }
            certainty = (
                "known"
                if exc.failure_class == "verification-failed"
                or not side_effects
                else "unknown"
            )
            result = self.state.finish_external_operation(
                request=request,
                descriptor=descriptor,
                workflow_id=workflow_id,
                receipt_id=receipt_id,
                outcome="failed",
                side_effects=side_effects,
                side_effects_certainty=certainty,
                detail={
                    "failure_class": exc.failure_class,
                    "message": exc.message,
                    "retryable": False,
                },
                validate_contract=self.contracts.validate,
                budget_hold_required=True,
            )
            return 200, result
        except PublicationServiceUnavailable as exc:
            self.state.pause_external_operation(
                workflow_id=workflow_id,
                failure_class="backend-unavailable",
                message=str(exc),
                retryable=True,
                side_effects=exc.side_effects_possible,
                side_effects_certainty=exc.side_effects_certainty,
                validate_contract=self.contracts.validate,
            )
            return 503, self.failure(
                request_id,
                operation,
                "backend-unavailable",
                str(exc)[:1000],
                True,
                side_effects=exc.side_effects_possible,
                detail={
                    "workflow_id": workflow_id,
                    "workflow_state": "waiting",
                    "side_effects_certainty": exc.side_effects_certainty,
                },
            )
        except PublicationServiceProtocolError as exc:
            self.state.pause_external_operation(
                workflow_id=workflow_id,
                failure_class="internal",
                message=str(exc),
                retryable=True,
                side_effects=True,
                side_effects_certainty="unknown",
                validate_contract=self.contracts.validate,
            )
            return 502, self.failure(
                request_id,
                operation,
                "internal",
                str(exc)[:1000],
                True,
                side_effects=True,
                detail={
                    "workflow_id": workflow_id,
                    "workflow_state": "waiting",
                    "side_effects_certainty": "unknown",
                },
            )
        except Exception as exc:
            message = (
                f"unexpected publication adapter failure: {exc}"
            )[:1000]
            self.state.pause_external_operation(
                workflow_id=workflow_id,
                failure_class="internal",
                message=message,
                retryable=False,
                side_effects=True,
                side_effects_certainty="unknown",
                validate_contract=self.contracts.validate,
            )
            return 500, self.failure(
                request_id,
                operation,
                "internal",
                message,
                False,
                side_effects=True,
                detail={
                    "workflow_id": workflow_id,
                    "workflow_state": "waiting",
                    "side_effects_certainty": "unknown",
                },
            )

        result = self.state.finish_external_operation(
            request=request,
            descriptor=descriptor,
            workflow_id=workflow_id,
            receipt_id=receipt_id,
            outcome="completed",
            side_effects=True,
            side_effects_certainty="known",
            detail={
                "sha256": service_result["sha256"],
                "size_bytes": service_result["size_bytes"],
                "cid": service_result["cid"],
                "cid_profile": service_result["cid_profile"],
                "pinned": service_result["pinned"],
                "verified": service_result["verified"],
            },
            validate_contract=self.contracts.validate,
            budget_hold_required=True,
        )
        return 200, result

    def workflow_evidence(
        self,
        workflow_id: str,
    ) -> tuple[int, dict[str, Any]]:
        evidence = self.state.get_workflow_evidence(workflow_id)
        if evidence is None:
            return 404, {
                "contract_version": 1,
                "workflow_id": workflow_id,
                "error": "workflow-not-found",
                "side_effects": False,
            }

        self.contracts.validate("workflow-evidence-v1.schema.json", evidence)
        return 200, evidence

    def failure(
        self,
        request_id: Any,
        operation: Any,
        failure_class: str,
        message: Any,
        retryable: bool,
        side_effects: bool = False,
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized_request_id = (
            request_id
            if isinstance(request_id, str) and _ID_RE.fullmatch(request_id)
            else "invalid:request"
        )

        normalized_operation = (
            operation
            if isinstance(operation, str)
            and len(operation) <= 160
            and _OPERATION_RE.fullmatch(operation)
            else "audit.invalid_request"
        )

        normalized_message = str(message)[:1000]
        if not normalized_message:
            normalized_message = "request failed"

        failure = {
            "contract_version": 1,
            "request_id": normalized_request_id,
            "operation": normalized_operation,
            "failure_class": failure_class,
            "message": normalized_message,
            "retryable": bool(retryable),
            "side_effects": bool(side_effects),
        }
        if detail is not None:
            failure["detail"] = detail
        self.contracts.validate("failure-envelope-v1.schema.json", failure)
        return failure
