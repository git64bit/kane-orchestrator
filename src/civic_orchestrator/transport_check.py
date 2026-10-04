"""Prove the Portal broker -> Orchestrator transport for one Participant.

Run by the Owner Operator as root inside the Portal container:

    python -m civic_orchestrator.transport_check \\
        --participant <unix-username> \\
        --orchestrator-base-url http://<orchestrator-bridge-address>:8045

The check resolves the Participant exactly as the broker does (Unix account
-> civic-participants membership -> active stable mapping), submits one fixed
side-effect-free stub operation with the broker's adapter credential, then
reads the Orchestrator's workflow evidence back and verifies that the
Participant identity and the adapter identity arrived unchanged.

The operation is fixed in code. It is registered as a stub with effect scope
`none`, so the check can never cause an external side effect.
"""

from __future__ import annotations

import argparse
import json
import pwd
import sys
from pathlib import Path
from typing import Any

from .orchestrator_client import (
    OrchestratorClient,
    load_protected_adapter_credential,
)
from .participants import LocalAdapterError, ParticipantIdentity, ParticipantRegistry


CHECK_OPERATION = "participant.validate_publication"
DEFAULT_ADAPTER_CREDENTIAL = "/etc/civic-orchestrator/credentials/adapter.json"
DEFAULT_PARTICIPANT_REGISTRY = "/etc/civic-orchestrator/participants-v1.json"


def _check(checks: list[dict[str, Any]], name: str, passed: bool, detail: Any) -> None:
    checks.append({"check": name, "passed": bool(passed), "detail": detail})


def run_transport_check(
    client: OrchestratorClient,
    participant: ParticipantIdentity,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    credential = client.credential

    sent, reply = client.submit(
        CHECK_OPERATION,
        participant,
        {},
        request_namespace="transport-check",
    )
    body = reply.body

    _check(checks, "orchestrator accepted adapter credential", reply.http_status == 200, reply.http_status)
    _check(checks, "request_id round-trip", body.get("request_id") == sent["request_id"], body.get("request_id"))
    _check(checks, "fixed operation", body.get("operation") == CHECK_OPERATION, body.get("operation"))
    _check(checks, "stub completed without side effects",
           body.get("status") == "not-implemented" and body.get("side_effects") is False,
           {"status": body.get("status"), "side_effects": body.get("side_effects")})

    workflow_id = body.get("workflow_id")
    evidence: dict[str, Any] = {}
    if isinstance(workflow_id, str) and workflow_id:
        evidence_reply = client.workflow_evidence(workflow_id)
        evidence = evidence_reply.body
        _check(checks, "workflow evidence readable", evidence_reply.http_status == 200, evidence_reply.http_status)
    else:
        _check(checks, "workflow evidence readable", False, "no workflow_id returned")

    accepted = [
        event
        for event in evidence.get("audit_events", [])
        if isinstance(event, dict)
        and event.get("event_type") == "civic.operation.accepted"
    ]
    event = accepted[0] if len(accepted) == 1 else {}
    data = event.get("data", {}) if isinstance(event.get("data"), dict) else {}

    _check(checks, "participant identity preserved",
           event.get("actor") == participant.participant_id,
           {"expected": participant.participant_id, "recorded": event.get("actor")})
    _check(checks, "adapter client identity preserved",
           data.get("client_id") == credential.client_id
           and data.get("client_kind") == credential.client_kind,
           {"client_id": data.get("client_id"), "client_kind": data.get("client_kind")})
    _check(checks, "adapter authentication recorded",
           data.get("authenticated_by") == credential.authenticated_by,
           data.get("authenticated_by"))
    _check(checks, "evidence records no side effects", evidence.get("side_effects") is False,
           evidence.get("side_effects"))

    return {
        "status": "passed" if all(item["passed"] for item in checks) else "failed",
        "operation": CHECK_OPERATION,
        "participant_id": participant.participant_id,
        "orchestrator": client.base_url,
        "workflow_id": workflow_id,
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the authenticated Portal broker -> Orchestrator transport.",
    )
    parser.add_argument("--participant", required=True, help="Unix username of a provisioned Participant")
    parser.add_argument("--orchestrator-base-url", required=True)
    parser.add_argument("--adapter-credential", default=DEFAULT_ADAPTER_CREDENTIAL)
    parser.add_argument("--participant-registry", default=DEFAULT_PARTICIPANT_REGISTRY)
    parser.add_argument("--participant-group", default="civic-participants")
    args = parser.parse_args(argv)

    try:
        credential = load_protected_adapter_credential(Path(args.adapter_credential))
        try:
            account = pwd.getpwnam(args.participant)
        except KeyError as exc:
            raise LocalAdapterError("Participant Unix account does not exist") from exc
        participant = ParticipantRegistry(
            Path(args.participant_registry),
            participant_group=args.participant_group,
        ).resolve(account.pw_uid)
        client = OrchestratorClient(args.orchestrator_base_url, credential)
        report = run_transport_check(client, participant)
    except LocalAdapterError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        return 2

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
