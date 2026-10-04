from __future__ import annotations

import argparse
import json
from pathlib import Path

from civic_orchestrator.runtime import ContractStore, StateStore


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Reconcile one waiting publication workflow after an operator has "
            "proved that the prior uncertain dispatch produced no external side effect."
        )
    )
    parser.add_argument("--workflow-id", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument(
        "--actor",
        default="operator:publication-recovery",
    )
    parser.add_argument(
        "--state-db",
        default="/var/lib/civic-orchestrator/state/orchestrator.sqlite3",
    )
    parser.add_argument(
        "--repo-root",
        default="/opt/civic-orchestrator/current",
    )
    args = parser.parse_args()

    contracts = ContractStore(Path(args.repo_root))
    state = StateStore(Path(args.state_db))
    event_id = state.reconcile_publication_no_effect(
        args.workflow_id,
        actor=args.actor,
        reason=args.reason,
        validate_contract=contracts.validate,
    )

    evidence = state.get_workflow_evidence(args.workflow_id)
    print(
        json.dumps(
            {
                "status": "reconciled",
                "workflow_id": args.workflow_id,
                "event_id": event_id,
                "workflow": evidence["workflow"] if evidence else None,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
