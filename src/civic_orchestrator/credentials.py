"""Generate Civic service credentials.

    python -m civic_orchestrator.credentials adapter --output PATH
    python -m civic_orchestrator.credentials publication --output PATH

`adapter` writes the shared broker <-> Orchestrator credential: one random
bearer token plus the fixed identity binding the Orchestrator enforces. The
same file is installed in the Portal container (read by the broker) and in
the Orchestrator container (read by the Orchestrator).

`publication` writes the Orchestrator <-> publication-service bearer token.

The output file is created exclusively with mode 0600 and is never
overwritten. Nothing is printed to the terminal.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any


DEFAULT_BINDING = {
    "client_id": "portal-broker",
    "client_kind": "service",
    "authenticated_by": "adapter:portal-broker",
    "caller_authority": "portal-participant-registry",
    "subject_prefix": "participant:",
}


def new_token() -> str:
    # 48 random bytes -> 64 URL-safe characters, no whitespace.
    return secrets.token_urlsafe(48)


def adapter_document(binding: dict[str, str]) -> dict[str, Any]:
    return {"version": 1, "token": new_token(), "binding": dict(binding)}


def publication_document() -> dict[str, Any]:
    return {"version": 1, "token": new_token()}


def write_exclusive(path: Path, value: dict[str, Any]) -> None:
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, data)
    finally:
        os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Civic service credentials.")
    sub = parser.add_subparsers(dest="kind", required=True)

    adapter = sub.add_parser("adapter", help="broker <-> Orchestrator credential")
    adapter.add_argument("--output", required=True, type=Path)
    for field, default in DEFAULT_BINDING.items():
        adapter.add_argument(f"--{field.replace('_', '-')}", default=default)

    publication = sub.add_parser("publication", help="Orchestrator <-> publication credential")
    publication.add_argument("--output", required=True, type=Path)

    args = parser.parse_args(argv)

    if args.kind == "adapter":
        binding = {field: getattr(args, field) for field in DEFAULT_BINDING}
        value = adapter_document(binding)
    else:
        value = publication_document()

    try:
        write_exclusive(args.output, value)
    except FileExistsError:
        print(f"refusing to overwrite existing file: {args.output}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
