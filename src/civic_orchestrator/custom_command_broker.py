from __future__ import annotations

import argparse
import socket
from pathlib import Path

from .custom_command_access import CustomCommandAccessPolicy
from .custom_commands import (
    CustomCommandRegistry,
    LocalCustomCommandAdapter,
)
from .usermin_adapter import ParticipantRegistry
from .usermin_broker import (
    handle_command_connection,
    systemd_listener,
)


def serve_commands(
    listener: socket.socket,
    adapter: LocalCustomCommandAdapter,
) -> None:
    while True:
        conn, _ = listener.accept()
        with conn:
            handle_command_connection(conn, adapter)


def build_adapter(
    *,
    participant_registry_path: Path,
    participant_group: str,
    command_registry_path: Path,
    command_schema_path: Path,
    help_catalog_path: Path,
    help_schema_path: Path,
    access_policy_path: Path,
    access_schema_path: Path,
    require_secure_access_file: bool = True,
) -> LocalCustomCommandAdapter:
    participants = ParticipantRegistry(
        participant_registry_path,
        participant_group=participant_group,
    )
    commands = CustomCommandRegistry.load(
        command_registry_path,
        command_schema_path,
        help_catalog_path,
        help_schema_path,
    )
    access = CustomCommandAccessPolicy.load(
        access_policy_path,
        access_schema_path,
        require_secure_file=require_secure_access_file,
    )
    access.validate_codenames(commands.codenames)
    return LocalCustomCommandAdapter(
        participants,
        commands,
        access,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Validation-only Civic Custom Command AF_UNIX broker. "
            "This entry point has no remote-dispatch configuration."
        )
    )
    parser.add_argument(
        "--participant-registry",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--participant-group",
        default="civic-participants",
    )
    parser.add_argument(
        "--command-registry",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--command-schema",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--help-catalog",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--help-schema",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--access-policy",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--access-schema",
        type=Path,
        required=True,
    )
    args = parser.parse_args()

    adapter = build_adapter(
        participant_registry_path=args.participant_registry,
        participant_group=args.participant_group,
        command_registry_path=args.command_registry,
        command_schema_path=args.command_schema,
        help_catalog_path=args.help_catalog,
        help_schema_path=args.help_schema,
        access_policy_path=args.access_policy,
        access_schema_path=args.access_schema,
    )

    listener = systemd_listener()
    with listener:
        serve_commands(listener, adapter)


if __name__ == "__main__":
    main()
