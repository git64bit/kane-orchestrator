from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .custom_command_access import CustomCommandAccessPolicy
from .participants import (
    LocalAdapterError,
    ParticipantIdentity,
    ParticipantRegistry,
    derive_artifact,
)


class CustomCommandError(LocalAdapterError):
    pass


@dataclass(frozen=True)
class CommandInvocation:
    codename: str | None
    arguments: dict[str, Any]
    payload: bytes
    request_kind: str = "invoke"


class CustomCommandRegistry:
    """Validated, trusted inventory of participant-facing Custom Commands."""

    CALLABLE_LIFECYCLES = {"stub", "validation", "available"}

    def __init__(
        self,
        value: dict[str, Any],
        help_value: dict[str, Any],
    ) -> None:
        self.value = value
        self.help_value = help_value
        commands = value["commands"]
        seen: set[str] = set()
        indexed: dict[str, dict[str, Any]] = {}

        for command in commands:
            codename = command["codename"]
            if codename in seen:
                raise CustomCommandError(
                    f"duplicate Custom Command codename: {codename}"
                )
            seen.add(codename)

            lifecycle = command["lifecycle"]
            side_effects = command["side_effects_enabled"]
            binding = command["binding"]

            if lifecycle != "available" and side_effects:
                raise CustomCommandError(
                    f"non-available command enables side effects: {codename}"
                )
            if lifecycle in self.CALLABLE_LIFECYCLES:
                if binding["status"] != "bound":
                    raise CustomCommandError(
                        f"callable command has no bound operation: {codename}"
                    )

            indexed[codename] = command

        self._commands = indexed

        help_seen: set[str] = set()
        help_indexed: dict[str, dict[str, Any]] = {}
        for item in help_value["commands"]:
            codename = item["codename"]
            if codename in help_seen:
                raise CustomCommandError(
                    f"duplicate Custom Command help codename: {codename}"
                )
            help_seen.add(codename)
            help_indexed[codename] = item

        if set(help_indexed) != set(indexed):
            missing = sorted(set(indexed) - set(help_indexed))
            extra = sorted(set(help_indexed) - set(indexed))
            raise CustomCommandError(
                f"Custom Command help coverage mismatch: missing={missing} extra={extra}"
            )

        for codename, command in indexed.items():
            if help_indexed[codename]["display_name"] != command["display_name"]:
                raise CustomCommandError(
                    f"Custom Command help display name mismatch: {codename}"
                )

        self._help = help_indexed

    @classmethod
    def load(
        cls,
        registry_path: Path,
        schema_path: Path,
        help_path: Path,
        help_schema_path: Path,
    ) -> "CustomCommandRegistry":
        try:
            registry_value = yaml.safe_load(
                Path(registry_path).read_text(encoding="utf-8")
            )
            schema_value = json.loads(
                Path(schema_path).read_text(encoding="utf-8")
            )
            help_value = yaml.safe_load(
                Path(help_path).read_text(encoding="utf-8")
            )
            help_schema_value = json.loads(
                Path(help_schema_path).read_text(encoding="utf-8")
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
            raise CustomCommandError(
                f"Custom Command contracts cannot be loaded: {exc}"
            ) from exc

        if not isinstance(registry_value, dict):
            raise CustomCommandError("Custom Command registry must be an object")
        if not isinstance(help_value, dict):
            raise CustomCommandError("Custom Command help catalog must be an object")

        try:
            Draft202012Validator.check_schema(schema_value)
            Draft202012Validator(schema_value).validate(registry_value)
            Draft202012Validator.check_schema(help_schema_value)
            Draft202012Validator(help_schema_value).validate(help_value)
        except Exception as exc:
            raise CustomCommandError(
                f"Custom Command contract is invalid: {exc}"
            ) from exc

        return cls(registry_value, help_value)

    @property
    def codenames(self) -> set[str]:
        return set(self._commands)

    def lookup(self, codename: str) -> dict[str, Any]:
        try:
            return self._commands[codename]
        except KeyError as exc:
            raise CustomCommandError(
                f"unknown Custom Command codename: {codename}"
            ) from exc

    def participant_commands(
        self,
        *,
        include_declared: bool = False,
    ) -> list[dict[str, Any]]:
        commands = [
            command
            for command in self._commands.values()
            if "participant" in command["audience"]
            and command["lifecycle"] != "retired"
        ]
        if not include_declared:
            commands = [
                command
                for command in commands
                if command["lifecycle"] in self.CALLABLE_LIFECYCLES
            ]
        return sorted(
            commands,
            key=lambda item: item["display_name"].casefold(),
        )

    def help_for(self, codename: str) -> dict[str, Any]:
        self.lookup(codename)
        return self._help[codename]

    def render_catalog(self, *, include_declared: bool = False) -> str:
        commands = self.participant_commands(
            include_declared=include_declared
        )
        if not commands:
            return "No Custom Commands are currently discoverable."

        lines = ["Civic Custom Commands", ""]
        for command in commands:
            help_value = self._help[command["codename"]]
            lines.append(
                f"{command['display_name']} ({command['codename']}) "
                f"[{command['lifecycle']}]"
            )
            lines.append(f"  {help_value['summary']}")
        return "\n".join(lines)

    def render_help(self, codename: str) -> str:
        command = self.lookup(codename)
        help_value = self.help_for(codename)
        status_text = {
            "declared": "Not available yet. Reserved for a future bounded capability.",
            "stub": "Repository stub only. No remote dispatch or external side effect occurs.",
            "validation": "Validation path. External side effects remain disabled.",
            "available": "Available. Review the guidance below before running it.",
            "disabled": "Known command, but disabled by current policy or deployment.",
            "retired": "Retired. Historical identity is preserved; new invocation is rejected.",
        }[command["lifecycle"]]

        lines = [
            f"{command['display_name']} ({codename})",
            f"Status: {command['lifecycle']} — {status_text}",
            f"Attention: {help_value['attention']}",
            "",
            help_value["summary"],
        ]
        sections = [
            ("Use this when", help_value["use_when"]),
            ("Before you run it", help_value["before_run"]),
            ("Significant effects", help_value["significant_effects"]),
            ("Consequences to understand", help_value["consequences"]),
            ("If something goes wrong", help_value["incident_guidance"]),
        ]
        for title, entries in sections:
            if entries:
                lines.extend(["", f"{title}:"])
                lines.extend(f"- {entry}" for entry in entries)

        confirmation = help_value["confirmation"]
        if confirmation == "explicit":
            lines.extend([
                "",
                "Confirmation: explicit acknowledgement is required before invocation.",
            ])
        elif confirmation == "review":
            lines.extend([
                "",
                "Confirmation: review this guidance before invocation.",
            ])
        return "\n".join(lines)

    def require_confirmation(self, codename: str, confirmed: bool) -> None:
        help_value = self.help_for(codename)
        if help_value["confirmation"] == "explicit" and not confirmed:
            raise CustomCommandError(
                f"explicit participant confirmation is required: {codename}"
            )

    def is_callable(self, codename: str) -> bool:
        command = self.lookup(codename)
        return (
            command["lifecycle"] in self.CALLABLE_LIFECYCLES
            and command["binding"]["status"] == "bound"
        )

    def require_callable(self, codename: str) -> dict[str, Any]:
        command = self.lookup(codename)
        if command["lifecycle"] not in self.CALLABLE_LIFECYCLES:
            raise CustomCommandError(
                f"Custom Command is not callable: {codename}"
            )
        if command["binding"]["status"] != "bound":
            raise CustomCommandError(
                f"Custom Command has no bound operation: {codename}"
            )
        return command


class LocalCustomCommandAdapter:
    """Repository-side generic Custom Command stub dispatcher.

    This class deliberately performs no remote dispatch. It proves command
    recognition, participant binding, input validation, and fixed semantic
    binding before the production Usermin command is switched to this path.
    """

    def __init__(
        self,
        participant_registry: ParticipantRegistry,
        command_registry: CustomCommandRegistry,
        access_policy: CustomCommandAccessPolicy,
    ) -> None:
        self.participant_registry = participant_registry
        self.command_registry = command_registry
        self.access_policy = access_policy

    def _validate_input(
        self,
        command: dict[str, Any],
        invocation: CommandInvocation,
    ) -> None:
        profile = command["input_profile"]

        if not isinstance(invocation.arguments, dict):
            raise CustomCommandError("Custom Command arguments must be an object")

        if not profile["byte_payload"] and invocation.payload:
            raise CustomCommandError(
                f"Custom Command does not accept a byte payload: {invocation.codename}"
            )

        mode = profile["mode"]
        if mode in {"none", "upload-bytes"} and invocation.arguments:
            raise CustomCommandError(
                f"Custom Command does not accept typed arguments: {invocation.codename}"
            )
        if mode == "none" and invocation.payload:
            raise CustomCommandError(
                f"Custom Command accepts no input payload: {invocation.codename}"
            )

    def handle(
        self,
        peer_uid: int,
        invocation: CommandInvocation,
    ) -> dict[str, Any]:
        participant = self.participant_registry.resolve(peer_uid)

        if invocation.request_kind == "list":
            grants = self.access_policy.discoverable_grants(
                participant.participant_id
            )
            commands: list[dict[str, Any]] = []
            for grant in grants:
                codename = grant["codename"]
                command = self.command_registry.lookup(codename)
                if command["lifecycle"] == "retired":
                    continue
                help_value = self.command_registry.help_for(codename)
                commands.append({
                    "codename": codename,
                    "display_name": command["display_name"],
                    "lifecycle": command["lifecycle"],
                    "summary": help_value["summary"],
                    "available_to_run": (
                        grant["invoke"]
                        and self.command_registry.is_callable(codename)
                    ),
                })
            return {
                "status": "ok",
                "remote_dispatch": False,
                "side_effects": False,
                "participant_id": participant.participant_id,
                "commands": sorted(
                    commands,
                    key=lambda item: item["display_name"].casefold(),
                ),
            }

        if invocation.codename is None:
            raise CustomCommandError(
                "Custom Command codename is required"
            )

        if invocation.request_kind == "help":
            grant = self.access_policy.require_discover(
                participant.participant_id,
                invocation.codename,
            )
            command = self.command_registry.lookup(invocation.codename)
            return {
                "status": "ok",
                "remote_dispatch": False,
                "side_effects": False,
                "participant_id": participant.participant_id,
                "command": invocation.codename,
                "available_to_run": (
                    grant["invoke"]
                    and self.command_registry.is_callable(invocation.codename)
                ),
                "help": self.command_registry.render_help(
                    invocation.codename
                ),
            }

        if invocation.request_kind != "invoke":
            raise CustomCommandError(
                "unsupported Custom Command request kind"
            )

        self.access_policy.require_invoke(
            participant.participant_id,
            invocation.codename,
        )
        command = self.command_registry.require_callable(invocation.codename)
        self._validate_input(command, invocation)

        if invocation.codename != "water-ants":
            raise CustomCommandError(
                f"no repository stub handler exists for: {invocation.codename}"
            )

        artifact = derive_artifact(invocation.payload)
        binding = command["binding"]
        return {
            "status": "stub",
            "remote_dispatch": False,
            "side_effects": False,
            "command": invocation.codename,
            "operation": binding["operation"],
            "participant_id": participant.participant_id,
            "artifact": {
                "media_type": artifact["media_type"],
                "size_bytes": artifact["size_bytes"],
                "sha256": artifact["sha256"],
            },
        }
