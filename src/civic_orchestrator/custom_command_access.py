from __future__ import annotations

import json
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .participants import LocalAdapterError


class CustomCommandAccessError(LocalAdapterError):
    pass


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise CustomCommandAccessError(
            "Custom Command access timestamp must include a timezone"
        )
    return parsed.astimezone(timezone.utc)


class CustomCommandAccessPolicy:
    """Deployment-local, default-deny Participant Custom Command access."""

    def __init__(self, value: dict[str, Any]) -> None:
        self.value = value
        seen_participants: set[str] = set()
        indexed: dict[str, dict[str, Any]] = {}

        for participant in value["participants"]:
            participant_id = participant["participant_id"]
            if participant_id in seen_participants:
                raise CustomCommandAccessError(
                    f"duplicate Custom Command access participant_id: {participant_id}"
                )
            seen_participants.add(participant_id)

            seen_qualifications: set[str] = set()
            for qualification in participant["qualifications"]:
                name = qualification["name"]
                if name in seen_qualifications:
                    raise CustomCommandAccessError(
                        "duplicate Participant qualification in Custom Command access "
                        f"policy: {participant_id} / {name}"
                    )
                seen_qualifications.add(name)

            seen_commands: set[str] = set()
            for grant in participant["command_access"]:
                codename = grant["codename"]
                if codename in seen_commands:
                    raise CustomCommandAccessError(
                        "duplicate Custom Command access grant: "
                        f"{participant_id} / {codename}"
                    )
                seen_commands.add(codename)

            indexed[participant_id] = participant

        self._participants = indexed

    @classmethod
    def load(
        cls,
        policy_path: Path,
        schema_path: Path,
        *,
        require_secure_file: bool = True,
    ) -> "CustomCommandAccessPolicy":
        policy_path = Path(policy_path)
        schema_path = Path(schema_path)

        try:
            st = policy_path.stat()
        except OSError as exc:
            raise CustomCommandAccessError(
                f"Custom Command access policy is unavailable: {exc}"
            ) from exc

        if not stat.S_ISREG(st.st_mode):
            raise CustomCommandAccessError(
                "Custom Command access policy is not a regular file"
            )
        if require_secure_file:
            if st.st_uid != 0:
                raise CustomCommandAccessError(
                    "Custom Command access policy must be owned by root"
                )
            if stat.S_IMODE(st.st_mode) & 0o022:
                raise CustomCommandAccessError(
                    "Custom Command access policy must not be group/world writable"
                )

        try:
            value = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
            schema_value = json.loads(
                schema_path.read_text(encoding="utf-8")
            )
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            yaml.YAMLError,
        ) as exc:
            raise CustomCommandAccessError(
                f"Custom Command access contracts cannot be loaded: {exc}"
            ) from exc

        if not isinstance(value, dict):
            raise CustomCommandAccessError(
                "Custom Command access policy must be an object"
            )

        try:
            Draft202012Validator.check_schema(schema_value)
            Draft202012Validator(
                schema_value,
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            ).validate(value)
        except Exception as exc:
            raise CustomCommandAccessError(
                f"Custom Command access policy is invalid: {exc}"
            ) from exc

        return cls(value)

    def validate_codenames(self, codenames: set[str]) -> None:
        for participant in self._participants.values():
            for grant in participant["command_access"]:
                codename = grant["codename"]
                if codename not in codenames:
                    raise CustomCommandAccessError(
                        "Custom Command access policy references unknown codename: "
                        f"{codename}"
                    )

    def _participant(self, participant_id: str) -> dict[str, Any]:
        participant = self._participants.get(participant_id)
        if participant is None or not participant["active"]:
            raise CustomCommandAccessError(
                "Participant has no active Custom Command access profile"
            )
        return participant

    def qualifications(self, participant_id: str) -> list[dict[str, Any]]:
        participant = self._participant(participant_id)
        return list(participant["qualifications"])

    def _grant(
        self,
        participant_id: str,
        codename: str,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        participant = self._participant(participant_id)
        matches = [
            grant
            for grant in participant["command_access"]
            if grant["codename"] == codename
        ]
        if len(matches) != 1:
            raise CustomCommandAccessError(
                "Custom Command access is not granted"
            )

        grant = matches[0]
        expires_at = grant.get("expires_at")
        if expires_at is not None:
            if now is None:
                now = datetime.now(timezone.utc)
            elif now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)
            else:
                now = now.astimezone(timezone.utc)

            if now >= _parse_time(expires_at):
                raise CustomCommandAccessError(
                    "Custom Command access grant has expired"
                )

        return grant

    def discoverable_grants(
        self,
        participant_id: str,
        *,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        participant = self._participant(participant_id)
        visible: list[dict[str, Any]] = []

        for grant in participant["command_access"]:
            if not grant["discover"]:
                continue

            expires_at = grant.get("expires_at")
            if expires_at is not None:
                current = now
                if current is None:
                    current = datetime.now(timezone.utc)
                elif current.tzinfo is None:
                    current = current.replace(tzinfo=timezone.utc)
                else:
                    current = current.astimezone(timezone.utc)

                if current >= _parse_time(expires_at):
                    continue

            visible.append(grant)

        return sorted(
            visible,
            key=lambda item: item["codename"],
        )

    def require_discover(
        self,
        participant_id: str,
        codename: str,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        grant = self._grant(
            participant_id,
            codename,
            now=now,
        )
        if not grant["discover"]:
            raise CustomCommandAccessError(
                "Custom Command discovery is not granted"
            )
        return grant

    def require_invoke(
        self,
        participant_id: str,
        codename: str,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        grant = self._grant(
            participant_id,
            codename,
            now=now,
        )
        if not grant["invoke"]:
            raise CustomCommandAccessError(
                "Custom Command invocation is not granted"
            )
        return grant
