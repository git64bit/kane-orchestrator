from __future__ import annotations

import base64
import grp
import hashlib
import json
import os
import pwd
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_ARTIFACT_BYTES = 262_144
DEFAULT_MEDIA_TYPE = "application/octet-stream"
_PARTICIPANT_ID_RE = re.compile(
    r"^participant:[A-Za-z0-9][A-Za-z0-9._:@-]{0,148}$"
)


class LocalAdapterError(ValueError):
    pass


@dataclass(frozen=True)
class ParticipantIdentity:
    uid: int
    username: str
    participant_id: str


class ParticipantRegistry:
    """Resolve a kernel UID to a stable, provisioning-owned Civic identity."""

    def __init__(
        self,
        path: Path,
        *,
        participant_group: str = "civic-participants",
        require_secure_file: bool = True,
    ) -> None:
        self.path = Path(path)
        self.participant_group = participant_group
        self.require_secure_file = require_secure_file

    def _load_entries(self) -> list[dict[str, Any]]:
        try:
            st = self.path.stat()
        except OSError as exc:
            raise LocalAdapterError(
                f"participant registry is unavailable: {exc}"
            ) from exc

        if not stat.S_ISREG(st.st_mode):
            raise LocalAdapterError("participant registry is not a regular file")

        if self.require_secure_file:
            if st.st_uid != 0:
                raise LocalAdapterError(
                    "participant registry must be owned by root"
                )
            if stat.S_IMODE(st.st_mode) & 0o022:
                raise LocalAdapterError(
                    "participant registry must not be group/world writable"
                )

        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LocalAdapterError(
                f"participant registry cannot be read: {exc}"
            ) from exc

        if not isinstance(value, dict) or value.get("version") != 1:
            raise LocalAdapterError("participant registry version is invalid")

        entries = value.get("participants")
        if not isinstance(entries, list):
            raise LocalAdapterError(
                "participant registry participants must be a list"
            )

        seen_accounts: set[tuple[str, int]] = set()
        seen_participants: set[str] = set()
        normalized: list[dict[str, Any]] = []

        for item in entries:
            if not isinstance(item, dict):
                raise LocalAdapterError("participant registry entry is invalid")
            if set(item) != {
                "username",
                "uid",
                "participant_id",
                "active",
            }:
                raise LocalAdapterError(
                    "participant registry entry fields are invalid"
                )

            username = item["username"]
            uid = item["uid"]
            participant_id = item["participant_id"]
            active = item["active"]

            if not isinstance(username, str) or not username:
                raise LocalAdapterError("participant username is invalid")
            if (
                not isinstance(uid, int)
                or isinstance(uid, bool)
                or uid < 0
            ):
                raise LocalAdapterError("participant uid is invalid")
            if (
                not isinstance(participant_id, str)
                or not _PARTICIPANT_ID_RE.fullmatch(participant_id)
            ):
                raise LocalAdapterError("participant_id is invalid")
            if not isinstance(active, bool):
                raise LocalAdapterError("participant active flag is invalid")

            account_key = (username, uid)
            if account_key in seen_accounts:
                raise LocalAdapterError(
                    "participant registry contains duplicate account mapping"
                )
            if participant_id in seen_participants:
                raise LocalAdapterError(
                    "participant registry contains reused participant_id"
                )
            seen_accounts.add(account_key)
            seen_participants.add(participant_id)
            normalized.append(item)

        return normalized

    def _require_participant_group(self, username: str, primary_gid: int) -> None:
        try:
            group = grp.getgrnam(self.participant_group)
        except KeyError as exc:
            raise LocalAdapterError(
                f"required group does not exist: {self.participant_group}"
            ) from exc

        try:
            gids = os.getgrouplist(username, primary_gid)
        except OSError as exc:
            raise LocalAdapterError(
                "cannot resolve participant group membership"
            ) from exc

        if group.gr_gid not in gids:
            raise LocalAdapterError(
                "peer is not a member of the authorized participant group"
            )

    def resolve(self, uid: int) -> ParticipantIdentity:
        try:
            account = pwd.getpwuid(uid)
        except KeyError as exc:
            raise LocalAdapterError("peer UID has no Unix account") from exc

        self._require_participant_group(account.pw_name, account.pw_gid)

        matches = [
            item
            for item in self._load_entries()
            if item["username"] == account.pw_name
            and item["uid"] == uid
            and item["active"]
        ]
        if len(matches) != 1:
            raise LocalAdapterError(
                "Unix account has no unique active stable participant mapping"
            )

        return ParticipantIdentity(
            uid=uid,
            username=account.pw_name,
            participant_id=matches[0]["participant_id"],
        )


def derive_artifact(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes):
        raise LocalAdapterError("publication payload must be bytes")
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise LocalAdapterError(
            f"artifact exceeds {MAX_ARTIFACT_BYTES} byte publication limit"
        )

    return {
        "media_type": DEFAULT_MEDIA_TYPE,
        "size_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "encoding": "base64",
        "content": base64.b64encode(payload).decode("ascii"),
    }
