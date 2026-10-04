"""Owner Operator command for Participant onboarding (BCP-0002).

Run as root inside the Portal container:

    civic-participant add USERNAME [--create-account] [--qualification NAME ...]
    civic-participant grant USERNAME CODENAME --reason TEXT [--discover-only] [--expires ISO8601]
    civic-participant revoke USERNAME CODENAME
    civic-participant retire USERNAME
    civic-participant list

Rules enforced here:

- a Participant identifier is minted once (`participant:<uuid4>`) and never
  reused, renamed, or deleted; retirement sets it inactive and keeps it as a
  tombstone;
- one Unix account maps to at most one Participant identifier, ever;
- command access is default-deny and every grant records who granted it,
  when, and why; qualifications are descriptive and never grant anything;
- both files are validated in full before they replace the originals, and
  are replaced atomically with their ownership and mode preserved.

The broker reads the Participant registry on every request but loads the
access policy at start, so access changes restart the broker service.
"""

from __future__ import annotations

import argparse
import fcntl
import grp
import json
import os
import pwd
import re
import subprocess
import sys
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence

import yaml
from jsonschema import Draft202012Validator

from .custom_command_access import CustomCommandAccessPolicy
from .custom_commands import CustomCommandRegistry
from .participants import LocalAdapterError, ParticipantRegistry


ETC = Path("/etc/civic-orchestrator")
BROKER_SERVICE = "civic-custom-command-broker.service"
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_QUALIFICATION_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")

Runner = Callable[[Sequence[str]], None]


class AdminError(RuntimeError):
    pass


def _run(argv: Sequence[str]) -> None:
    subprocess.run(list(argv), check=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class AdminPaths:
    registry: Path = ETC / "participants-v1.json"
    access_policy: Path = ETC / "custom-command-access-v1.yaml"
    access_schema: Path = ETC / "custom-command-access-v1.schema.json"
    command_registry: Path = ETC / "custom-command-registry-v1.yaml"
    command_schema: Path = ETC / "custom-command-registry-v1.schema.json"
    help_catalog: Path = ETC / "custom-command-help-v1.yaml"
    help_schema: Path = ETC / "custom-command-help-v1.schema.json"
    lock: Path = ETC / ".participant-admin.lock"


def empty_registry() -> dict[str, Any]:
    return {"version": 1, "participants": []}


def empty_access_policy() -> dict[str, Any]:
    return {
        "contract_version": 1,
        "policy": "civic-custom-command-access",
        "defaults": {"discover": False, "invoke": False},
        "qualification_semantics": {"descriptive_only": True, "automatic_grants": False},
        "participants": [],
    }


def write_atomic(path: Path, data: bytes, *, uid: int, gid: int, mode: int) -> None:
    """Replace `path` atomically with `data`, owned uid:gid with `mode`."""
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        if os.geteuid() == 0:
            os.fchown(fd, uid, gid)
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(tmp, path)
    finally:
        if fd != -1:
            os.close(fd)
        if os.path.exists(tmp):
            os.unlink(tmp)


class ParticipantAdmin:
    def __init__(
        self,
        paths: AdminPaths = AdminPaths(),
        *,
        participant_group: str = "civic-participants",
        file_group: str = "civic-broker",
        operator: str = "operator:root",
        runner: Runner = _run,
        require_secure_files: bool = True,
        restart_broker: bool = True,
    ) -> None:
        self.paths = paths
        self.participant_group = participant_group
        self.file_group = file_group
        self.operator = operator
        self.runner = runner
        self.require_secure_files = require_secure_files
        self.restart_broker = restart_broker

    # ---------------------------------------------------------------- files

    @contextmanager
    def locked(self) -> Iterator[None]:
        with open(self.paths.lock, "a") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def _file_owner(self, path: Path) -> tuple[int, int, int]:
        try:
            st = path.stat()
            return st.st_uid, st.st_gid, 0o640
        except FileNotFoundError:
            try:
                gid = grp.getgrnam(self.file_group).gr_gid
            except KeyError:
                gid = 0
            return 0, gid, 0o640

    def load_registry(self) -> dict[str, Any]:
        if not self.paths.registry.exists():
            return empty_registry()
        value = json.loads(self.paths.registry.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise AdminError("participant registry is not an object")
        return value

    def load_access(self) -> dict[str, Any]:
        if not self.paths.access_policy.exists():
            return empty_access_policy()
        value = yaml.safe_load(self.paths.access_policy.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise AdminError("access policy is not an object")
        return value

    def _command_registry(self) -> CustomCommandRegistry:
        return CustomCommandRegistry.load(
            self.paths.command_registry,
            self.paths.command_schema,
            self.paths.help_catalog,
            self.paths.help_schema,
        )

    def _validate(self, registry: dict[str, Any], access: dict[str, Any]) -> None:
        # Registry: run the broker's own parser over a candidate copy.
        with tempfile.TemporaryDirectory(dir=str(self.paths.registry.parent)) as tmp:
            candidate = Path(tmp) / "participants-v1.json"
            candidate.write_text(json.dumps(registry), encoding="utf-8")
            try:
                ParticipantRegistry(candidate, require_secure_file=False)._load_entries()
            except LocalAdapterError as exc:
                raise AdminError(f"participant registry would be invalid: {exc}") from exc

        # Access policy: schema, then the broker's own semantic checks.
        schema = json.loads(self.paths.access_schema.read_text(encoding="utf-8"))
        validator = Draft202012Validator(
            schema, format_checker=Draft202012Validator.FORMAT_CHECKER
        )
        errors = sorted(validator.iter_errors(access), key=lambda e: list(e.absolute_path))
        if errors:
            raise AdminError(f"access policy would be invalid: {errors[0].message}")
        try:
            CustomCommandAccessPolicy(access).validate_codenames(
                self._command_registry().codenames
            )
        except LocalAdapterError as exc:
            raise AdminError(f"access policy would be invalid: {exc}") from exc

        registered = {item["participant_id"] for item in registry["participants"]}
        for item in access["participants"]:
            if item["participant_id"] not in registered:
                raise AdminError(
                    f"access policy references an unregistered Participant: {item['participant_id']}"
                )

    def _save(self, registry: dict[str, Any], access: dict[str, Any], *, access_changed: bool) -> None:
        self._validate(registry, access)
        uid, gid, mode = self._file_owner(self.paths.access_policy)
        write_atomic(
            self.paths.access_policy,
            yaml.safe_dump(access, sort_keys=False, default_flow_style=False).encode("utf-8"),
            uid=uid, gid=gid, mode=mode,
        )
        uid, gid, mode = self._file_owner(self.paths.registry)
        write_atomic(
            self.paths.registry,
            (json.dumps(registry, indent=2) + "\n").encode("utf-8"),
            uid=uid, gid=gid, mode=mode,
        )
        if access_changed and self.restart_broker:
            self.runner(["systemctl", "try-restart", BROKER_SERVICE])

    # --------------------------------------------------------------- lookup

    @staticmethod
    def _entry_for(registry: dict[str, Any], username: str) -> dict[str, Any]:
        matches = [item for item in registry["participants"] if item["username"] == username]
        if not matches:
            raise AdminError(f"no Participant is registered for account {username}")
        if len(matches) > 1:
            raise AdminError(f"account {username} has more than one registry entry")
        return matches[0]

    @staticmethod
    def _access_for(access: dict[str, Any], participant_id: str) -> dict[str, Any]:
        for item in access["participants"]:
            if item["participant_id"] == participant_id:
                return item
        raise AdminError(f"no access profile exists for {participant_id}")

    # ------------------------------------------------------------- commands

    def add(
        self,
        username: str,
        *,
        create_account: bool = False,
        qualifications: Sequence[str] = (),
    ) -> str:
        if not _USERNAME_RE.fullmatch(username):
            raise AdminError(f"invalid Unix username: {username}")
        for name in qualifications:
            if not _QUALIFICATION_RE.fullmatch(name):
                raise AdminError(f"invalid qualification name: {name}")

        with self.locked():
            registry = self.load_registry()
            access = self.load_access()

            try:
                account = pwd.getpwnam(username)
            except KeyError:
                if not create_account:
                    raise AdminError(
                        f"Unix account {username} does not exist; use --create-account"
                    ) from None
                self.runner(["useradd", "--create-home", "--shell", "/bin/bash", username])
                account = pwd.getpwnam(username)

            for item in registry["participants"]:
                if item["username"] == username or item["uid"] == account.pw_uid:
                    state = "active" if item["active"] else "retired"
                    raise AdminError(
                        f"account {username} (uid {account.pw_uid}) is already mapped to "
                        f"{item['participant_id']} ({state}); identities are never reused"
                    )

            participant_id = f"participant:{uuid.uuid4()}"
            now = utc_now()
            registry["participants"].append({
                "username": username,
                "uid": account.pw_uid,
                "participant_id": participant_id,
                "active": True,
            })
            access["participants"].append({
                "participant_id": participant_id,
                "active": True,
                "qualifications": [
                    {
                        "name": name,
                        "status": "current",
                        "recorded_by": self.operator,
                        "recorded_at": now,
                        "note": None,
                    }
                    for name in qualifications
                ],
                "command_access": [],
            })

            self._validate(registry, access)
            self.runner(["gpasswd", "--add", username, self.participant_group])
            self._save(registry, access, access_changed=True)
            return participant_id

    def grant(
        self,
        username: str,
        codename: str,
        *,
        reason: str,
        invoke: bool = True,
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        if not reason or not reason.strip():
            raise AdminError("a grant requires a reason")
        with self.locked():
            registry = self.load_registry()
            access = self.load_access()
            entry = self._entry_for(registry, username)
            if not entry["active"]:
                raise AdminError(f"{username} is retired; grants are not allowed")
            profile = self._access_for(access, entry["participant_id"])

            if codename not in self._command_registry().codenames:
                raise AdminError(f"unknown Custom Command: {codename}")

            grant = {
                "codename": codename,
                "discover": True,
                "invoke": bool(invoke),
                "granted_by": self.operator,
                "granted_at": utc_now(),
                "expires_at": expires_at,
                "reason": reason.strip(),
            }
            profile["command_access"] = [
                item for item in profile["command_access"] if item["codename"] != codename
            ] + [grant]
            self._save(registry, access, access_changed=True)
            return grant

    def revoke(self, username: str, codename: str) -> None:
        with self.locked():
            registry = self.load_registry()
            access = self.load_access()
            entry = self._entry_for(registry, username)
            profile = self._access_for(access, entry["participant_id"])
            remaining = [i for i in profile["command_access"] if i["codename"] != codename]
            if len(remaining) == len(profile["command_access"]):
                raise AdminError(f"{username} has no grant for {codename}")
            profile["command_access"] = remaining
            self._save(registry, access, access_changed=True)

    def retire(self, username: str) -> str:
        with self.locked():
            registry = self.load_registry()
            access = self.load_access()
            entry = self._entry_for(registry, username)
            if not entry["active"]:
                raise AdminError(f"{username} is already retired")
            entry["active"] = False
            try:
                profile = self._access_for(access, entry["participant_id"])
                profile["active"] = False
                profile["command_access"] = []
            except AdminError:
                pass
            self._validate(registry, access)
            self.runner(["gpasswd", "--delete", username, self.participant_group])
            self._save(registry, access, access_changed=True)
            return entry["participant_id"]

    def listing(self) -> list[dict[str, Any]]:
        registry = self.load_registry()
        access = self.load_access()
        profiles = {item["participant_id"]: item for item in access["participants"]}
        rows = []
        for item in registry["participants"]:
            profile = profiles.get(item["participant_id"], {})
            rows.append({
                "username": item["username"],
                "uid": item["uid"],
                "participant_id": item["participant_id"],
                "active": item["active"],
                "grants": [
                    g["codename"] + ("" if g["invoke"] else " (discover only)")
                    for g in profile.get("command_access", [])
                ],
            })
        return rows


_OPERATOR_RE = re.compile(r"^operator:[A-Za-z0-9._@-]{1,64}$")


def default_operator(environ: dict[str, str] | None = None) -> str:
    """Who is recorded as granting or recording.

    Order: a sudo user inside this container, then the node's recorded
    Owner Operator (CIVIC_OPERATOR, written by the installer from the host
    account that ran it), then the login name.
    """
    env = os.environ if environ is None else environ
    if env.get("SUDO_USER"):
        return f"operator:{env['SUDO_USER']}"
    recorded = env.get("CIVIC_OPERATOR", "")
    if _OPERATOR_RE.fullmatch(recorded):
        return recorded
    return f"operator:{env.get('USER') or 'root'}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="civic-participant", description=__doc__.split("\n\n")[0])
    parser.add_argument("--operator", default=default_operator(),
                        help="recorded as granted_by / recorded_by (default: the node's Owner Operator)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="register a Participant and mint a permanent identifier")
    p_add.add_argument("username")
    p_add.add_argument("--create-account", action="store_true")
    p_add.add_argument("--qualification", action="append", default=[])

    p_grant = sub.add_parser("grant", help="grant one Custom Command")
    p_grant.add_argument("username")
    p_grant.add_argument("codename")
    p_grant.add_argument("--reason", required=True)
    p_grant.add_argument("--discover-only", action="store_true")
    p_grant.add_argument("--expires")

    p_revoke = sub.add_parser("revoke", help="remove one Custom Command grant")
    p_revoke.add_argument("username")
    p_revoke.add_argument("codename")

    p_retire = sub.add_parser("retire", help="retire a Participant (kept as a tombstone)")
    p_retire.add_argument("username")

    sub.add_parser("list", help="show Participants and grants")

    args = parser.parse_args(argv)
    if not _OPERATOR_RE.fullmatch(args.operator):
        print("--operator must look like operator:<name>", file=sys.stderr)
        return 2
    admin = ParticipantAdmin(operator=args.operator)

    if os.geteuid() != 0:
        print("civic-participant must run as root", file=sys.stderr)
        return 2

    try:
        if args.command == "add":
            pid = admin.add(args.username, create_account=args.create_account,
                            qualifications=args.qualification)
            print(f"{args.username} -> {pid}")
            print("No Custom Commands are granted yet (default deny).")
        elif args.command == "grant":
            grant = admin.grant(args.username, args.codename, reason=args.reason,
                                invoke=not args.discover_only, expires_at=args.expires)
            print(json.dumps(grant, indent=2))
        elif args.command == "revoke":
            admin.revoke(args.username, args.codename)
            print(f"revoked {args.codename} from {args.username}")
        elif args.command == "retire":
            pid = admin.retire(args.username)
            print(f"retired {args.username} ({pid}); the identifier is kept and never reused")
        else:
            for row in admin.listing():
                state = "active " if row["active"] else "retired"
                grants = ", ".join(row["grants"]) or "-"
                print(f"{state} {row['username']:<20} {row['participant_id']}  {grants}")
    except (AdminError, subprocess.CalledProcessError) as exc:
        print(f"civic-participant: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
