"""Authenticated client from the Portal broker to the Civic Orchestrator.

The broker holds one adapter credential. The Orchestrator maps that credential
to a fixed client identity, caller authority, and Participant subject
namespace (RFC-0002). This client never accepts an operation, endpoint, or
identity from a Participant: callers in this package pass fixed operation
constants and a ParticipantIdentity resolved from SO_PEERCRED.
"""

from __future__ import annotations

import json
import os
import re
import stat
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlsplit

from .participants import LocalAdapterError, ParticipantIdentity


_CREDENTIAL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_OPERATION_RE = re.compile(
    r"^(publication|geography|participant|repository|rag|inference|edge|firmware|"
    r"signing|audit|incident)\.[a-z][a-z0-9._-]{0,159}$"
)
MAX_CREDENTIAL_BYTES = 16_384
MAX_ORCHESTRATOR_RESPONSE_BYTES = 65_536
_BINDING_FIELDS = frozenset({
    "client_id",
    "client_kind",
    "authenticated_by",
    "caller_authority",
    "subject_prefix",
})


@dataclass(frozen=True)
class AdapterCredential:
    token: str
    client_id: str
    client_kind: str
    authenticated_by: str
    caller_authority: str
    subject_prefix: str


@dataclass(frozen=True)
class OrchestratorReply:
    http_status: int
    body: dict[str, Any]

    @property
    def ok(self) -> bool:
        return 200 <= self.http_status < 300


def parse_adapter_credential(raw: bytes) -> AdapterCredential:
    """Parse the shared adapter credential document (version 1)."""
    if not raw or len(raw) > MAX_CREDENTIAL_BYTES:
        raise LocalAdapterError("adapter credential size is invalid")

    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LocalAdapterError("adapter credential is not valid JSON") from exc

    if not isinstance(value, dict) or set(value) != {
        "version",
        "token",
        "binding",
    }:
        raise LocalAdapterError("adapter credential fields are invalid")
    if value["version"] != 1:
        raise LocalAdapterError("adapter credential version is invalid")

    token = value["token"]
    if (
        not isinstance(token, str)
        or len(token) < 32
        or len(token) > 4096
        or any(ch.isspace() for ch in token)
    ):
        raise LocalAdapterError("adapter bearer token is invalid")

    binding = value["binding"]
    if (
        not isinstance(binding, dict)
        or set(binding) != _BINDING_FIELDS
        or any(
            not isinstance(binding[field], str) or not binding[field]
            for field in _BINDING_FIELDS
        )
    ):
        raise LocalAdapterError("adapter binding fields are invalid")

    return AdapterCredential(
        token=token,
        client_id=binding["client_id"],
        client_kind=binding["client_kind"],
        authenticated_by=binding["authenticated_by"],
        caller_authority=binding["caller_authority"],
        subject_prefix=binding["subject_prefix"],
    )


def load_systemd_adapter_credential(
    credential_name: str,
    *,
    credentials_directory: str | None = None,
) -> AdapterCredential:
    """Load the broker's adapter credential from systemd credentials."""
    if not _CREDENTIAL_NAME_RE.fullmatch(credential_name):
        raise LocalAdapterError("adapter credential name is invalid")

    directory_value = (
        credentials_directory
        if credentials_directory is not None
        else os.environ.get("CREDENTIALS_DIRECTORY")
    )
    if not directory_value:
        raise LocalAdapterError("systemd CREDENTIALS_DIRECTORY is unavailable")

    directory = Path(directory_value)
    if not directory.is_absolute():
        raise LocalAdapterError(
            "systemd CREDENTIALS_DIRECTORY must be absolute"
        )

    try:
        raw = (directory / credential_name).read_bytes()
    except OSError as exc:
        raise LocalAdapterError("adapter credential cannot be read") from exc
    return parse_adapter_credential(raw)


def load_protected_adapter_credential(
    path: Path,
    *,
    required_owner_uid: int | None = 0,
) -> AdapterCredential:
    """Load the adapter credential file directly, for operator tools.

    The file must be a regular file, not a symlink, owned by root, and
    readable by its owner only.
    """
    path = Path(path)
    if not path.is_absolute():
        raise LocalAdapterError("adapter credential path must be absolute")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise LocalAdapterError("adapter credential cannot be opened") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise LocalAdapterError("adapter credential must be a regular file")
        if required_owner_uid is not None and st.st_uid != required_owner_uid:
            raise LocalAdapterError("adapter credential has an invalid owner")
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise LocalAdapterError(
                "adapter credential must not be group/world accessible"
            )
        raw = os.read(fd, MAX_CREDENTIAL_BYTES + 1)
    finally:
        os.close(fd)

    return parse_adapter_credential(raw)


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


class OrchestratorClient:
    """Submit fixed Civic operations for a resolved Participant."""

    def __init__(
        self,
        base_url: str,
        credential: AdapterCredential,
        *,
        timeout: float = 10.0,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise LocalAdapterError("Orchestrator base URL is invalid")
        if timeout <= 0:
            raise LocalAdapterError("Orchestrator timeout must be positive")

        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.operations_url = f"{self.base_url}/v1/operations"
        self.credential = credential
        self.timeout = timeout
        self._opener = opener or urllib.request.urlopen

    def build_request(
        self,
        operation: str,
        participant: ParticipantIdentity,
        input_value: dict[str, Any],
        *,
        request_namespace: str = "broker",
    ) -> dict[str, Any]:
        if not isinstance(operation, str) or not _OPERATION_RE.fullmatch(operation):
            raise LocalAdapterError("Civic operation is invalid")
        if not isinstance(input_value, dict):
            raise LocalAdapterError("Civic operation input must be an object")
        if (
            not participant.participant_id.startswith(
                self.credential.subject_prefix
            )
            or len(participant.participant_id)
            <= len(self.credential.subject_prefix)
        ):
            raise LocalAdapterError(
                "participant identity is outside adapter subject namespace"
            )

        return {
            "contract_version": 1,
            "request_id": f"req:{request_namespace}:{uuid.uuid4().hex}",
            "operation": operation,
            "caller": {
                "subject": participant.participant_id,
                "authority": self.credential.caller_authority,
                "authenticated_by": self.credential.authenticated_by,
            },
            "client": {
                "id": self.credential.client_id,
                "kind": self.credential.client_kind,
            },
            "submitted_at": _utc_now(),
            "input": input_value,
        }

    def _exchange(
        self,
        request: urllib.request.Request,
    ) -> OrchestratorReply:
        try:
            response = self._opener(request, timeout=self.timeout)
            status = int(response.getcode())
            raw = response.read(MAX_ORCHESTRATOR_RESPONSE_BYTES + 1)
            response.close()
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            raw = exc.read(MAX_ORCHESTRATOR_RESPONSE_BYTES + 1)
            exc.close()
        except (OSError, urllib.error.URLError) as exc:
            raise LocalAdapterError(
                "Orchestrator transport is unavailable"
            ) from exc

        if len(raw) > MAX_ORCHESTRATOR_RESPONSE_BYTES:
            raise LocalAdapterError("Orchestrator response is too large")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LocalAdapterError(
                "Orchestrator returned invalid JSON"
            ) from exc
        if not isinstance(value, dict):
            raise LocalAdapterError("Orchestrator response must be an object")
        return OrchestratorReply(http_status=status, body=value)

    def submit(
        self,
        operation: str,
        participant: ParticipantIdentity,
        input_value: dict[str, Any],
        *,
        request_namespace: str = "broker",
    ) -> tuple[dict[str, Any], OrchestratorReply]:
        """Submit one operation. Returns (request_sent, reply)."""
        request_value = self.build_request(
            operation,
            participant,
            input_value,
            request_namespace=request_namespace,
        )
        body = json.dumps(
            request_value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        request = urllib.request.Request(
            self.operations_url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.credential.token}",
                "Content-Type": "application/json",
            },
        )
        return request_value, self._exchange(request)

    def workflow_evidence(self, workflow_id: str) -> OrchestratorReply:
        if not isinstance(workflow_id, str) or not workflow_id:
            raise LocalAdapterError("workflow_id is invalid")
        request = urllib.request.Request(
            f"{self.base_url}/v1/workflows/{quote(workflow_id, safe=':')}",
            method="GET",
            headers={"Authorization": f"Bearer {self.credential.token}"},
        )
        return self._exchange(request)
