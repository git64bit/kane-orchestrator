from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from .usermin_adapter import LocalAdapterError, ParticipantIdentity


_CREDENTIAL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
MAX_CREDENTIAL_BYTES = 16_384
MAX_ORCHESTRATOR_RESPONSE_BYTES = 65_536


@dataclass(frozen=True)
class AdapterCredential:
    token: str
    client_id: str
    client_kind: str
    authenticated_by: str
    caller_authority: str
    subject_prefix: str


def load_systemd_adapter_credential(
    credential_name: str,
    *,
    credentials_directory: str | None = None,
) -> AdapterCredential:
    """Load the Usermin broker credential from systemd credentials."""
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

    path = directory / credential_name
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise LocalAdapterError("adapter credential cannot be read") from exc

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
    fields = {
        "client_id",
        "client_kind",
        "authenticated_by",
        "caller_authority",
        "subject_prefix",
    }
    if (
        not isinstance(binding, dict)
        or set(binding) != fields
        or any(
            not isinstance(binding[field], str) or not binding[field]
            for field in fields
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


class OrchestratorPublisher:
    """Publish one prepared participant artifact through the Civic Orchestrator."""

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
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise LocalAdapterError("Orchestrator base URL is invalid")
        if timeout <= 0:
            raise LocalAdapterError("Orchestrator timeout must be positive")

        self.operations_url = (
            f"{parsed.scheme}://{parsed.netloc}/v1/operations"
        )
        self.credential = credential
        self.timeout = timeout
        self._opener = opener or urllib.request.urlopen

    def build_request(
        self,
        participant: ParticipantIdentity,
        artifact: dict[str, Any],
    ) -> dict[str, Any]:
        if not participant.participant_id.startswith(
            self.credential.subject_prefix
        ):
            raise LocalAdapterError(
                "participant identity is outside adapter subject namespace"
            )

        return {
            "contract_version": 1,
            "request_id": f"req:usermin:{uuid.uuid4().hex}",
            "operation": "publication.publish",
            "caller": {
                "subject": participant.participant_id,
                "authority": self.credential.caller_authority,
                "authenticated_by": self.credential.authenticated_by,
            },
            "client": {
                "id": self.credential.client_id,
                "kind": self.credential.client_kind,
            },
            "submitted_at": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "input": {
                "artifact": artifact,
            },
        }

    def _decode_response(self, raw: bytes) -> dict[str, Any]:
        if len(raw) > MAX_ORCHESTRATOR_RESPONSE_BYTES:
            raise LocalAdapterError("Orchestrator response is too large")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LocalAdapterError(
                "Orchestrator returned invalid JSON"
            ) from exc
        if not isinstance(value, dict):
            raise LocalAdapterError(
                "Orchestrator response must be an object"
            )
        return value

    def __call__(
        self,
        participant: ParticipantIdentity,
        artifact: dict[str, Any],
    ) -> dict[str, Any]:
        request_value = self.build_request(participant, artifact)
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

        value = self._decode_response(raw)

        if (
            200 <= status < 300
            and value.get("status") in {"accepted", "completed"}
        ):
            result = dict(value)
            result["remote_dispatch"] = True
            result["orchestrator_http_status"] = status
            return result

        message = value.get("message")
        if not isinstance(message, str) or not message:
            message = f"Orchestrator rejected publication with HTTP {status}"

        return {
            "status": "rejected",
            "remote_dispatch": True,
            "orchestrator_http_status": status,
            "error": message[:500],
            "orchestrator": value,
        }
