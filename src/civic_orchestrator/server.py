from __future__ import annotations

import argparse
import hmac
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from .publication import PublicationServiceClient
from .publication_budget import (
    PublicationBudgetPolicy,
    load_publication_budget_policy,
)
from .runtime import (
    AuthenticatedAdapterBinding,
    CivicOrchestrator,
    RuntimePaths,
)


MAX_OPERATION_REQUEST_BYTES = 1_500_000
_ADAPTER_CREDENTIAL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_PUBLICATION_CREDENTIAL_NAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
)
MAX_ADAPTER_CREDENTIAL_BYTES = 16_384
MAX_PUBLICATION_CREDENTIAL_BYTES = 4_096


class AdapterCredentialError(ValueError):
    pass


class BearerAdapterAuthenticator:
    """Resolve an HTTP bearer credential to one fixed adapter binding."""

    def __init__(
        self,
        credentials: list[
            tuple[str, AuthenticatedAdapterBinding]
        ],
    ) -> None:
        if not credentials:
            raise ValueError("at least one adapter credential is required")
        normalized: list[tuple[bytes, AuthenticatedAdapterBinding]] = []
        for token, binding in credentials:
            if not isinstance(token, str) or not token:
                raise ValueError("adapter bearer credential is invalid")
            normalized.append((token.encode("utf-8"), binding))
        self._credentials = tuple(normalized)

    def authenticate(
        self,
        authorization_header: str | None,
    ) -> AuthenticatedAdapterBinding:
        if not isinstance(authorization_header, str):
            raise AdapterCredentialError("adapter credential is required")
        scheme, sep, token = authorization_header.partition(" ")
        if sep != " " or scheme != "Bearer" or not token:
            raise AdapterCredentialError("adapter credential is invalid")

        token_bytes = token.encode("utf-8")
        for expected, binding in self._credentials:
            if hmac.compare_digest(token_bytes, expected):
                return binding

        raise AdapterCredentialError("adapter credential is invalid")


def load_systemd_adapter_authenticator(
    credential_name: str,
    *,
    credentials_directory: str | None = None,
) -> BearerAdapterAuthenticator:
    """Load one adapter credential from systemd's protected credential directory."""
    if not _ADAPTER_CREDENTIAL_NAME_RE.fullmatch(credential_name):
        raise ValueError("adapter credential name is invalid")

    directory_value = (
        credentials_directory
        if credentials_directory is not None
        else os.environ.get("CREDENTIALS_DIRECTORY")
    )
    if not directory_value:
        raise ValueError("systemd CREDENTIALS_DIRECTORY is unavailable")

    directory = Path(directory_value)
    if not directory.is_absolute():
        raise ValueError("systemd CREDENTIALS_DIRECTORY must be absolute")

    path = directory / credential_name
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError("adapter credential cannot be read") from exc

    if not raw or len(raw) > MAX_ADAPTER_CREDENTIAL_BYTES:
        raise ValueError("adapter credential size is invalid")

    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("adapter credential is not valid JSON") from exc

    if not isinstance(value, dict) or set(value) != {
        "version",
        "token",
        "binding",
    }:
        raise ValueError("adapter credential fields are invalid")
    if value["version"] != 1:
        raise ValueError("adapter credential version is invalid")

    token = value["token"]
    if (
        not isinstance(token, str)
        or len(token) < 32
        or len(token) > 4096
        or any(ch.isspace() for ch in token)
    ):
        raise ValueError("adapter bearer token is invalid")

    binding_value = value["binding"]
    required_binding_fields = {
        "client_id",
        "client_kind",
        "authenticated_by",
        "caller_authority",
        "subject_prefix",
    }
    if (
        not isinstance(binding_value, dict)
        or set(binding_value) != required_binding_fields
        or any(
            not isinstance(binding_value[field], str)
            or not binding_value[field]
            for field in required_binding_fields
        )
    ):
        raise ValueError("adapter binding fields are invalid")

    binding = AuthenticatedAdapterBinding(
        client_id=binding_value["client_id"],
        client_kind=binding_value["client_kind"],
        authenticated_by=binding_value["authenticated_by"],
        caller_authority=binding_value["caller_authority"],
        subject_prefix=binding_value["subject_prefix"],
    )
    return BearerAdapterAuthenticator([(token, binding)])


def load_systemd_publication_bearer_token(
    credential_name: str,
    *,
    credentials_directory: str | None = None,
) -> str:
    """Load the Orchestrator -> publication-service bearer token from systemd."""
    if not _PUBLICATION_CREDENTIAL_NAME_RE.fullmatch(credential_name):
        raise ValueError("publication credential name is invalid")

    directory_value = (
        credentials_directory
        if credentials_directory is not None
        else os.environ.get("CREDENTIALS_DIRECTORY")
    )
    if not directory_value:
        raise ValueError("systemd CREDENTIALS_DIRECTORY is unavailable")

    directory = Path(directory_value)
    if not directory.is_absolute():
        raise ValueError("systemd CREDENTIALS_DIRECTORY must be absolute")

    path = directory / credential_name
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError("publication credential cannot be read") from exc

    if not raw or len(raw) > MAX_PUBLICATION_CREDENTIAL_BYTES:
        raise ValueError("publication credential size is invalid")

    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("publication credential is not valid JSON") from exc

    if not isinstance(value, dict) or set(value) != {"version", "token"}:
        raise ValueError("publication credential fields are invalid")
    if value["version"] != 1:
        raise ValueError("publication credential version is invalid")

    token = value["token"]
    if (
        not isinstance(token, str)
        or len(token) < 32
        or len(token) > 4096
        or any(ch.isspace() for ch in token)
    ):
        raise ValueError("publication bearer token is invalid")

    return token


class Handler(BaseHTTPRequestHandler):
    runtime: CivicOrchestrator
    adapter_authenticator: BearerAdapterAuthenticator | None = None

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _operation_failure(
        self,
        status: int,
        failure_class: str,
        message: str,
        request_id=None,
        operation=None,
        retryable: bool = False,
    ) -> None:
        self.runtime.state.record_request_diagnostic(
            f"http-{failure_class}",
            request_id=request_id,
            operation=operation,
            detail=message,
        )
        self._send_json(
            status,
            self.runtime.failure(
                request_id=request_id,
                operation=operation,
                failure_class=failure_class,
                message=message,
                retryable=retryable,
            ),
        )

    def _authenticate_adapter(self) -> AuthenticatedAdapterBinding | None:
        if self.adapter_authenticator is None:
            self._operation_failure(
                503,
                "backend-unavailable",
                "authenticated adapter ingress is not configured",
                retryable=False,
            )
            return None

        try:
            return self.adapter_authenticator.authenticate(
                self.headers.get("Authorization")
            )
        except AdapterCredentialError as exc:
            self._operation_failure(
                401,
                "unauthorized",
                str(exc),
                retryable=False,
            )
            return None

    def do_GET(self) -> None:
        path = urlparse(self.path).path

        if path == "/v1/capabilities":
            self._send_json(200, self.runtime.capabilities())
            return

        if path == "/healthz":
            self._send_json(200, self.runtime.health())
            return

        if path.startswith("/v1/workflows/"):
            if self._authenticate_adapter() is None:
                return
            workflow_id = unquote(path[len("/v1/workflows/"):])
            if not workflow_id:
                self._send_json(
                    404,
                    {
                        "contract_version": 1,
                        "workflow_id": "invalid:workflow",
                        "error": "workflow-not-found",
                        "side_effects": False,
                    },
                )
                return
            try:
                status, payload = self.runtime.workflow_evidence(workflow_id)
                self._send_json(status, payload)
            except Exception:
                self._operation_failure(
                    500,
                    "internal",
                    "internal workflow evidence error",
                    operation="audit.get_workflow",
                )
            return

        self._operation_failure(
            404,
            "invalid-contract",
            "endpoint not found",
        )

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/v1/operations":
            self._operation_failure(
                404,
                "invalid-contract",
                "endpoint not found",
            )
            return

        adapter_binding = self._authenticate_adapter()
        if adapter_binding is None:
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._operation_failure(
                400,
                "invalid-contract",
                "invalid content length",
            )
            return

        if length <= 0 or length > MAX_OPERATION_REQUEST_BYTES:
            self._operation_failure(
                400,
                "invalid-contract",
                "request body size rejected",
            )
            return

        try:
            body = self.rfile.read(length)
            request = json.loads(body)
            if not isinstance(request, dict):
                raise ValueError("request body must be a JSON object")
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            self._operation_failure(
                400,
                "invalid-contract",
                str(exc),
            )
            return

        try:
            status, payload = self.runtime.submit_authenticated(
                request,
                adapter_binding,
            )
        except Exception:
            self._operation_failure(
                500,
                "internal",
                "internal request processing error",
                request_id=request.get("request_id"),
                operation=request.get("operation"),
            )
            return

        self._send_json(status, payload)

    def log_message(self, format: str, *args) -> None:
        return



_WILDCARD_LISTEN_ADDRESSES = frozenset({"", "0.0.0.0", "::", "[::]", "*"})


def require_specific_listen_address(address: str) -> str:
    """Refuse wildcard binds: the Orchestrator listens on one chosen address.

    On a node this is the Orchestrator container's private bridge address
    (RFC-0002); in development it is loopback.
    """
    if not isinstance(address, str) or address.strip() in _WILDCARD_LISTEN_ADDRESSES:
        raise ValueError(
            "the Orchestrator must listen on a specific address, not a wildcard"
        )
    return address


def build_runtime(
    repo_root: Path,
    state_db: Path,
    publication_base_url: str | None = None,
    publication_bearer_token: str | None = None,
    publication_budget_policy: PublicationBudgetPolicy | None = None,
) -> CivicOrchestrator:
    if publication_base_url and publication_budget_policy is None:
        raise ValueError(
            "publication budget policy is required when publication "
            "service routing is configured"
        )

    runtime = CivicOrchestrator(
        RuntimePaths(
            repo_root=repo_root,
            state_db=state_db,
        ),
        publication_budget_policy=publication_budget_policy,
    )
    if publication_base_url:
        runtime.publication_client = PublicationServiceClient(
            publication_base_url,
            runtime.contracts.validate,
            bearer_token=publication_bearer_token,
        )
    return runtime


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--state-db", required=True)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8045)
    parser.add_argument("--publication-base-url")
    parser.add_argument(
        "--publication-budget-policy",
        help=(
            "absolute path to the root-owned publication budget policy "
            "JSON file"
        ),
    )
    parser.add_argument(
        "--publication-credential-name",
        help=(
            "systemd credential name containing the Orchestrator-to-publication "
            "service bearer token"
        ),
    )
    parser.add_argument(
        "--adapter-credential-name",
        help=(
            "systemd credential name containing the adapter bearer token "
            "and fixed identity binding"
        ),
    )
    args = parser.parse_args()
    try:
        require_specific_listen_address(args.listen)
    except ValueError as exc:
        parser.error(str(exc))

    publication_budget_policy = None
    if args.publication_budget_policy:
        publication_budget_policy = load_publication_budget_policy(
            Path(args.publication_budget_policy)
        )

    publication_bearer_token = None
    if args.publication_credential_name:
        publication_bearer_token = load_systemd_publication_bearer_token(
            args.publication_credential_name
        )

    runtime = build_runtime(
        repo_root=Path(args.repo_root),
        state_db=Path(args.state_db),
        publication_base_url=args.publication_base_url,
        publication_bearer_token=publication_bearer_token,
        publication_budget_policy=publication_budget_policy,
    )
    Handler.runtime = runtime
    Handler.adapter_authenticator = None
    if args.adapter_credential_name:
        Handler.adapter_authenticator = load_systemd_adapter_authenticator(
            args.adapter_credential_name
        )
    server = ThreadingHTTPServer((args.listen, args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
