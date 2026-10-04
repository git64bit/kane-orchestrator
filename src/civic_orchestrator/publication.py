from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ContractValidator = Callable[[str, Any], None]

CID_PROFILE = "civic-ipfs-kubo-v1"
MAX_SINGLE_RAW_BLOCK_BYTES = 262_144


def validate_artifact_integrity(artifact: dict[str, Any]) -> str:
    """Verify that declared size/digest describe the submitted artifact bytes."""
    try:
        decoded = base64.b64decode(
            artifact["content"].encode("ascii"),
            validate=True,
        )
    except (KeyError, UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("publication artifact content is not strict base64") from exc

    if len(decoded) != artifact["size_bytes"]:
        raise ValueError(
            "publication artifact decoded size does not match size_bytes"
        )

    actual_sha256 = hashlib.sha256(decoded).hexdigest()
    if actual_sha256 != artifact["sha256"]:
        raise ValueError(
            "publication artifact bytes do not match declared sha256"
        )
    return actual_sha256


def expected_single_raw_cid(sha256_hex: str) -> str:
    """Return the CIDv1/raw/sha2-256 base32 identity for one raw block."""
    digest = bytes.fromhex(sha256_hex)
    if len(digest) != 32:
        raise ValueError("sha256 digest must be 32 bytes")
    # CIDv1 (0x01), raw codec (0x55), sha2-256 multihash (0x12, 0x20).
    binary_cid = b"\x01\x55\x12\x20" + digest
    return "b" + base64.b32encode(binary_cid).decode("ascii").lower().rstrip("=")


@dataclass(frozen=True)
class PublicationServiceFailure(Exception):
    status_code: int
    failure_class: str
    message: str
    retryable: bool
    response: dict[str, Any]

    def __str__(self) -> str:
        return self.message


class PublicationServiceUnavailable(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        side_effects_possible: bool = True,
        side_effects_certainty: str = "unknown",
    ) -> None:
        super().__init__(message)
        self.side_effects_possible = bool(side_effects_possible)
        self.side_effects_certainty = side_effects_certainty


class PublicationServiceProtocolError(RuntimeError):
    pass


class PublicationServiceClient:
    """Bounded Orchestrator client for the frozen publication-service contract."""

    def __init__(
        self,
        base_url: str,
        validate_contract: ContractValidator,
        timeout_seconds: float = 5.0,
        bearer_token: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.validate_contract = validate_contract
        self.timeout_seconds = timeout_seconds
        if bearer_token is not None:
            if (
                len(bearer_token) < 32
                or len(bearer_token) > 4096
                or any(ch.isspace() for ch in bearer_token)
            ):
                raise ValueError("publication service bearer token is invalid")
        self.bearer_token = bearer_token

    def publish(
        self,
        workflow_id: str,
        artifact: dict[str, Any],
    ) -> dict[str, Any]:
        request_value = {
            "contract_version": 1,
            "workflow_id": workflow_id,
            "operation": "publication.publish",
            "artifact": artifact,
        }
        self.validate_contract(
            "publication-service-request-v1.schema.json",
            request_value,
        )
        verified_sha256 = validate_artifact_integrity(artifact)

        if self.bearer_token is None:
            raise PublicationServiceUnavailable(
                "publication service credential is not configured",
                side_effects_possible=False,
                side_effects_certainty="known",
            )

        body = json.dumps(
            request_value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

        request = Request(
            f"{self.base_url}/v1/publications",
            data=body,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.bearer_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                status_code = response.getcode()
                raw = response.read()
        except HTTPError as exc:
            raw = exc.read()
            if exc.code in {401, 403}:
                raise PublicationServiceUnavailable(
                    "publication service authentication failed",
                    side_effects_possible=False,
                    side_effects_certainty="known",
                ) from exc
            self._raise_service_failure(
                status_code=exc.code,
                raw=raw,
                expected_workflow_id=workflow_id,
            )
            raise AssertionError("unreachable")
        except URLError as exc:
            known_pre_dispatch = isinstance(exc.reason, ConnectionRefusedError)
            raise PublicationServiceUnavailable(
                f"publication service unavailable: {exc}",
                side_effects_possible=not known_pre_dispatch,
                side_effects_certainty=(
                    "known" if known_pre_dispatch else "unknown"
                ),
            ) from exc
        except ConnectionRefusedError as exc:
            raise PublicationServiceUnavailable(
                f"publication service unavailable: {exc}",
                side_effects_possible=False,
                side_effects_certainty="known",
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise PublicationServiceUnavailable(
                f"publication service unavailable: {exc}",
                side_effects_possible=True,
                side_effects_certainty="unknown",
            ) from exc

        if status_code != 200:
            raise PublicationServiceProtocolError(
                f"unexpected publication service HTTP status: {status_code}"
            )

        result = self._decode_json_object(raw)
        try:
            self.validate_contract(
                "publication-service-result-v1.schema.json",
                result,
            )
        except Exception as exc:
            raise PublicationServiceProtocolError(
                f"invalid publication service result: {exc}"
            ) from exc

        if result["workflow_id"] != workflow_id:
            raise PublicationServiceProtocolError(
                "publication service returned a different workflow_id"
            )
        if result["sha256"] != artifact["sha256"]:
            raise PublicationServiceProtocolError(
                "publication service returned a different sha256"
            )
        if result["size_bytes"] != artifact["size_bytes"]:
            raise PublicationServiceProtocolError(
                "publication service returned a different size_bytes"
            )
        if result["cid_profile"] != CID_PROFILE:
            raise PublicationServiceProtocolError(
                "publication service returned an unsupported cid_profile"
            )
        if artifact["size_bytes"] > MAX_SINGLE_RAW_BLOCK_BYTES:
            raise PublicationServiceProtocolError(
                "artifact exceeds independently verifiable single-block profile"
            )
        expected_cid = expected_single_raw_cid(verified_sha256)
        if result["cid"] != expected_cid:
            raise PublicationServiceProtocolError(
                "publication service returned a CID that does not match "
                "the submitted artifact under the frozen profile"
            )

        return result

    def _raise_service_failure(
        self,
        status_code: int,
        raw: bytes,
        expected_workflow_id: str,
    ) -> None:
        failure = self._decode_json_object(raw)
        try:
            self.validate_contract(
                "publication-service-failure-v1.schema.json",
                failure,
            )
        except Exception as exc:
            raise PublicationServiceProtocolError(
                f"invalid publication service failure: {exc}"
            ) from exc

        if failure["workflow_id"] != expected_workflow_id:
            raise PublicationServiceProtocolError(
                "publication service failure returned a different workflow_id"
            )

        raise PublicationServiceFailure(
            status_code=status_code,
            failure_class=failure["failure_class"],
            message=failure["message"],
            retryable=failure["retryable"],
            response=failure,
        )

    @staticmethod
    def _decode_json_object(raw: bytes) -> dict[str, Any]:
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PublicationServiceProtocolError(
                "publication service returned invalid JSON"
            ) from exc

        if not isinstance(value, dict):
            raise PublicationServiceProtocolError(
                "publication service response must be a JSON object"
            )
        return value
