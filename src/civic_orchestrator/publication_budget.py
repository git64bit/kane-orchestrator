from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path


MAX_PUBLICATION_BUDGET_POLICY_BYTES = 4_096


@dataclass(frozen=True)
class PublicationBudgetPolicy:
    max_publications: int
    max_publication_bytes: int

    def __post_init__(self) -> None:
        for name, value in (
            ("max_publications", self.max_publications),
            ("max_publication_bytes", self.max_publication_bytes),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise ValueError(f"{name} must be a non-negative integer")


@dataclass(frozen=True)
class PublicationBudgetUsage:
    completed_publications: int
    completed_bytes: int
    held_publications: int
    held_bytes: int

    @property
    def charged_publications(self) -> int:
        return self.completed_publications + self.held_publications

    @property
    def charged_bytes(self) -> int:
        return self.completed_bytes + self.held_bytes




def load_publication_budget_policy(
    path: Path,
    *,
    required_owner_uid: int | None = 0,
) -> PublicationBudgetPolicy:
    """Load an integrity-sensitive deployment publication budget policy."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("publication budget policy path must be absolute")
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("O_NOFOLLOW is required for publication budget policy")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError("publication budget policy cannot be opened") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(
                "publication budget policy must be a regular file"
            )
        if required_owner_uid is not None and st.st_uid != required_owner_uid:
            raise ValueError(
                "publication budget policy has an invalid owner"
            )
        if stat.S_IMODE(st.st_mode) & 0o022:
            raise ValueError(
                "publication budget policy must not be group/world writable"
            )

        raw = os.read(fd, MAX_PUBLICATION_BUDGET_POLICY_BYTES + 1)
    finally:
        os.close(fd)

    if not raw or len(raw) > MAX_PUBLICATION_BUDGET_POLICY_BYTES:
        raise ValueError("publication budget policy size is invalid")

    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            "publication budget policy is not valid JSON"
        ) from exc

    required_fields = {
        "version",
        "max_publications",
        "max_publication_bytes",
    }
    if not isinstance(value, dict) or set(value) != required_fields:
        raise ValueError("publication budget policy fields are invalid")
    if value["version"] != 1:
        raise ValueError("publication budget policy version is invalid")

    return PublicationBudgetPolicy(
        max_publications=value["max_publications"],
        max_publication_bytes=value["max_publication_bytes"],
    )

class PublicationBudgetExceeded(ValueError):
    def __init__(
        self,
        *,
        usage: PublicationBudgetUsage,
        policy: PublicationBudgetPolicy,
        requested_bytes: int,
        reason: str,
    ) -> None:
        super().__init__(reason)
        self.usage = usage
        self.policy = policy
        self.requested_bytes = requested_bytes
