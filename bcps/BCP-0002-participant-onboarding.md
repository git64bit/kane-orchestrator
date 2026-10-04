# BCP-0002 — Participant Onboarding

Number: BCP-0002  
Title: Participant Onboarding  
Status: Accepted  
Date: 2026-10-04  
Supersedes: none  
Superseded-by: none  
Related: RFC-0002, kane-civicmin BCP-0002

## Purpose

Give the Owner Operator one bounded way to admit, grant, and retire Participants on a node, so that identity and access records stay consistent and auditable.

## Practice

Participants are managed only with `civic-participant`, run as root in the Portal container:

```text
civic-participant add USERNAME [--create-account] [--qualification NAME ...]
civic-participant grant USERNAME CODENAME --reason TEXT [--discover-only] [--expires ISO8601]
civic-participant revoke USERNAME CODENAME
civic-participant retire USERNAME
civic-participant list
```

The Participant registry and the Custom Command access policy are not edited by hand.

## Identity

- `add` mints one permanent identifier, `participant:<uuid4>`, for one Unix account.
- An identifier is never reused, renamed, transferred, or deleted.
- A Unix account (by name or uid) that has ever been mapped is never mapped again, even after retirement.
- `retire` marks the identifier inactive, removes all its grants and its `civic-participants` membership, and keeps the registry entry as a tombstone so historical evidence stays attributable.

## Access

- Access is default-deny. `add` grants nothing.
- Every grant records who granted it (`--operator`, default `operator:<login>`), when, and why. A grant without a reason is refused.
- Qualifications are descriptive context recorded by the operator. They never grant access.
- A grant names one registered Custom Command. Granting invocation always includes discovery.

## Integrity

- The registry and the access policy are validated in full, with the broker's own loaders, before either is replaced.
- Both are replaced atomically, remain owned by `root` with group `civic-broker`, mode `0640`.
- Changes are serialized with a lock.
- The broker reads the registry on every request; access changes restart the broker so the new policy takes effect at once.

## Relationship to voluntary participation

Admission through `civic-participant` is the operator's record that the Participant has been admitted. It does not replace the Participant's own explicit evidence of voluntary participation recorded under `kane-civicmin` BCP-0002 (Self-Addressed Stamped Envelope, manual certificate installation, in-product acknowledgement). The `--reason` on a grant should reference that evidence.
