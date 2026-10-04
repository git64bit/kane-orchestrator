# BCP-0001 — Release and Repository Practice

Number: BCP-0001  
Title: Release and Repository Practice  
Status: Accepted  
Date: 2026-10-04  
Supersedes: none  
Superseded-by: none  
Related: RFC-0002, kane-civicmin BCP-0001

## Purpose

Keep the Orchestrator simple, inspectable, and usable by independent Owner Operators, and keep it in step with `kane-civicmin`.

## Documentation

The repository carries exactly these documents:

```text
README.md   single current operating document
rfcs/       architecture and contract decisions
bcps/       implementation and operating practices
INSTALL/    installation assets and scripts
```

Do not add separate living architecture, deployment, roadmap, handoff, or acceptance documents. Current state belongs in `README.md`; durable decisions belong in an RFC or BCP. Deployment facts about a particular Owner Operator's hosts do not belong in the repository.

## RFC and BCP lifecycle

States: `Draft`, `Accepted`, `Superseded`, `Withdrawn`.

An Accepted record is not rewritten to reverse its decision. A material change is a new record that supersedes the earlier one. Editorial corrections that do not change meaning are allowed.

## Versioning

Semantic Versioning: `vMAJOR.MINOR.PATCH`.

Before `v1.0.0`, minor versions are acceptance milestones. Release candidates use `vX.Y.Z-rc.N`.

Tags mark repository states that passed their milestone gate. Ordinary development commits are not tagged. Tags before `v1.0.0` are published as pre-releases.

Patch releases correct defects without widening the supported Civic surface. Minor releases may add bounded, compatible capability.

## Cross-review

At each tag, the assistant maintaining `kane-civicmin` inspects this repository's tagged state, and this repository's maintainer inspects the matching Civicmin tag. Findings are resolved before the next milestone begins.

Decisions are raised to the Owner Operator only when both repositories need them.

## Release notes

A tagged release states at minimum:

- supported Ubuntu LTS and Python baseline;
- the broker protocol version it serves;
- meaningful behavior changes;
- configuration or migration requirements;
- known limitations.

## Scope discipline

Implementation does not widen scope because Kubo, Usermin, or Civic Infrastructure exposes additional capability. Useful discoveries are noted in `README.md` and become work only when promoted into the active milestone.

## Verification

Every tag passes the full regression suite on the supported Python versions. No change may introduce a literal operator-specific address, hostname, or account into source or installation templates.
