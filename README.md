# Kane Orchestrator

Kane Orchestrator is the Civic authority plane of a portable Civic Infrastructure node: the Civic Orchestrator, the trusted local broker that Participant interfaces talk to, and the bounded services the Orchestrator consumes.

One Ubuntu LTS machine runs one node. An Owner Operator installs it with the scripts in `INSTALL/` and receives a working node. Kane County is the first reference deployment, not the product boundary.

```text
Participant
    |
    v
Usermin / Civicmin                       (kane-civicmin repository)
    |
    | AF_UNIX /run/civic-orchestrator/custom-command.sock
    v
Custom Command broker                    \
    |  SO_PEERCRED -> stable Participant  |
    |  default-deny command access        |  this repository,
    v                                     |  one Ubuntu node
Civic Orchestrator (127.0.0.1)            |
    |  workflow, authorization, budget,   |
    |  audit, receipts, CID verification /
    v
Publication service + Kubo               (separate publication host;
                                          INSTALL/ will provide it too)
```

## Current state

**Status:** `v0.1.0` — extraction baseline, pre-release

`v0.1.0` carries the accepted Orchestrator from the frozen `git64bit/kane-capabilities` repository into this repository **without behavior change**:

- contract-bearing runtime: request envelope validation, authorization decisions, workflow state machine, audit events, receipts, replay/idempotency, resumable external workflows, side-effect certainty;
- `publication.publish`: exact-byte integrity, per-Participant publication budget, independent CID verification under the frozen single-raw-block profile (262,144-byte ceiling);
- Custom Command broker: protocol v2 over AF_UNIX, `SO_PEERCRED` Participant resolution, curated default-deny access, `water-ants` / Publish File bound to `publication.publish` as a local stub;
- stub-first operation registry: every other Civic operation is registered and fails closed as `not-implemented` with no side effects;
- publication service: validation-only; Kubo is not enabled.

The suite runs 171 tests on Python 3.12 and 3.13.

Removed during extraction: the earlier Usermin stock Custom Command helpers (`usermin_upload`, `usermin_command`), all Kane host/network/account deployment records, and the cross-host ingress relay. The legacy single-purpose publication broker code (`usermin_broker.main`, `LocalPublicationAdapter`) is still present without deployment units; `v0.2.0` consolidates it into the one Custom Command broker.

No production node has been installed from this repository yet.

## Scope

This repository owns:

- Civic Participant identity resolution on the node (Unix account -> stable `participant:` identifier);
- Custom Command access policy and the trusted local broker;
- Orchestrator workflow, authorization, budget, audit, and evidence;
- the publication service and its Kubo backend;
- node and publication-host installation.

It does **not** own the Participant interface. Usermin and the Civicmin module belong to `kane-civicmin`, which also installs Usermin.

## Boundary shared with kane-civicmin

The two repositories reference each other only through what the installers need:

```text
socket   /run/civic-orchestrator/custom-command.sock   (0660)
group    civic-participants
protocol Custom Command broker protocol v2
```

This repository's installer creates the group and the socket. Civicmin's installer only checks that they exist.

## Layout

```text
README.md        single current operating document
rfcs/            architecture and contract decisions
bcps/            implementation and operating practices
INSTALL/         installation assets and scripts
src/             civic_orchestrator package
services/        publication service
contracts/       operation and Custom Command registries
schemas/         JSON Schema contracts
workflows/       workflow definitions
tests/           regression suite
```

`README.md` changes with the code. Long-lived decisions go to `rfcs/` and `bcps/`; accepted records are superseded, never silently rewritten.

## Running the tests

```text
python3 -m venv .venv
.venv/bin/pip install .
.venv/bin/python -m unittest discover -s tests
```

## Release path

Gate-driven Semantic Versioning (BCP-0001). Each tag is reviewed against the matching `kane-civicmin` tag before the next milestone starts.

```text
v0.1.0  extraction baseline
v0.2.0  single-node link: Custom Command broker -> local Orchestrator
v0.3.0  node installer on a clean Ubuntu LTS host, Participant onboarding
v0.4.0  Kubo publication backend and publication-host installer
v0.5.0  Owner Operator access to a shared publication host
v0.6.0  reference deployment validation with kane-civicmin
v0.9.0  independent Owner Operator release candidate
v1.0.0  water-ants publishes end to end on an independently installed node
```

Milestones may split or merge when implementation evidence requires it.

## Decisions pending

These are recorded here until they are settled by an RFC. They are raised to the Owner Operator only when both repositories need the decision.

- whether published content is retrievable from the IPFS network in `v1.0.0` (the frozen design keeps Kubo loopback-only with swarm disabled);
- how other Owner Operators are credentialed and capped on a shared publication host, and how that host is reached over the internet;
- the broker's real (non-stub) `water-ants` result shape, and whether explicit Participant confirmation is carried to the Orchestrator and recorded as evidence;
- the Owner Operator command for Participant onboarding.

## License

BSD 3-Clause License. See [LICENSE](LICENSE).
