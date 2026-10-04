# Kane Orchestrator

Kane Orchestrator is the Civic authority plane of a portable Civic Infrastructure node: the Civic Orchestrator, the trusted local broker that Participant interfaces talk to, and the bounded services the Orchestrator consumes.

One physical Ubuntu LTS host runs one node, with two LXD system containers as separate security domains (RFC-0002). An Owner Operator installs Ubuntu Server, runs one command from `INSTALL/`, and receives a working node. Kane County is the first reference deployment, not the product boundary.

```text
Ubuntu LTS host (node boundary)
|
+-- Portal container
|     Usermin / Civicmin                  (kane-civicmin)
|        |  AF_UNIX /run/civic-orchestrator/custom-command.sock
|        v
|     Custom Command broker               (this repository)
|        SO_PEERCRED -> stable Participant, default-deny access
|        |
|        |  authenticated HTTP over the private LXD bridge
|        v
+-- Orchestrator container
      Civic Orchestrator                  (this repository)
        workflow, authorization, budget, audit, receipts, CID verification
        |
        |  WireGuard, per-operator bearer credential
        v
Publication host: publication service + Kubo   (this repository)
```

The node consumes shared Civic Infrastructure services (DNS/DANE, certificate authority, WireGuard hub, pass-through proxy, publication host) from a default provider or from the Owner Operator's own hosts.

## Current state

**Status:** `v0.2.0` candidate — awaiting live acceptance on the reference node. `v0.1.0` (extraction baseline) is released.

### What works

- contract-bearing Orchestrator runtime carried unchanged from `git64bit/kane-capabilities`: envelope validation, authorization decisions, workflow state machine, audit events, receipts, replay/idempotency, resumable external workflows, side-effect certainty;
- `publication.publish`: exact-byte integrity, per-Participant publication budget, independent CID verification under the frozen single-raw-block profile (262,144-byte ceiling);
- Custom Command broker: protocol v2 over AF_UNIX, `SO_PEERCRED` Participant resolution, curated default-deny access, `water-ants` / Publish File bound to `publication.publish` as a **local stub**;
- stub-first operation registry: every other Civic operation is registered and fails closed as `not-implemented` with no side effects;
- publication service: validation-only; Kubo is not enabled.

### v0.2.0: Portal broker -> Orchestrator transport

`v0.2.0` builds and proves the authenticated transport across the private LXD bridge (RFC-0002) without changing anything Civicmin sees:

- `civic_orchestrator.orchestrator_client` — the broker-side client. It submits only operations fixed in code, for a Participant resolved from `SO_PEERCRED`, with the broker's adapter credential; it refuses any subject outside the credential's namespace before dispatch.
- `civic_orchestrator.transport_check` — run by the Owner Operator as root in the Portal container. It resolves a real Participant exactly as the broker does, submits one fixed side-effect-free stub operation (`participant.validate_publication`), reads the workflow evidence back, and verifies that the Participant identity and the adapter identity arrived unchanged.
- `civic_orchestrator.credentials` — generates the shared adapter credential and the publication credential as owner-only files, never overwriting.
- The Orchestrator refuses wildcard listen addresses; its unit template binds `@ORCHESTRATOR_LISTEN@`, the Orchestrator container's bridge address.
- The legacy single-purpose publication broker is removed; modules are renamed to `participants`, `broker_protocol`, `orchestrator_client`.

Unchanged by design, until `kane-civicmin` and this repository jointly define the real `water-ants` result and recorded-confirmation contract:

- broker protocol v2 and its `list`, `help`, and `water-ants` stub responses (locked by `tests/test_civicmin_contract.py`);
- `water-ants` remains `lifecycle: stub` in the registry; the broker service stays AF_UNIX-only and does not dispatch Participant commands to the Orchestrator.

The suite runs 193 tests; CI covers Python 3.11, 3.12, and 3.13 on Ubuntu 24.04.

No production node has been installed from this repository yet.

## Scope

This repository owns:

- the Custom Command broker in the Portal container: Participant identity resolution (Unix account -> stable `participant:` identifier), default-deny command access, fixed command-to-operation binding;
- the Civic Orchestrator in its own container: workflow, authorization, budget, audit, and evidence;
- the publication service and its Kubo backend;
- node installation (LXD, both containers, post-install enrollment) and publication-host installation.

It does **not** own the Participant interface (Usermin, Civicmin), which `kane-civicmin` installs, or the shared default infrastructure (DNS/DANE, certificate authority, WireGuard hub, proxy).

## Boundary shared with kane-civicmin

Inside the Portal container the repositories share only:

```text
socket   /run/civic-orchestrator/custom-command.sock   (0660)
group    civic-participants
protocol Custom Command broker protocol v2
```

The container manager is LXD. This repository's installer creates the group and the socket, then runs the `kane-civicmin` installer at a pinned release tag inside the Portal container. That location and tag are the only reference this repository holds to `kane-civicmin`.

## Authoritative records

- [RFC-0001 — Orchestrator Node Scope and Boundaries](rfcs/RFC-0001-orchestrator-node-scope-and-boundaries.md) (superseded by RFC-0002)
- [RFC-0002 — Node Topology and Installation](rfcs/RFC-0002-node-topology-and-installation.md)
- [BCP-0001 — Release and Repository Practice](bcps/BCP-0001-release-and-repository-practice.md)

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
v0.2.0  broker -> Orchestrator link across the private LXD bridge
v0.3.0  one-command node installer (LXD, both containers, post-install enrollment), Participant onboarding
v0.4.0  Kubo publication backend and publication-host installer
v0.5.0  per-operator publication credentials over WireGuard
v0.6.0  reference deployment validation with kane-civicmin
v0.9.0  independent Owner Operator release candidate
v1.0.0  water-ants publishes end to end on an independently installed node
```

Milestones may split or merge when implementation evidence requires it.

## Decisions pending

Recorded here until settled by an RFC. Raised to the Owner Operator only when both repositories need the decision.

- whether published content is retrievable from the IPFS network in `v1.0.0` (the frozen design keeps Kubo loopback-only with swarm disabled);
- per-operator caps enforced by a shared publication host;
- the broker's real (non-stub) `water-ants` result shape, and whether explicit Participant confirmation is carried to the Orchestrator and recorded as evidence;
- the Owner Operator command for Participant onboarding;

## License

BSD 3-Clause License. See [LICENSE](LICENSE).
