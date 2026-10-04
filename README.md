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

## Install a node

On a freshly installed **Ubuntu Server 24.04 LTS** host with a wired connection, run one command:

```text
curl -fsSL https://raw.githubusercontent.com/git64bit/kane-orchestrator/v0.3.0/INSTALL/install.sh | sudo bash
```

Add `-s -- --dry-run` after `bash` to see every change first without making any. Other options: `--subnet` (private bridge, default `10.77.0.0/24`), `--storage auto|lvm|dir`, `--pool-size GIB`.

The installer:

1. checks the host (Ubuntu 24.04, root, bridge subnet free);
2. installs LXD (the snap's current stable channel) and creates a `civic` storage pool: an LVM thin pool from free volume-group space when the root filesystem is on LVM, otherwise a directory pool;
3. creates the private bridge `civicbr0` and a `civic` profile, without touching any existing LXD configuration;
4. creates the `orchestrator` (`.20`) and `portal` (`.10`) containers;
5. installs this release in both, with its Python dependencies from their current releases;
6. generates one adapter credential in the Orchestrator container and copies it to the Portal container without writing it to the host disk;
7. starts the Orchestrator on its bridge address and the broker socket in the Portal container;
8. verifies the Portal reaches the Orchestrator, the Orchestrator is not on loopback, and the broker answers.

It is safe to re-run. Existing pieces are reused; anything that exists but does not match is reported and left unchanged. Participant records are never overwritten.

A node needs no publication host. Publication settings arrive with the publication milestone.

Then admit Participants (BCP-0002), from the host:

```text
sudo lxc exec portal -- civic-participant add <username> --create-account
sudo lxc exec portal -- passwd <username>
sudo lxc exec portal -- civic-participant grant <username> water-ants --reason "<evidence of voluntary participation>"
sudo lxc exec portal -- civic-transport-check --participant <username>
sudo lxc exec portal -- civic-participant list
```

## Current state

**Status:** `v0.3.0` — one-command node installer and Participant onboarding, accepted on a clean reference host. `v0.2.0` (Portal broker -> Orchestrator transport) is released.

### What works

- contract-bearing Orchestrator runtime carried unchanged from `git64bit/kane-capabilities`: envelope validation, authorization decisions, workflow state machine, audit events, receipts, replay/idempotency, resumable external workflows, side-effect certainty;
- `publication.publish`: exact-byte integrity, per-Participant publication budget, independent CID verification under the frozen single-raw-block profile (262,144-byte ceiling);
- Custom Command broker: protocol v2 over AF_UNIX, `SO_PEERCRED` Participant resolution, curated default-deny access, `water-ants` / Publish File bound to `publication.publish` as a **local stub**;
- authenticated Portal broker -> Orchestrator transport across the private bridge, proven by `civic-transport-check` (`v0.2.0`, accepted live);
- `INSTALL/install.sh` and `INSTALL/node_install.py`: one-command, idempotent node installation (`v0.3.0`);
- `civic-participant`: Participant onboarding with permanent identifiers, default-deny grants with recorded reasons, and retirement as tombstones (`v0.3.0`, BCP-0002);
- stub-first operation registry: every other Civic operation is registered and fails closed as `not-implemented` with no side effects;
- publication service: validation-only; Kubo is not enabled.

Unchanged by design, until `kane-civicmin` and this repository jointly define the real `water-ants` result and recorded-confirmation contract: broker protocol v2 and its `list`, `help`, and `water-ants` stub responses (locked by `tests/test_civicmin_contract.py`); `water-ants` remains `lifecycle: stub`; the broker service stays AF_UNIX-only.

The suite runs 227 tests; CI covers Python 3.11, 3.12, and 3.13 on Ubuntu 24.04. The installer's decisions (fresh host, re-run, mismatched bridge or container, storage fallback, credential copy) are tested with a simulated host.

Live acceptance on the reference node (Ubuntu 24.04 LTS laptop, 2 cores, 4 GB RAM, LVM root, wired; prior LXD state removed so the host matched a fresh install):

- the one-line command installed a working node unattended: 272 GiB LVM thin pool from free volume-group space, private bridge, both containers, release with hash-verified dependencies, credential generated and copied without host disk, services under full systemd hardening in unprivileged containers, verification passed;
- `civic-participant add` minted a permanent identifier; `grant` recorded grantor, time, and reason; `civic-transport-check` passed for the new Participant;
- as the Participant's own Unix account over the broker socket: `list` returned `water-ants` available; `water-ants` returned the protocol v2 stub with the correct SHA-256 and `remote_dispatch: false`;
- re-running the installer created nothing, kept and verified the credential, and left Participants and grants unchanged;
- re-running at a newer commit upgraded the node in place.

One defect was found and fixed during acceptance: grants made through `sudo lxc exec` recorded `operator:root`; the installer now records the installing Owner Operator and `civic-participant` uses it.

No production node has been installed from this repository yet.

## Scope

This repository owns:

- the Custom Command broker in the Portal container: Participant identity resolution (Unix account -> stable `participant:` identifier), default-deny command access, fixed command-to-operation binding;
- the Civic Orchestrator in its own container: workflow, authorization, budget, audit, and evidence;
- the publication service and its Kubo backend;
- node installation (LXD, both containers, Participant onboarding; enrollment in shared services next) and publication-host installation.

It does **not** own the Participant interface (Usermin, Civicmin), which `kane-civicmin` installs, or the shared default infrastructure (DNS/DANE, certificate authority, WireGuard hub, proxy).

## Boundary shared with kane-civicmin

Inside the Portal container the repositories share only:

```text
socket   /run/civic-orchestrator/custom-command.sock   (0660)
group    civic-participants
protocol Custom Command broker protocol v2
```

The container manager is LXD. This repository's installer creates the group and the socket, then runs the `kane-civicmin` installer at a pinned release tag inside the Portal container. That location and tag are the only reference this repository holds to `kane-civicmin`.

`kane-civicmin` installer contract (accepted in both repositories; `kane-civicmin` BCP-0003): the node installer clones `kane-civicmin` at a release tag into `/opt/kane-civicmin/<tag>` inside the Portal container and runs `INSTALL/install.sh` there as root, with no arguments, after the group and the broker socket exist. Proven live with `kane-civicmin` at `dbcd2d9`; `kane-civicmin v0.5.0` is the first tag the node installer will pin (`v0.4.0`).

Portal TLS contract (paths and ownership accepted; not yet implemented on either side; details pending the TLS / proxy / WireGuard design discussion before `v0.4.0`): enrollment in this repository generates the Portal key and certificate request and places the certificate in `/etc/civic-portal/tls/` (`private.key`, `request.csr`, `certificate.pem`, `chain.pem`, `fullchain.pem`), then will call `kane-civicmin`'s `INSTALL/configure-tls.sh` (root, no arguments; not yet written) to point Usermin at it.

## Authoritative records

- [RFC-0001 — Orchestrator Node Scope and Boundaries](rfcs/RFC-0001-orchestrator-node-scope-and-boundaries.md) (superseded by RFC-0002)
- [RFC-0002 — Node Topology and Installation](rfcs/RFC-0002-node-topology-and-installation.md)
- [RFC-0003 — Infrastructure, Not Service: Policy Boundary](rfcs/RFC-0003-infrastructure-not-service-policy-boundary.md)
- [BCP-0001 — Release and Repository Practice](bcps/BCP-0001-release-and-repository-practice.md)
- [BCP-0002 — Participant Onboarding](bcps/BCP-0002-participant-onboarding.md)
- [BCP-0003 — Upstream Component Versions](bcps/BCP-0003-upstream-component-versions.md)

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
v0.3.0  one-command node installer (LXD, both containers), Participant onboarding
v0.4.0  node enrollment: WireGuard, Portal certificate request and DANE TLSA, Civicmin installed by the node installer
v0.5.0  Kubo publication backend and publication-host installer
v0.6.0  per-operator publication credentials over WireGuard
v0.7.0  reference deployment validation with kane-civicmin
v0.9.0  independent Owner Operator release candidate
v1.0.0  water-ants publishes end to end on an independently installed node
```

Milestones may split or merge when implementation evidence requires it.

## Decisions pending

Recorded here until settled by an RFC. Raised to the Owner Operator only when both repositories need the decision.

- whether published content is retrievable from the IPFS network in `v1.0.0` (the frozen design keeps Kubo loopback-only with swarm disabled);
- per-operator caps enforced by a shared publication host;
- the broker's real (non-stub) `water-ants` result shape, and whether explicit Participant confirmation is carried to the Orchestrator and recorded as evidence;

## License

BSD 3-Clause License. See [LICENSE](LICENSE).
