# RFC-0002 — Node Topology and Installation

Number: RFC-0002  
Title: Node Topology and Installation  
Status: Accepted  
Date: 2026-10-04  
Supersedes: RFC-0001  
Superseded-by: none  
Related: BCP-0001, kane-civicmin RFC-0001, kane-civicmin RFC-0002, git64bit/kane-capabilities

## Decision

A Civic Infrastructure node is one physical Ubuntu LTS host running LXD with two system containers:

```text
Ubuntu LTS host (the node boundary)
|
+-- Portal container
|     Webmin, Usermin, Civicmin            (kane-civicmin)
|     Custom Command broker                (kane-orchestrator)
|
+-- Orchestrator container
      Civic Orchestrator                   (kane-orchestrator)
```

The host is the node boundary. The two containers are separate security domains. Both run Ubuntu LTS.

This RFC supersedes RFC-0001. RFC-0001 placed the broker and the Orchestrator in one operating-system namespace and assigned Participant identity resolution to the Orchestrator; both are replaced below. Its remaining decisions are restated here unchanged.

## Authority

The **Custom Command broker** runs in the Portal container, beside Usermin and Civicmin, so that `SO_PEERCRED` identifies the real local Participant. It is the authority for:

- mapping a kernel-verified Unix account to a stable, never-recycled Civic Participant identifier;
- Custom Command discovery and invocation grants, default-deny;
- fixed semantic binding of each Custom Command to one Civic operation.

The **Civic Orchestrator** runs in the Orchestrator container. It is the authority for workflow, authorization, publication budget, audit, receipts, and publication evidence. It accepts a Participant identity only from an authenticated adapter, and only inside that adapter's fixed subject namespace.

A Participant interface may present and collect; it never selects an operation, route, endpoint, credential, or backend.

## Broker to Orchestrator

The broker reaches the Orchestrator over the host's private LXD bridge using the existing authenticated adapter transport:

- HTTP `POST /v1/operations` with a bearer credential held only by the broker service;
- the credential maps, in the Orchestrator, to a fixed `client.id`, `client.kind`, `authenticated_by`, `caller.authority`, and subject prefix;
- the Orchestrator binds only to its private bridge address, never to a host-external interface;
- the Orchestrator container shares no filesystem, Unix socket namespace, or credential with the Portal container.

Traffic does not leave the host, so transport encryption is not required at this boundary. Adding TLS later does not change the contract.

## Boundary with kane-civicmin

Inside the Portal container the repositories share only:

```text
socket   /run/civic-orchestrator/custom-command.sock   (0660)
group    civic-participants
protocol Custom Command broker protocol v2
```

This repository creates the group and the socket. Changes to the broker protocol or its response shape require a coordinated decision recorded in both repositories.

## Installation

Installation follows the appliance model:

1. The Owner Operator installs Ubuntu Server LTS on the host.
2. The Owner Operator runs one command from this repository. It installs and initializes LXD, creates the private bridge and both containers, installs the Orchestrator and the broker, and finally runs the `kane-civicmin` installer, pinned to a release tag, inside the Portal container. The `kane-civicmin` repository location and tag are the only reference this repository holds to it.
3. A post-install step collects what is specific to the Owner Operator: node name, first operator account, WireGuard enrollment, Portal certificate request, and publication host endpoint and credential.

Keys are generated where they are used and never leave that place. The Portal private key is generated in the Portal container; the installer prints the certificate signing request and the matching DANE TLSA record for the Owner Operator to submit. The WireGuard private key is generated on the node.

Containers are backed up by export to removable storage.

## Default infrastructure

A node consumes external Civic Infrastructure services. An Owner Operator may use a shared default provider or operate their own; the node does not change either way:

- DNS with DNSSEC and DANE;
- the Civic Infrastructure certificate authority and its county intermediates;
- a WireGuard hub for nodes without a public address;
- a reverse proxy that passes TLS through to the Portal by server name without terminating it, so the proxy never sees Participant traffic and DANE pins the Portal's own key;
- the publication host.

This repository installs nodes and publication hosts. It does not install DNS, the certificate authority, the WireGuard hub, or the proxy.

## Publication host

The publication service is reached only by Orchestrators, only across WireGuard, and never from the public internet. Each Owner Operator's Orchestrator holds its own revocable publication credential. Kubo remains loopback-only inside the publication host.

## Inherited contracts

The frozen `git64bit/kane-capabilities` contracts are the starting baseline: request/result/failure envelopes, operation registry, workflow definitions, Custom Command registry and help catalog, publication contracts, and the `civic-ipfs-kubo-v1` content-identity profile. This repository is their authority from `v0.1.0`; changes are recorded as RFCs.

## Stub-first

Every registered Civic operation exists before it is implemented. An unimplemented operation completes as `not-implemented` with full workflow evidence and no side effects. An operation becomes `available` only through an accepted milestone.

## Portability

Hostnames, addresses, account names, credentials, certificates, budget values, and service topology are installation inputs, not source-code values. Templates carry placeholders or loopback addresses only.

Ubuntu LTS is the only supported operating system, on the host and in both containers. Other platforms are left to forks.

## Consequence

A new Owner Operator can install a working node on modest hardware with one command, rely on a default provider for shared services, and replace any of those services later without reinstalling the node.
