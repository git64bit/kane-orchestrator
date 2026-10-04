# RFC-0001 — Orchestrator Node Scope and Boundaries

Number: RFC-0001  
Title: Orchestrator Node Scope and Boundaries  
Status: Accepted  
Date: 2026-10-04  
Supersedes: none  
Superseded-by: none  
Related: BCP-0001, kane-civicmin RFC-0001, git64bit/kane-capabilities

## Decision

`kane-orchestrator` is the Civic authority plane of one portable Civic Infrastructure node.

One Ubuntu LTS host runs one node: the trusted local broker and the Civic Orchestrator. Participant interfaces, beginning with Usermin/Civicmin, run on the same host and reach Civic authority only through the local broker.

Bounded services consumed by the Orchestrator, beginning with the publication service, may run on other hosts. They are reached only by the Orchestrator, with service credentials unavailable to Participants.

## Authority

On the node, this repository is the authority for:

- mapping a kernel-verified Unix account to a stable, never-recycled Civic Participant identifier;
- Custom Command discovery and invocation grants, default-deny;
- fixed semantic binding of each Custom Command to one Civic operation;
- Orchestrator workflow, authorization, budget, audit, receipts, and publication evidence.

A Participant interface may present and collect; it never selects an operation, route, endpoint, credential, or backend.

Services consumed by the Orchestrator are not Civic authorities. They perform their bounded function and return evidence that the Orchestrator verifies independently.

## Boundary with kane-civicmin

The repositories share only what installation requires:

```text
socket   /run/civic-orchestrator/custom-command.sock
group    civic-participants
protocol Custom Command broker protocol v2
```

This repository creates the group and the socket. Changes to the broker protocol or its response shape require a coordinated decision recorded in both repositories.

## Inherited contracts

The frozen `git64bit/kane-capabilities` contracts are carried forward unchanged as the starting baseline: request/result/failure envelopes, operation registry, workflow definitions, Custom Command registry and help catalog, publication contracts, and the `civic-ipfs-kubo-v1` content-identity profile.

From `v0.1.0` onward this repository is the authority for those contracts. Changes follow BCP-0001 and are recorded here as new RFCs.

## Stub-first

Every registered Civic operation exists before it is implemented. An unimplemented operation completes as `not-implemented` with full workflow evidence and no side effects. An operation becomes `available` only through an accepted milestone.

## Portability

Hostnames, addresses, account names, credentials, budget values, and service topology are installation inputs, not source-code values. Installation templates carry placeholders or loopback addresses only.

Ubuntu LTS is the only supported operating system. Other platforms are left to forks.

## Consequence

A new Owner Operator can install a node without any Kane infrastructure. The Kane deployment is the first reference and acceptance environment only.
