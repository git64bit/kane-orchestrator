# RFC-0003 — Infrastructure, Not Service: Policy Boundary

Number: RFC-0003  
Title: Infrastructure, Not Service: Policy Boundary  
Status: Draft  
Date: 2026-10-04  
Supersedes: none  
Superseded-by: none  
Related: RFC-0002, BCP-0002, BCP-0003, kane-civicmin (matching record)

## Decision

Civic Infrastructure is infrastructure operated by independent Owner Operators, not a service operated for them.

It provides mechanisms. It does not restrict or replace upstream defaults, and it does not decide what an Owner Operator's Participants may do as users of the Owner Operator's systems. The only properties fixed by Civic Infrastructure are those that make Civic records trustworthy.

The same decision is recorded in `kane-civicmin`. The two records must not diverge.

## Owner Operator policy

The following are Owner Operator policy. Neither repository restricts them, and installation leaves them at their upstream defaults:

- login shells, Terminal, File Manager, and other Usermin or Webmin modules available to Participants;
- mail, including whether mail exists at all;
- quotas, storage limits, and resource limits;
- SSH and other ingress;
- firewall rules, allow-lists, and network exposure beyond the installer's defaults below;
- which upstream facilities are enabled, disabled, or hardened.

Operating guidance for narrowing these ("throttled installation") may be published after `v1.0.0` as optional Owner Operator choices. It is not a default and not a requirement.

## Civic authority integrity

The following are fixed. They do not limit what a Participant can do as a user; they define what a Civic record means:

- **Identity** is derived from the kernel (`SO_PEERCRED`) and mapped to a permanent, never-reused Participant identifier; it is never accepted from a Participant's input.
- **Civic Custom Commands** are default-deny and granted per Participant with a recorded grantor, time, and reason (BCP-0002).
- **Credentials** between Civic components are generated where used, held by root only, and never exposed to Participants.
- **The Orchestrator** accepts operations only from an authenticated adapter, within that adapter's fixed identity namespace, and listens only where the installer places it.
- **Evidence** — workflow state, authorization decisions, audit events, receipts, and publication records — is recorded by the Orchestrator and independently verifiable.

A Participant with full shell access still cannot assert another Participant's identity, read a Civic credential, or alter Orchestrator evidence.

## Installer defaults

Installer defaults are mechanisms with conservative starting values, not policy:

- the node installer publishes the Portal's Usermin only; it does not publish Webmin or any other administrative interface;
- the Orchestrator is reachable only from the Portal container across the private bridge;
- nothing else is opened.

An Owner Operator may change any of these afterwards. Doing so is their policy decision and does not alter Civic authority integrity.

## Consequences

Participant processes may share the Portal container with the Custom Command broker. A privilege escalation inside the Portal could reach the broker's files. This risk is accepted for infrastructure. The separate Orchestrator container (RFC-0002) keeps the Orchestrator, its credentials, and its evidence outside the Portal's reach.

Security hardening proposed for either repository must state whether it protects Civic authority integrity (in scope) or restricts Owner Operator policy (out of scope for defaults; eligible for optional guidance).
