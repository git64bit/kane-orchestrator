# BCP-0003 — Upstream Component Versions

Number: BCP-0003  
Title: Upstream Component Versions  
Status: Accepted  
Date: 2026-10-04  
Supersedes: none  
Superseded-by: none  
Related: BCP-0001, kane-civicmin BCP-0003

## Practice

Only Civic releases are pinned: a node installs one `kane-orchestrator` release and one `kane-civicmin` release, each by tag.

Upstream components are installed from their current stable channels and are not pinned by this repository:

- Ubuntu packages, from the Ubuntu LTS archive;
- LXD, from the snap's current stable channel;
- Webmin and Usermin, from the upstream stable repository (installed by `kane-civicmin`);
- Python dependencies, at their current releases within the ranges in `requirements.txt`.

## Reason

During development, tracking current upstream releases surfaces incompatibilities early, while they are cheap to fix. Pinning adds maintenance work without helping to discover those problems.

## Revisiting

Any component may be pinned later, by a new BCP that supersedes this one, when a concrete defect, a security requirement, or reproducibility for a release candidate requires it. Compatibility floors that protect a known contract, such as a minimum Usermin version, are not pins and remain allowed.
