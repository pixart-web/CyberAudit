# Security Gates

A security gate is an organization-owned deterministic policy. Inputs are
persisted facts; outputs are `passed` or `failed` plus stable reason codes.
Missing required evidence fails closed.

Rules cover minimum AppSec score, severity ceilings, known exploited
dependencies, confirmed secret observations, artifact signatures and required
SBOM/SAST/SCA/IaC/container evidence. Evaluations expire. Exceptions use a
separate reviewed, expiring workflow.
