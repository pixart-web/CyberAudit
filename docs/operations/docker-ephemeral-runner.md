# Docker ephemeral runner

CyberAudit sends a closed execution declaration to a separately privileged HTTPS
controller. Each operation maps to a fixed image digest. Requests cannot include
commands, arguments, environment variables, mounts or images.

The required container profile is non-root, read-only, no new privileges, all
capabilities dropped, bounded PIDs/CPU/memory/output/time, no Docker socket, no
host mounts, no metadata service and no network by default. The controller must
create one container per execution and prove cleanup on success, failure,
timeout and cancellation.

No Docker controller is present in the local environment, so this readiness
check is blocked despite unit validation of the immutable spec.
