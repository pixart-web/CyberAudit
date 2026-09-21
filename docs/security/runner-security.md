# Runner security

The runner API accepts a schema-bound operation, payload size and timeout. It does not accept a
shell command, executable, user-selected path, arbitrary environment variable, container image or
host mount.

The development runner implements only deterministic internal operations and never starts a
subprocess. Docker and Kubernetes descriptors fail with `RUNNER_CONTROLLER_NOT_CONFIGURED` until an
external controller proves these controls:

- non-root identity, read-only root filesystem and temporary per-run storage;
- all Linux capabilities dropped, `no_new_privileges`, seccomp and bounded PIDs/CPU/memory;
- no Docker socket, privileged mode, host network or host filesystem;
- default-deny egress with an exact connector destination allowlist;
- metadata service blocked, timeout enforced and cleanup independently reconciled;
- structured, redacted output with a maximum size and stable content hash.

Workers must re-run tenant, scope, authorization and approval checks immediately before delegation.
Cancellation is cooperative first and enforced by deleting the isolated workload after its grace
period. The local runner is never accepted by production configuration.
