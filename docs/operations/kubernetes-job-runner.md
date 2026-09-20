# Kubernetes Job runner

The Kubernetes runner uses the same closed, digest-pinned operation registry as
the Docker runner. A dedicated controller translates it into a one-shot Job
using a dedicated ServiceAccount, restricted security context, read-only root
filesystem, seccomp runtime default, dropped capabilities, resource limits,
NetworkPolicy and TTL cleanup. Privileged pods, host namespaces, host paths and
service-account token automount are forbidden.

The application has no Kubernetes API credential and cannot submit arbitrary
Pod specs. A real cluster execution, policy rejection and cleanup exercise is
required before the gate can pass.
