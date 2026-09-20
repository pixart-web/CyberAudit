# Phase 5 Worker Isolation

All AppSec adapters remain allowlisted and reachable only through the
JobOrchestrator. Networked work uses `SecureHttpClient`; offline parsers receive
bounded content and cannot spawn subprocesses.

The generic sandbox contract retains read-only filesystem, ephemeral temporary
storage, CPU/memory/process limits, network mode, allowed destinations, timeout
and environment allowlist. No user-supplied container command exists.
