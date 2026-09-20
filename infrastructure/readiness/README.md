# Production-like readiness environment

This environment is exclusively for synthetic Phase 10.2 validation. It binds
all host ports to loopback and keeps private keys, bootstrap credentials and
service data under ignored `infrastructure/readiness/runtime` paths or named
Docker volumes.

Run `make readiness-up` to generate a laboratory PKI and start the dependency
plane. The command never modifies `/etc/hosts`: names ending in `.localhost`
resolve to loopback in supported browsers, while containers use explicit
host-gateway mappings where necessary.

Vault runs with file storage and TLS, not development mode. Initial unseal and
root material is written with mode `0600` under the ignored runtime directory.
It is laboratory evidence only and is not a production secret-management
topology.
