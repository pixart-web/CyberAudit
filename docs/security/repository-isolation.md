# Repository Isolation

Repositories cannot provide executable plugins, commands, environment variables
or filesystem locations. Phase 5 performs offline analysis of explicitly uploaded
bounded documents only.

A future repository worker must use an ephemeral directory, read-only checkout,
no hooks, no package scripts, no Docker socket, restricted egress, CPU/memory/
process limits and guaranteed cleanup.
