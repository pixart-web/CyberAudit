# Container Image Analysis

The Phase 5 container adapter reviews declared metadata only. It never pulls or
runs images, mounts the Docker socket or trusts an image entrypoint.

Future implementation must resolve an immutable digest, verify registry policy,
inspect layers without execution and operate inside a separate sandbox with
network disabled and strict decompression limits.
