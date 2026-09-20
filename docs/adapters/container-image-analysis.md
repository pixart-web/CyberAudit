# Container Image Analysis Adapter

`cyberaudit.container_image_analysis` handles metadata only. It does not pull,
mount or execute images and has no Docker socket access. Digest-pinned, offline
layer inspection is reserved for a future isolated runner.
