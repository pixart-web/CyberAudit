# API Specification Import

`cyberaudit.api_specification_import` parses a bounded JSON document offline.
OpenAPI 2/3/3.1 paths are normalized. Remote/file references are blocked.
Production imports should use the private upload, preview and confirm API rather
than embedding a document in job configuration.
