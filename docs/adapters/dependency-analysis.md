# Dependency Analysis

`cyberaudit.dependency_analysis` parses exact pinned Python requirements and npm
lockfiles. Unlocked requirements and unsupported executable manifests are
rejected. No package manager, lifecycle script or network registry is invoked.
