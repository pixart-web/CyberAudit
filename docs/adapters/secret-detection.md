# Secret Detection Adapter

`cyberaudit.secret_detection` uses only an internal synthetic scenario in Phase
5, so raw candidates never enter persisted job configuration. Output contains
fingerprint, type, location, length, confidence and mask only. Future real input
must arrive as ephemeral worker bytes from private storage and be discarded
before the transaction completes.
