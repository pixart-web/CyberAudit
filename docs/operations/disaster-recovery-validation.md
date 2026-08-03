# Disaster-recovery validation

The minimum exercise assumes loss of the primary application and database
location. Operators declare the incident, freeze promotions, verify the latest
encrypted backup and signatures, restore into the recovery location, apply
configuration from version control, rotate credentials, validate RLS and tenant
isolation, then switch traffic.

Record achieved RTO/RPO, data-loss window, integrity checks, approvals and
rollback decision. Do not mark DR passed from a tabletop review alone; an
isolated restoration and application smoke test are mandatory.

The local encrypted backup/isolated restore observed RPO 0 seconds and RTO 1
second for the synthetic dataset, with matching database counts and MinIO
checksums. It ran on the primary Docker host, so `make readiness-dr-test`
correctly records `blocked`. A second cluster/server, endpoint cutover and
controlled failback remain mandatory.
