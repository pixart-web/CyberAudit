# Disaster-recovery validation

The minimum exercise assumes loss of the primary application and database
location. Operators declare the incident, freeze promotions, verify the latest
encrypted backup and signatures, restore into the recovery location, apply
configuration from version control, rotate credentials, validate RLS and tenant
isolation, then switch traffic.

Record achieved RTO/RPO, data-loss window, integrity checks, approvals and
rollback decision. Do not mark DR passed from a tabletop review alone; an
isolated restoration and application smoke test are mandatory.
