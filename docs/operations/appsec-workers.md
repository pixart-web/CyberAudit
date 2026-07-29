# AppSec Workers

Workers load adapters only from `AdapterRegistry`, revalidate policy and validate
stored configuration with a strict Pydantic schema. Network access is disabled by
default. Networked adapters require an explicit profile and central destination
policy. Monitor duration, queue time, parser errors, redactions and gate results.
