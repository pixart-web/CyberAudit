# AppSec Retesting

Move remediation to `ready_for_validation`, request a retest and select a safe
profile. ScopePolicyEngine runs before queueing and again in the worker. A gate
must use the new finding state rather than overwriting the earlier result.
