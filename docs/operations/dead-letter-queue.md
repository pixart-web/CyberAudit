# Universal dead-letter queue

Critical asynchronous message families use a versioned, strict envelope and an
opaque payload reference. The DLQ stores sanitized error summaries, deduplicates
on tenant, queue and idempotency key, and supports acknowledge, discard and
replay. Replay and discard require permission plus phishing-resistant step-up.

Replay revalidates tenant context, envelope schema, message version, feature
state and a closed handler registry. There is no dynamic import, command field
or user-selected callable. Every transition is auditable. Messages that cannot
be handled remain in the DLQ; they are never silently dropped.
