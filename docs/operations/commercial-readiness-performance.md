# Performance measurements (2026-10-08)

Environment: MacBook (local), PostgreSQL 16 in Docker, **one** uvicorn process, Redis local. Tenant "Northstar demo" plus bulk synthetic rows:
**30 008 assets, 60 009 findings**. Authenticated, warm cache, 5 runs each (median / max, response size).

| Endpoint | p50 | max | Payload |
|---|---|---|---|
| `GET /command-center` | 31 ms | 36 ms | 0.8 KB |
| `GET /dashboard` | 93 ms | 96 ms | 1.5 KB |
| `GET /assets?page_size=20` | 22 ms | 79 ms | 7.9 KB |
| `GET /assets?q=load-asset-0042` | 39 ms | 50 ms | 4.0 KB |
| `GET /findings?page_size=20` | 27 ms | 29 ms | 24.5 KB |
| `GET /findings?q=MFA` | 67 ms | 73 ms | 24.5 KB |
| `GET /findings?q=Load finding 05` | 77 ms | 78 ms | 24.5 KB |
| `GET /incidents?q=` / `/engagements?q=` (global search sources) | 6–7 ms | 11 ms | <1 KB |
| `GET /asset-graph`, `/knowledge-graph` | 6 ms | 8 ms | 2–3 KB (bounded) |

Concurrency (mixed command-center, dashboard, findings list/search, assets search; single process):

| Users | Requests | Errors | p50 | p95 | Throughput |
|---|---|---|---|---|---|
| 10 | 80 | 0 | 113 ms | 249 ms | 74 req/s |
| 25 | 200 | 0 | 261 ms | 532 ms | 84 req/s |

## Findings
- Aggregations are SQL-side (earlier fix to `/command-center`); no endpoint loaded whole tables.
- Throughput saturates at ~80 req/s with one process (CPU-bound Python) → the evaluation compose now runs `uvicorn --workers 2`.
- Text search uses `ILIKE '%q%'` (sequential scan): 60 k rows ≈ 70 ms. Expect linear growth; a `pg_trgm` GIN index is the planned fix if a tenant exceeds ~500 k findings (needs the extension and a reviewed migration; not applied blindly).
- Not measured: report generation under load, SOC event ingestion volume (no bulk ingestion path exercised), browser rendering of very large graphs, multi-tenant contention.
