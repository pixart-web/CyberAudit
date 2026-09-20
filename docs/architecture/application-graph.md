# Application Graph

The application graph uses stable typed nodes for application, API, endpoint,
repository, release, SBOM and component. Edges such as `exposes`, `built_from`,
`released_as` and `depends_on` are derived from tenant-filtered relational data.

`GET /api/v1/applications/{id}/graph` provides the initial bounded projection.
It never follows URLs. PostgreSQL remains the source of truth if a graph store is
introduced later.
