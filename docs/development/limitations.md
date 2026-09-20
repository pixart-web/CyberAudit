# Current limitations

- Enterprise provider SDK collection is not enabled; adapters accept controlled
  synthetic/import metadata only.
- There is no external remediation, user disable, session revoke, policy
  application or cloud mutation.
- Graph projections are represented by bounded APIs; large-scale partitioning
  and dedicated graph storage remain future work.
- Connector secret resolution and rotation require a production secret manager.
- Digital Twin rendering is deliberately limited to 200 nodes per view.
- Zero Trust is an evidence-based posture score, not an access authorization
  decision engine.
