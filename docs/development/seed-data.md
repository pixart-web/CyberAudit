# Synthetic seed data

Run base seeds in order, ending with:

```bash
make seed-enterprise
make enterprise-domain-seed
```

The expansion creates eleven read-only connectors and synthetic identity,
SaaS, cloud, Kubernetes, endpoint, mobile, Zero Trust and Knowledge Graph
records. Every business object is marked `demo_data=true` directly or in its
metadata. No real person, customer domain, password or provider token is used.
