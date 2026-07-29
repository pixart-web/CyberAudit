# On-premises deployment

The production Compose overlay and Helm chart expect externally managed PostgreSQL, Redis, object
storage, secrets and TLS. They do not install weak single-node databases as production defaults.

Before go-live, provide digest-pinned API/web images, OIDC, secure cookie/HTTPS settings, secret
files or workload identity, external storage, an ephemeral runner controller, encrypted backups,
monitoring/exporters and tested DNS/certificates. Run:

```bash
make verify-production-config
alembic -c apps/api/alembic.ini upgrade head
```

For Kubernetes, populate `existingSecret`, image digests and ingress TLS values. Review the network
policy for the cluster CNI and restrict database/Redis/object-store CIDRs further. The included chart
is a secure reference baseline, not a substitute for provider-specific architecture review.
