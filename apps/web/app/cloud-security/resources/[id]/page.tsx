"use client";

import { Badge, Card, ErrorState, LoadingState, SeverityBadge } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type CloudResource = {
  id: string;
  provider: string;
  resource_type: string;
  name: string;
  region: string | null;
  environment: string;
  criticality: string;
  public_exposure: boolean;
  managed: boolean;
  owner: string | null;
  status: string;
  risk_score: number;
  configuration_hash: string;
};
type CloudAccount = { id: string; name: string; provider: string } | null;
type ResourceDetail = { resource: CloudResource; account: CloudAccount };

export default function CloudResourceDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, isLoading } = useQuery({
    queryKey: ["cloud-resource", id],
    queryFn: () => api<ResourceDetail>(`/cloud/resources/${id}`),
    retry: false,
  });

  if (isLoading) return <Shell title="Recurso Cloud"><LoadingState /></Shell>;
  if (error || !data) {
    return (
      <Shell title="Recurso Cloud">
        <ErrorState title="Recurso não encontrado ou sem autorização." />
      </Shell>
    );
  }

  const { resource, account } = data;

  return (
    <Shell title={resource.name} eyebrow={`Cloud · ${resource.provider} · ${resource.resource_type}`}>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <Badge tone="neutral">{resource.status}</Badge>
        <SeverityBadge state={resource.criticality} />
        {resource.public_exposure && <Badge tone="danger">Exposição pública</Badge>}
        <Badge tone="info">Risco: {resource.risk_score.toFixed(0)}</Badge>
        {account && (
          <Link href={`/cloud-security/accounts/${account.id}`} className="ml-auto text-sm text-cyan hover:underline">
            Ver conta {account.name}
          </Link>
        )}
      </div>
      <Card className="p-6">
        <dl className="grid gap-3 text-sm sm:grid-cols-2">
          <Row label="Região" value={resource.region ?? "—"} />
          <Row label="Ambiente" value={resource.environment} />
          <Row label="Responsável" value={resource.owner ?? "Sem responsável"} />
          <Row label="Gerido" value={resource.managed ? "Sim" : "Não"} />
          <Row label="Hash de configuração" value={resource.configuration_hash} />
        </dl>
      </Card>
    </Shell>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs font-semibold text-muted">{label}</dt>
      <dd className="mt-1 break-all">{value}</dd>
    </div>
  );
}
