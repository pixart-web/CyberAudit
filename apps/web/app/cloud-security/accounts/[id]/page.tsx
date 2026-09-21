"use client";

import { Badge, Card, EmptyState, ErrorState, LoadingState, SeverityBadge } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type CloudAccount = {
  id: string;
  provider: string;
  account_type: string;
  external_id: string;
  name: string;
  environment: string;
  owner: string | null;
  criticality: string;
  status: string;
  risk_score: number;
};
type CloudResource = { id: string; name: string; resource_type: string; public_exposure: boolean; risk_score: number };
type AccountDetail = { account: CloudAccount; resources: CloudResource[] };

export default function CloudAccountDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, isLoading } = useQuery({
    queryKey: ["cloud-account", id],
    queryFn: () => api<AccountDetail>(`/cloud/accounts/${id}`),
    retry: false,
  });

  if (isLoading) return <Shell title="Conta Cloud"><LoadingState /></Shell>;
  if (error || !data) {
    return (
      <Shell title="Conta Cloud">
        <ErrorState title="Conta não encontrada ou sem autorização." />
      </Shell>
    );
  }

  const { account, resources } = data;

  return (
    <Shell title={account.name} eyebrow={`Cloud · ${account.provider}`}>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <Badge tone="neutral">{account.status}</Badge>
        <SeverityBadge state={account.criticality} />
        <Badge tone="info">Risco: {account.risk_score.toFixed(0)}</Badge>
      </div>
      <Card className="p-6">
        <dl className="grid gap-3 text-sm sm:grid-cols-2">
          <Row label="Tipo de conta" value={account.account_type} />
          <Row label="Identificador externo" value={account.external_id} />
          <Row label="Ambiente" value={account.environment} />
          <Row label="Responsável" value={account.owner ?? "Sem responsável"} />
        </dl>
      </Card>
      <Card className="mt-4 p-6">
        <h2 className="mb-3 font-semibold">Recursos desta conta</h2>
        {resources.length === 0 && <EmptyState title="Sem recursos observados nesta conta." />}
        <ul className="space-y-2">
          {resources.map((resource) => (
            <li key={resource.id}>
              <Link
                href={`/cloud-security/resources/${resource.id}`}
                className="flex items-center justify-between rounded-lg border border-border p-3 text-sm hover:border-primary/40"
              >
                <span>{resource.name} · {resource.resource_type}</span>
                <div className="flex items-center gap-2">
                  {resource.public_exposure && <Badge tone="warning">Público</Badge>}
                  <Badge tone="info">Risco: {resource.risk_score.toFixed(0)}</Badge>
                </div>
              </Link>
            </li>
          ))}
        </ul>
      </Card>
    </Shell>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs font-semibold text-muted">{label}</dt>
      <dd className="mt-1">{value}</dd>
    </div>
  );
}
