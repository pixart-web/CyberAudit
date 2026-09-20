"use client";

import { Badge, Card, EmptyState, ErrorState, LoadingState, SeverityBadge } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Indicator = {
  id: string;
  indicator_type: string;
  display_value: string;
  confidence: number;
  severity: string;
  status: string;
  valid_from: string;
  valid_until: string | null;
  labels: string[];
  references: string[];
};
type Feed = { id: string; name: string; provider: string; trust_level: string } | null;
type IndicatorDetail = { indicator: Indicator; feed: Feed };

export default function IocDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, isLoading } = useQuery({
    queryKey: ["ioc", id],
    queryFn: () => api<IndicatorDetail>(`/iocs/${id}`),
    retry: false,
  });

  if (isLoading) return <Shell title="Indicador de Compromisso"><LoadingState /></Shell>;
  if (error || !data) {
    return (
      <Shell title="Indicador de Compromisso">
        <ErrorState title="Indicador não encontrado ou sem autorização." />
      </Shell>
    );
  }

  const { indicator, feed } = data;

  return (
    <Shell title={indicator.display_value} eyebrow={`IOC · ${indicator.indicator_type}`}>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <SeverityBadge state={indicator.severity} />
        <Badge tone="neutral">{indicator.status}</Badge>
        <Badge tone="info">Confiança: {(indicator.confidence * 100).toFixed(0)}%</Badge>
      </div>
      <Card className="p-6">
        <dl className="grid gap-3 text-sm sm:grid-cols-2">
          <Row label="Válido desde" value={new Date(indicator.valid_from).toLocaleString("pt-PT")} />
          <Row
            label="Válido até"
            value={indicator.valid_until ? new Date(indicator.valid_until).toLocaleString("pt-PT") : "Sem expiração"}
          />
        </dl>
        {indicator.labels.length > 0 && (
          <div className="mt-4 flex flex-wrap gap-2">
            {indicator.labels.map((label) => (
              <Badge key={label} tone="neutral">{label}</Badge>
            ))}
          </div>
        )}
        {indicator.references.length > 0 && (
          <div className="mt-4">
            <p className="mb-1 text-xs font-semibold text-muted">Referências</p>
            <ul className="list-disc pl-4 text-sm text-muted">
              {indicator.references.map((reference, index) => (
                <li key={index} className="break-all">{reference}</li>
              ))}
            </ul>
          </div>
        )}
      </Card>
      <Card className="mt-4 p-6">
        <h2 className="mb-3 font-semibold">Feed de origem</h2>
        {feed ? (
          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <Row label="Nome" value={feed.name} />
            <Row label="Fornecedor" value={feed.provider} />
            <Row label="Nível de confiança" value={feed.trust_level} />
          </dl>
        ) : (
          <EmptyState title="Sem feed de origem registado (indicador introduzido manualmente)." />
        )}
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
