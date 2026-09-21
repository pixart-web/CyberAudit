"use client";

import { Badge, Card, ErrorState, LoadingState, SeverityBadge } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Alert = {
  id: string;
  title: string;
  severity: string;
  status: string;
  confidence: number;
  fingerprint: string;
  incident_id: string | null;
  event_id: string;
  reasons: string[];
  mitre_techniques: string[];
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
};
type Rule = { id: string; name: string; description: string; severity: string } | null;
type Event = { id: string; summary: string; source: string } | null;
type AlertDetail = { alert: Alert; rule: Rule; event: Event };

export default function DetectionAlertDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, isLoading } = useQuery({
    queryKey: ["detection-alert", id],
    queryFn: () => api<AlertDetail>(`/detections/alerts/${id}`),
    retry: false,
  });

  if (isLoading) return <Shell title="Deteção"><LoadingState /></Shell>;
  if (error || !data) {
    return (
      <Shell title="Deteção">
        <ErrorState title="Deteção não encontrada ou sem autorização." />
      </Shell>
    );
  }

  const { alert, rule, event } = data;

  return (
    <Shell title={alert.title} eyebrow="Deteção">
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <SeverityBadge state={alert.severity} />
        <Badge tone="neutral">{alert.status}</Badge>
        <Badge tone="info">Confiança: {(alert.confidence * 100).toFixed(0)}%</Badge>
        {alert.incident_id && (
          <Link href={`/incidents/${alert.incident_id}`} className="ml-auto text-sm text-cyan hover:underline">
            Ver incidente associado
          </Link>
        )}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-6">
          <h2 className="mb-3 font-semibold">Regra de deteção</h2>
          {rule ? (
            <dl className="space-y-3 text-sm">
              <Row label="Nome" value={rule.name} />
              <Row label="Descrição" value={rule.description || "—"} />
              <Row label="Severidade base" value={rule.severity} />
            </dl>
          ) : (
            <p className="text-sm text-muted">Regra de origem não disponível.</p>
          )}
          {alert.reasons.length > 0 && (
            <div className="mt-4">
              <p className="text-xs font-semibold text-muted">Razões</p>
              <ul className="mt-1 list-disc pl-4 text-sm">
                {alert.reasons.map((reason, index) => (
                  <li key={index}>{reason}</li>
                ))}
              </ul>
            </div>
          )}
          {alert.mitre_techniques.length > 0 && (
            <div className="mt-4 flex flex-wrap gap-2">
              {alert.mitre_techniques.map((technique) => (
                <Badge key={technique} tone="neutral">{technique}</Badge>
              ))}
            </div>
          )}
        </Card>
        <Card className="p-6">
          <h2 className="mb-3 font-semibold">Evento de origem</h2>
          {event ? (
            <>
              <p className="text-sm">{event.summary}</p>
              <p className="mt-1 text-xs text-muted">Origem: {event.source}</p>
              <Link href={`/security-events/${event.id}`} className="mt-3 inline-block text-sm text-cyan hover:underline">
                Ver evento completo
              </Link>
            </>
          ) : (
            <p className="text-sm text-muted">Evento de origem não disponível.</p>
          )}
          <dl className="mt-6 space-y-3 text-sm">
            <Row label="Ocorrências" value={String(alert.occurrence_count)} />
            <Row label="Primeira observação" value={new Date(alert.first_seen_at).toLocaleString("pt-PT")} />
            <Row label="Última observação" value={new Date(alert.last_seen_at).toLocaleString("pt-PT")} />
            <Row label="Fingerprint" value={alert.fingerprint} />
          </dl>
        </Card>
      </div>
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
