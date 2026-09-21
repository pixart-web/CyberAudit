"use client";

import { Badge, Card, EmptyState, ErrorState, LoadingState, SeverityBadge } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type SecurityEvent = {
  id: string;
  source: string;
  event_type: string;
  severity: string;
  occurred_at: string;
  actor_ref: string | null;
  asset_id: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  summary: string;
  normalized: Record<string, unknown>;
  labels: string[];
  content_hash: string;
  trusted: boolean;
};
type Alert = { id: string; title: string; severity: string; status: string };
type EventDetail = { event: SecurityEvent; alerts: Alert[] };

export default function SecurityEventDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, isLoading } = useQuery({
    queryKey: ["security-event", id],
    queryFn: () => api<EventDetail>(`/security-events/${id}`),
    retry: false,
  });

  if (isLoading) return <Shell title="Evento de Segurança"><LoadingState /></Shell>;
  if (error || !data) {
    return (
      <Shell title="Evento de Segurança">
        <ErrorState title="Evento não encontrado ou sem autorização." />
      </Shell>
    );
  }

  const { event, alerts } = data;

  return (
    <Shell title={event.summary} eyebrow={`Evento · ${event.event_type}`}>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <SeverityBadge state={event.severity} />
        <Badge tone={event.trusted ? "success" : "neutral"}>{event.trusted ? "Confiável" : "Não confirmado"}</Badge>
        {event.asset_id && (
          <Link href={`/assets/${event.asset_id}`} className="text-sm text-cyan hover:underline">
            Ver ativo relacionado
          </Link>
        )}
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="p-6 lg:col-span-2">
          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <Row label="Origem" value={event.source} />
            <Row label="Ator" value={event.actor_ref ?? "—"} />
            <Row label="IP origem" value={event.source_ip ?? "—"} />
            <Row label="IP destino" value={event.destination_ip ?? "—"} />
            <Row label="Ocorrido em" value={new Date(event.occurred_at).toLocaleString("pt-PT")} />
            <Row label="Hash de conteúdo" value={event.content_hash} />
          </dl>
          {event.labels.length > 0 && (
            <div className="mt-4 flex flex-wrap gap-2">
              {event.labels.map((label) => (
                <Badge key={label} tone="neutral">{label}</Badge>
              ))}
            </div>
          )}
          <p className="mb-2 mt-6 text-xs font-semibold text-muted">Payload normalizado</p>
          <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-lg border border-border bg-background p-4 text-xs text-muted">
            {JSON.stringify(event.normalized, null, 2)}
          </pre>
          <p className="mt-2 text-xs text-muted">
            Apresentado como texto inerte. HTML, JavaScript e SVG nunca são renderizados.
          </p>
        </Card>
        <Card className="p-5">
          <h2 className="mb-3 font-semibold">Deteções associadas</h2>
          {alerts.length === 0 && <EmptyState title="Sem deteções associadas a este evento." />}
          <ul className="space-y-2">
            {alerts.map((alert) => (
              <li key={alert.id}>
                <Link
                  href={`/detections/${alert.id}`}
                  className="flex items-center justify-between rounded-lg border border-border p-3 text-sm hover:border-primary/40"
                >
                  <span>{alert.title}</span>
                  <SeverityBadge state={alert.severity} />
                </Link>
              </li>
            ))}
          </ul>
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
