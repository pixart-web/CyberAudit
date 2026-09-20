"use client";

import { Badge, Button, Card, ConfirmationDialog, EmptyState, ErrorState, LoadingState, SeverityBadge, Tabs, TabPanel } from "@cyberaudit/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Incident = {
  id: string;
  reference: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  category: string;
  business_impact: string;
  risk_score: number;
  detected_at: string;
};
type TimelineEntry = { id: string; entry_type: string; title: string; description: string | null; occurred_at: string };
type IncidentDetail = { incident: Incident; timeline: TimelineEntry[] };
type CaseRecord = { id: string; reference: string; title: string; status: string };
type Alert = { id: string; title: string; severity: string; status: string };

const TABS = [
  { id: "overview", label: "Visão Geral" },
  { id: "timeline", label: "Cronologia" },
  { id: "cases", label: "Casos" },
  { id: "alerts", label: "Deteções" },
];

const TRANSITIONS: Record<string, string[]> = {
  open: ["triaged", "cancelled"],
  triaged: ["investigating", "contained", "cancelled"],
  investigating: ["contained", "resolved", "cancelled"],
  contained: ["investigating", "resolved"],
  resolved: ["closed", "investigating"],
  closed: [],
  cancelled: [],
};

export function IncidentWorkspace({ id }: { id: string }) {
  const [tab, setTab] = useState("overview");
  const [pendingCancel, setPendingCancel] = useState(false);
  const queryClient = useQueryClient();

  const detail = useQuery({
    queryKey: ["incident", id],
    queryFn: () => api<IncidentDetail>(`/incidents/${id}`),
    retry: false,
  });
  const cases = useQuery({
    queryKey: ["incident-cases", id],
    queryFn: () => api<{ items: CaseRecord[] }>(`/cases?incident_id=${id}`),
    enabled: tab === "cases",
  });
  const alerts = useQuery({
    queryKey: ["incident-alerts", id],
    queryFn: () => api<{ items: Alert[] }>(`/detections/alerts?incident_id=${id}`),
    enabled: tab === "alerts",
  });

  const transition = useMutation({
    mutationFn: (status: string) =>
      api(`/incidents/${id}/transition`, { method: "POST", body: JSON.stringify({ status }) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["incident", id] }),
  });

  if (detail.isLoading) return <Shell title="Incidente"><LoadingState /></Shell>;
  if (detail.error || !detail.data) {
    return (
      <Shell title="Incidente">
        <ErrorState title="Incidente não encontrado ou sem autorização." />
      </Shell>
    );
  }

  const { incident, timeline } = detail.data;
  const nextStates = TRANSITIONS[incident.status] ?? [];

  return (
    <Shell title={incident.title} eyebrow={`Incidente ${incident.reference}`}>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <SeverityBadge state={incident.severity} />
        <Badge tone="neutral">{incident.status}</Badge>
        <Badge tone="info">Risco: {incident.risk_score.toFixed(1)}</Badge>
        <div className="ml-auto flex gap-2">
          {nextStates.map((status) => (
            <Button
              key={status}
              className="text-xs"
              onClick={() => (status === "cancelled" ? setPendingCancel(true) : transition.mutate(status))}
              disabled={transition.isPending}
            >
              → {status}
            </Button>
          ))}
        </div>
      </div>
      <ConfirmationDialog
        open={pendingCancel}
        title="Cancelar este incidente?"
        description="O incidente passa a estado 'cancelled', que é terminal e não pode ser revertido."
        confirmLabel="Cancelar incidente"
        destructive
        onConfirm={() => {
          transition.mutate("cancelled");
          setPendingCancel(false);
        }}
        onCancel={() => setPendingCancel(false)}
      />
      <Card className="overflow-hidden">
        <Tabs items={TABS} active={tab} onChange={setTab} />
        <div className="p-5">
          <TabPanel id="overview" active={tab}>
            <dl className="space-y-3 text-sm">
              <Row label="Descrição" value={incident.description || "—"} />
              <Row label="Categoria" value={incident.category} />
              <Row label="Impacto de negócio" value={incident.business_impact || "—"} />
              <Row label="Detetado em" value={new Date(incident.detected_at).toLocaleString("pt-PT")} />
            </dl>
          </TabPanel>

          <TabPanel id="timeline" active={tab}>
            {timeline.length === 0 && <EmptyState title="Sem eventos registados." />}
            <ol className="space-y-3 border-l border-border pl-4">
              {timeline.map((row) => (
                <li key={row.id} className="relative text-sm">
                  <span className="absolute -left-[21px] top-1 h-2 w-2 rounded-full bg-primary" />
                  <p className="font-medium">{row.title}</p>
                  {row.description && <p className="text-xs text-muted">{row.description}</p>}
                  <p className="text-xs text-muted">{new Date(row.occurred_at).toLocaleString("pt-PT")}</p>
                </li>
              ))}
            </ol>
          </TabPanel>

          <TabPanel id="cases" active={tab}>
            {cases.isLoading && <LoadingState />}
            {cases.data?.items.length === 0 && <EmptyState title="Sem casos associados a este incidente." />}
            <ul className="space-y-2">
              {cases.data?.items.map((row) => (
                <li key={row.id} className="flex items-center justify-between rounded-lg border border-border p-3 text-sm">
                  <span>{row.reference} · {row.title}</span>
                  <Badge tone="neutral">{row.status}</Badge>
                </li>
              ))}
            </ul>
          </TabPanel>

          <TabPanel id="alerts" active={tab}>
            {alerts.isLoading && <LoadingState />}
            {alerts.data?.items.length === 0 && <EmptyState title="Sem deteções associadas a este incidente." />}
            <ul className="space-y-2">
              {alerts.data?.items.map((row) => (
                <li key={row.id} className="flex items-center justify-between rounded-lg border border-border p-3 text-sm">
                  <span>{row.title}</span>
                  <SeverityBadge state={row.severity} />
                </li>
              ))}
            </ul>
          </TabPanel>
        </div>
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
