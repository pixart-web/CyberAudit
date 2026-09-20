"use client";

import { Badge, Card, EmptyState, LoadingState, ErrorState, SeverityBadge, Tabs, TabPanel } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Control = {
  id: string;
  code: string;
  title: string;
  description: string;
  domain: string;
  objective: string;
  status: string;
  maturity_level: number;
  implementation_status: string;
  next_review_at: string | null;
};
type Mapping = { id: string; framework_id: string; external_control_id: string; external_title: string };
type Assessment = { id: string; status: string; result: string; effectiveness: number; tested_at: string | null };
type EvidenceLink = { id: string; evidence_id: string; purpose: string; verified_at: string | null };

const TABS = [
  { id: "overview", label: "Visão Geral" },
  { id: "mappings", label: "Frameworks" },
  { id: "assessments", label: "Avaliações" },
  { id: "evidence", label: "Evidência" },
];

export function ControlWorkspace({ id }: { id: string }) {
  const [tab, setTab] = useState("overview");

  const control = useQuery({
    queryKey: ["control", id],
    queryFn: () => api<Control>(`/grc/controls/${id}`),
    retry: false,
  });
  const mappings = useQuery({
    queryKey: ["control-mappings", id],
    queryFn: () => api<{ items: Mapping[] }>(`/grc/control-mappings?control_id=${id}`),
    enabled: tab === "mappings",
  });
  const assessments = useQuery({
    queryKey: ["control-assessments", id],
    queryFn: () => api<{ items: Assessment[] }>(`/grc/control-assessments?control_id=${id}`),
    enabled: tab === "assessments",
  });
  const evidence = useQuery({
    queryKey: ["control-evidence", id],
    queryFn: () =>
      api<{ items: EvidenceLink[] }>(`/grc/evidence-links?subject_type=control&subject_id=${id}`),
    enabled: tab === "evidence",
  });

  if (control.isLoading) return <Shell title="Controlo"><LoadingState /></Shell>;
  if (control.error || !control.data) {
    return (
      <Shell title="Controlo">
        <ErrorState title="Controlo não encontrado ou sem autorização." />
      </Shell>
    );
  }

  const item = control.data;

  return (
    <Shell title={`${item.code} · ${item.title}`} eyebrow={`Controlo · ${item.domain}`}>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <Badge tone="neutral">{item.status}</Badge>
        <SeverityBadge state={item.implementation_status === "implemented" ? "healthy" : "warning"} />
        <Badge tone="info">Maturidade: {item.maturity_level}</Badge>
      </div>
      <Card className="overflow-hidden">
        <Tabs items={TABS} active={tab} onChange={setTab} />
        <div className="p-5">
          <TabPanel id="overview" active={tab}>
            <dl className="space-y-3 text-sm">
              <Row label="Descrição" value={item.description} />
              <Row label="Objetivo" value={item.objective || "—"} />
              <Row
                label="Próxima revisão"
                value={item.next_review_at ? new Date(item.next_review_at).toLocaleDateString("pt-PT") : "—"}
              />
            </dl>
          </TabPanel>

          <TabPanel id="mappings" active={tab}>
            {mappings.isLoading && <LoadingState />}
            {mappings.data?.items.length === 0 && <EmptyState title="Sem mapeamentos de framework." />}
            <ul className="space-y-2">
              {mappings.data?.items.map((row) => (
                <li key={row.id} className="rounded-lg border border-border p-3 text-sm">
                  {row.external_control_id} · {row.external_title}
                </li>
              ))}
            </ul>
          </TabPanel>

          <TabPanel id="assessments" active={tab}>
            {assessments.isLoading && <LoadingState />}
            {assessments.data?.items.length === 0 && <EmptyState title="Ainda não existem avaliações." />}
            <ul className="space-y-2">
              {assessments.data?.items.map((row) => (
                <li key={row.id} className="flex items-center justify-between rounded-lg border border-border p-3 text-sm">
                  <SeverityBadge state={row.result === "effective" ? "healthy" : "warning"} />
                  <span className="text-xs text-muted">
                    Efetividade: {(row.effectiveness * 100).toFixed(0)}%
                  </span>
                </li>
              ))}
            </ul>
          </TabPanel>

          <TabPanel id="evidence" active={tab}>
            {evidence.isLoading && <LoadingState />}
            {evidence.data?.items.length === 0 && <EmptyState title="Sem evidência ligada a este controlo." />}
            <ul className="space-y-2">
              {evidence.data?.items.map((row) => (
                <li key={row.id} className="flex items-center justify-between rounded-lg border border-border p-3 text-sm">
                  <span>{row.purpose}</span>
                  <Badge tone={row.verified_at ? "success" : "warning"}>
                    {row.verified_at ? "Verificado" : "Pendente"}
                  </Badge>
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
