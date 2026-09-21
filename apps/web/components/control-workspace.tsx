"use client";

import { Badge, Card, EmptyState, LoadingState, ErrorState, SeverityBadge, Tabs, TabPanel } from "@cyberaudit/ui";
import { useMutation, useQuery } from "@tanstack/react-query";
import { BrainCircuit } from "lucide-react";
import { useState } from "react";
import { EvidenceLinksPanel } from "@/components/evidence-links-panel";
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
type GrcException = {
  id: string;
  reason: string;
  status: string;
  compensating_controls: string[];
  expires_at: string;
  reviewed_at: string | null;
};
type AgentAnswer = {
  response: string;
  citations: { node_id?: string; source_id?: string }[];
  confidence: number;
  limitations: string[];
};

const TABS = [
  { id: "overview", label: "Visão Geral" },
  { id: "mappings", label: "Frameworks" },
  { id: "assessments", label: "Avaliações" },
  { id: "evidence", label: "Evidência" },
  { id: "exceptions", label: "Exceções" },
  { id: "ai", label: "Cyber AI" },
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
  const exceptions = useQuery({
    queryKey: ["control-exceptions", id],
    queryFn: () =>
      api<{ items: GrcException[] }>(`/grc/exceptions?subject_type=control&subject_id=${id}`),
    enabled: tab === "exceptions",
  });
  const explain = useMutation({
    mutationFn: () =>
      api<AgentAnswer>("/agents/grc_analyst/ask", {
        method: "POST",
        body: JSON.stringify({
          question: "Explica o gap de conformidade deste controlo com base nas avaliações e evidência registadas.",
          source_ids: [id],
        }),
      }),
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
            <EvidenceLinksPanel subjectType="control" subjectId={id} enabled={tab === "evidence"} />
          </TabPanel>

          <TabPanel id="exceptions" active={tab}>
            {exceptions.isLoading && <LoadingState />}
            {exceptions.data?.items.length === 0 && (
              <EmptyState
                title="Sem exceções registadas para este controlo."
                description="Uma exceção não implica conformidade — apenas um risco aceite temporariamente com controlos compensatórios."
              />
            )}
            <ul className="space-y-2">
              {exceptions.data?.items.map((row) => (
                <li key={row.id} className="rounded-lg border border-border p-3 text-sm">
                  <div className="flex items-center justify-between">
                    <Badge tone={row.status === "approved" ? "success" : row.status === "rejected" ? "danger" : "warning"}>
                      {row.status}
                    </Badge>
                    <span className="text-xs text-muted">Expira: {new Date(row.expires_at).toLocaleDateString("pt-PT")}</span>
                  </div>
                  <p className="mt-2">{row.reason}</p>
                  {row.compensating_controls.length > 0 && (
                    <p className="mt-1 text-xs text-muted">
                      Controlos compensatórios: {row.compensating_controls.join(", ")}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          </TabPanel>

          <TabPanel id="ai" active={tab}>
            <button
              type="button"
              className="mb-4 inline-flex items-center gap-2 rounded-lg border border-border bg-surface px-4 py-2 text-sm font-medium hover:border-primary disabled:opacity-50"
              onClick={() => explain.mutate()}
              disabled={explain.isPending}
            >
              <BrainCircuit size={16} className="text-primary" />
              {explain.isPending ? "A analisar…" : "Explicar gap de conformidade"}
            </button>
            {explain.data && (
              <div className="space-y-2 rounded-lg border border-border bg-surface p-4 text-sm">
                <p>{explain.data.response}</p>
                {explain.data.citations.length > 0 && (
                  <p className="text-xs text-muted">
                    Fontes: {explain.data.citations.map((citation) => citation.source_id ?? citation.node_id).join(", ")}
                  </p>
                )}
                <p className="text-xs text-muted">Confiança: {(explain.data.confidence * 100).toFixed(0)}%</p>
              </div>
            )}
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
