"use client";

import { Badge, Card, EmptyState, ErrorState, LoadingState, SeverityBadge, Tabs, TabPanel } from "@cyberaudit/ui";
import { useMutation, useQuery } from "@tanstack/react-query";
import { BrainCircuit } from "lucide-react";
import { useState } from "react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Identity = {
  id: string;
  username: string;
  display_name: string;
  email: string | null;
  identity_type: string;
  enabled: boolean;
  privileged: boolean;
  guest: boolean;
  service_account: boolean;
  owner: string | null;
  department: string | null;
  job_title: string | null;
  mfa_state: string;
  risk_state: string;
  risk_score: number;
  last_login_at: string | null;
  last_activity_at: string | null;
};
type RiskDetail = { score: number; reasons: string[]; calculation_version: string };
type Items<T> = { items: T[]; total?: number };
type Posture = {
  id: string;
  mfa_enforced: string;
  conditional_access_covered: string;
  legacy_authentication_allowed: string;
  posture_score: number;
};
type Relationship = { id: string; relationship_type: string; target_type: string; target_id: string; source_id: string };
type AgentAnswer = {
  response: string;
  citations: { node_id?: string; source_id?: string }[];
  confidence: number;
  limitations: string[];
};

const REASON_LABELS: Record<string, string> = {
  privileged_identity: "Identidade privilegiada",
  mfa_not_enforced: "MFA não aplicado",
  mfa_state_unknown: "Estado de MFA desconhecido",
  enabled_stale_identity: "Conta ativa e inativa há mais de 90 dias",
  guest_identity: "Identidade convidada",
  owner_missing: "Sem responsável atribuído",
};

const TABS = [
  { id: "overview", label: "Visão Geral" },
  { id: "risk", label: "Risco" },
  { id: "posture", label: "Postura de Autenticação" },
  { id: "relationships", label: "Grupos e Funções" },
];

export function IdentityWorkspace({ id }: { id: string }) {
  const [tab, setTab] = useState("overview");

  const identity = useQuery({
    queryKey: ["identity", id],
    queryFn: () => api<Identity>(`/identity/users/${id}`),
    retry: false,
  });
  const risk = useQuery({
    queryKey: ["identity-risk", id],
    queryFn: () => api<RiskDetail>(`/identity/users/${id}/risk`),
    enabled: tab === "risk" || tab === "overview",
  });
  const posture = useQuery({
    queryKey: ["identity-posture", id],
    queryFn: () => api<Items<Posture>>(`/identity/posture?identity_id=${id}`),
    enabled: tab === "posture",
  });
  const relationships = useQuery({
    queryKey: ["identity-relationships", id],
    queryFn: () => api<Items<Relationship>>(`/identity/relationships?identity_id=${id}`),
    enabled: tab === "relationships",
  });
  const explain = useMutation({
    mutationFn: () =>
      api<AgentAnswer>("/agents/identity_analyst/ask", {
        method: "POST",
        body: JSON.stringify({
          question: "Explica a postura e o risco de privilégio desta identidade a partir do que está registado.",
          source_ids: [id],
        }),
      }),
  });

  if (identity.isLoading) return <Shell title="Identidade"><LoadingState /></Shell>;
  if (identity.error || !identity.data) {
    return (
      <Shell title="Identidade">
        <ErrorState title="Identidade não encontrada ou sem autorização." />
      </Shell>
    );
  }

  const item = identity.data;

  return (
    <Shell title={item.display_name} eyebrow={`Identidade · ${item.identity_type}`}>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <Badge tone={item.enabled ? "success" : "neutral"}>{item.enabled ? "Ativa" : "Desativada"}</Badge>
        {item.privileged && <Badge tone="warning">Privilegiada</Badge>}
        {item.guest && <Badge tone="neutral">Convidada</Badge>}
        {item.service_account && <Badge tone="neutral">Conta de serviço</Badge>}
        <SeverityBadge state={item.mfa_state === "true" ? "healthy" : item.mfa_state === "false" ? "failed" : "unknown"} />
        <Badge tone="info">Risco: {item.risk_score.toFixed(0)}</Badge>
      </div>
      <Card className="overflow-hidden">
        <Tabs items={TABS} active={tab} onChange={setTab} />
        <div className="p-5">
          <TabPanel id="overview" active={tab}>
            <dl className="grid gap-3 text-sm sm:grid-cols-2">
              <Row label="Username" value={item.username} />
              <Row label="Email" value={item.email ?? "—"} />
              <Row label="Responsável" value={item.owner ?? "Sem responsável"} />
              <Row label="Departamento" value={item.department ?? "—"} />
              <Row label="Cargo" value={item.job_title ?? "—"} />
              <Row
                label="Último login"
                value={item.last_login_at ? new Date(item.last_login_at).toLocaleString("pt-PT") : "—"}
              />
              <Row
                label="Última atividade"
                value={item.last_activity_at ? new Date(item.last_activity_at).toLocaleString("pt-PT") : "—"}
              />
            </dl>
            {risk.data && risk.data.reasons.length > 0 && (
              <div className="mt-5">
                <p className="mb-2 text-xs font-semibold text-muted">Principais fatores de risco</p>
                <div className="flex flex-wrap gap-2">
                  {risk.data.reasons.map((reason) => (
                    <Badge key={reason} tone="warning">{REASON_LABELS[reason] ?? reason}</Badge>
                  ))}
                </div>
              </div>
            )}
          </TabPanel>

          <TabPanel id="risk" active={tab}>
            {risk.isLoading && <LoadingState />}
            {risk.data && (
              <div className="space-y-4">
                <div className="rounded-lg border border-border p-4">
                  <p className="text-xs text-muted">Score de risco determinístico</p>
                  <p className="mt-1 text-3xl font-semibold text-cyan">{risk.data.score.toFixed(0)}</p>
                  <p className="mt-1 text-xs text-muted">Versão: {risk.data.calculation_version}</p>
                </div>
                {risk.data.reasons.length === 0 ? (
                  <EmptyState title="Sem fatores de risco identificados para esta identidade." />
                ) : (
                  <ul className="space-y-2">
                    {risk.data.reasons.map((reason) => (
                      <li key={reason} className="rounded-lg border border-border p-3 text-sm">
                        {REASON_LABELS[reason] ?? reason}
                      </li>
                    ))}
                  </ul>
                )}
                <button
                  type="button"
                  className="inline-flex items-center gap-2 rounded-lg border border-border bg-surface px-4 py-2 text-sm font-medium hover:border-primary disabled:opacity-50"
                  onClick={() => explain.mutate()}
                  disabled={explain.isPending}
                >
                  <BrainCircuit size={16} className="text-primary" />
                  {explain.isPending ? "A analisar…" : "Explicar risco desta identidade"}
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
              </div>
            )}
          </TabPanel>

          <TabPanel id="posture" active={tab}>
            {posture.isLoading && <LoadingState />}
            {posture.data?.items.length === 0 && (
              <EmptyState title="Sem dados de postura de autenticação para esta identidade." />
            )}
            <ul className="space-y-2">
              {posture.data?.items.map((row) => (
                <li key={row.id} className="rounded-lg border border-border p-3 text-sm">
                  <div className="flex flex-wrap gap-2">
                    <Badge tone={row.mfa_enforced === "true" ? "success" : "warning"}>
                      MFA aplicado: {row.mfa_enforced}
                    </Badge>
                    <Badge tone={row.conditional_access_covered === "true" ? "success" : "warning"}>
                      Acesso condicional: {row.conditional_access_covered}
                    </Badge>
                    <Badge tone={row.legacy_authentication_allowed === "true" ? "danger" : "success"}>
                      Autenticação legada: {row.legacy_authentication_allowed}
                    </Badge>
                  </div>
                  <p className="mt-2 text-xs text-muted">Posture score: {row.posture_score.toFixed(0)}</p>
                </li>
              ))}
            </ul>
          </TabPanel>

          <TabPanel id="relationships" active={tab}>
            {relationships.isLoading && <LoadingState />}
            {relationships.data?.items.length === 0 && (
              <EmptyState title="Sem grupos ou funções associados a esta identidade." />
            )}
            <ul className="space-y-2">
              {relationships.data?.items.map((row) => (
                <li key={row.id} className="flex items-center justify-between rounded-lg border border-border p-3 text-sm">
                  <span>{row.relationship_type} · {row.target_type}</span>
                  <span className="text-xs text-muted">{row.target_id}</span>
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
