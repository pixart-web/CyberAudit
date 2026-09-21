"use client";

import { Badge, Card, EmptyState, ErrorState, LoadingState, MetricCard, SeverityBadge } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type EnterpriseRisk = {
  id: string;
  reference: string;
  title: string;
  description: string;
  risk_type: string;
  category: string;
  status: string;
  asset_id: string | null;
  third_party: string | null;
  likelihood: number;
  impact: number;
  inherent_score: number;
  control_effectiveness: number;
  residual_score: number;
  appetite: number;
  treatment_strategy: string;
};
type Treatment = {
  id: string;
  title: string;
  description: string;
  status: string;
  target_residual_score: number;
  progress: number;
};
type RiskDetail = { risk: EnterpriseRisk; treatments: Treatment[] };

export default function RiskRegisterDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, isLoading } = useQuery({
    queryKey: ["risk-register", id],
    queryFn: () => api<RiskDetail>(`/grc/risks/${id}`),
    retry: false,
  });

  if (isLoading) return <Shell title="Risco"><LoadingState /></Shell>;
  if (error || !data) {
    return (
      <Shell title="Risco">
        <ErrorState title="Registo de risco não encontrado ou sem autorização." />
      </Shell>
    );
  }

  const { risk, treatments } = data;
  const withinAppetite = risk.residual_score <= risk.appetite;

  return (
    <Shell title={risk.title} eyebrow={`Risco ${risk.reference} · ${risk.risk_type}`}>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <Badge tone="neutral">{risk.status}</Badge>
        <Badge tone={withinAppetite ? "success" : "danger"}>
          {withinAppetite ? "Dentro do apetite" : "Acima do apetite"}
        </Badge>
        {risk.asset_id && (
          <Link href={`/assets/${risk.asset_id}`} className="ml-auto text-sm text-cyan hover:underline">
            Ver ativo associado
          </Link>
        )}
      </div>
      <div className="mb-4 grid gap-4 md:grid-cols-4">
        <MetricCard label="Inerente" value={risk.inherent_score.toFixed(1)} />
        <MetricCard label="Residual" value={risk.residual_score.toFixed(1)} tone={withinAppetite ? "healthy" : "high"} />
        <MetricCard label="Apetite" value={risk.appetite.toFixed(1)} />
        <MetricCard label="Efetividade dos controlos" value={`${(risk.control_effectiveness * 100).toFixed(0)}%`} />
      </div>
      <Card className="p-6">
        <p className="mb-4 text-sm text-muted">{risk.description}</p>
        <dl className="grid gap-3 text-sm sm:grid-cols-2">
          <Row label="Categoria" value={risk.category} />
          <Row label="Terceiro" value={risk.third_party ?? "—"} />
          <Row label="Probabilidade" value={risk.likelihood.toString()} />
          <Row label="Impacto" value={risk.impact.toString()} />
          <Row label="Estratégia de tratamento" value={risk.treatment_strategy} />
        </dl>
        <p className="mt-4 text-xs text-muted">
          Score inerente/residual calculado deterministicamente (probabilidade × impacto, ajustado pela efetividade
          dos controlos). Nunca recalculado silenciosamente por IA.
        </p>
      </Card>
      <Card className="mt-4 p-6">
        <h2 className="mb-3 font-semibold">Planos de tratamento</h2>
        {treatments.length === 0 && <EmptyState title="Ainda não existem planos de tratamento para este risco." />}
        <ul className="space-y-2">
          {treatments.map((treatment) => (
            <li key={treatment.id} className="rounded-lg border border-border p-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="font-medium">{treatment.title}</span>
                <SeverityBadge state={treatment.status === "completed" ? "healthy" : "warning"} />
              </div>
              <p className="mt-1 text-xs text-muted">{treatment.description}</p>
              <p className="mt-2 text-xs text-muted">
                Progresso: {treatment.progress}% · Alvo residual: {treatment.target_residual_score.toFixed(1)}
              </p>
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
