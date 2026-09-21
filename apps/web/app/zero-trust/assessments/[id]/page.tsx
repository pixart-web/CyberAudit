"use client";

import { Badge, Card, EmptyState, ErrorState, LoadingState, MetricCard, SeverityBadge } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Dimension = {
  id: string;
  dimension: string;
  score: number;
  status: string;
  weight: number;
  confidence: number;
  unknown_factors: string[];
};
type Assessment = {
  id: string;
  subject_type: string;
  subject_id: string | null;
  score: number;
  status: string;
  confidence: number;
  recommendations: string[];
  unknown_factors: string[];
  algorithm_version: string;
  evaluated_at: string;
  dimensions: Dimension[];
};

export default function ZeroTrustAssessmentDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, isLoading } = useQuery({
    queryKey: ["zero-trust-assessment", id],
    queryFn: () => api<Assessment>(`/zero-trust/assessments/${id}`),
    retry: false,
  });

  if (isLoading) return <Shell title="Avaliação Zero Trust"><LoadingState /></Shell>;
  if (error || !data) {
    return (
      <Shell title="Avaliação Zero Trust">
        <ErrorState title="Avaliação não encontrada ou sem autorização." />
      </Shell>
    );
  }

  return (
    <Shell title={`Avaliação · ${data.subject_type}`} eyebrow="Zero Trust">
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <SeverityBadge state={data.status === "strong" ? "healthy" : data.status === "weak" ? "failed" : "warning"} />
        <Badge tone="info">Confiança: {(data.confidence * 100).toFixed(0)}%</Badge>
        <Badge tone="neutral">{data.algorithm_version}</Badge>
        <Badge tone="neutral" className="ml-auto">
          {new Date(data.evaluated_at).toLocaleString("pt-PT")}
        </Badge>
      </div>
      <div className="mb-4 grid gap-4 md:grid-cols-3">
        <MetricCard label="Score global" value={data.score.toFixed(0)} />
        <MetricCard label="Âmbito" value={data.subject_id ?? data.subject_type} />
        <MetricCard label="Dimensões avaliadas" value={String(data.dimensions.length)} />
      </div>
      <Card className="p-6">
        <h2 className="mb-3 font-semibold">Dimensões</h2>
        {data.dimensions.length === 0 && <EmptyState title="Sem dimensões avaliadas." />}
        <ul className="space-y-2">
          {data.dimensions.map((dimension) => (
            <li key={dimension.id} className="rounded-lg border border-border p-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="font-medium">{dimension.dimension}</span>
                <SeverityBadge
                  state={dimension.status === "strong" ? "healthy" : dimension.status === "weak" ? "failed" : "warning"}
                />
              </div>
              <p className="mt-1 text-xs text-muted">
                Score: {dimension.score.toFixed(0)} · Peso: {dimension.weight} · Confiança: {(dimension.confidence * 100).toFixed(0)}%
              </p>
              {dimension.unknown_factors.length > 0 && (
                <p className="mt-1 text-xs text-muted">Fatores desconhecidos: {dimension.unknown_factors.join(", ")}</p>
              )}
            </li>
          ))}
        </ul>
      </Card>
      {data.recommendations.length > 0 && (
        <Card className="mt-4 p-6">
          <h2 className="mb-3 font-semibold">Recomendações</h2>
          <ul className="list-disc space-y-1 pl-4 text-sm">
            {data.recommendations.map((recommendation, index) => (
              <li key={index}>{recommendation}</li>
            ))}
          </ul>
        </Card>
      )}
      {data.unknown_factors.length > 0 && (
        <p className="mt-4 text-xs text-muted">
          Fatores globais desconhecidos: {data.unknown_factors.join(", ")} — a pontuação nunca assume &ldquo;seguro&rdquo; na
          ausência de evidência.
        </p>
      )}
    </Shell>
  );
}
