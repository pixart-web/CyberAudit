"use client";

import { Badge, Button, Card, ConfirmationDialog, ErrorState, LoadingState, SeverityBadge } from "@cyberaudit/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type AgentAnswer = {
  response: string;
  citations: { source_id: string }[];
  confidence: number;
  limitations: string[];
};

type AttackPath = {
  id: string;
  name: string;
  description: string;
  entry_asset_id: string;
  target_asset_id: string;
  path_type: string;
  severity: string;
  confidence: number;
  overall_risk: number;
  status: string;
  generated_by: string;
};
type Step = {
  id: string;
  sequence: number;
  source_asset_id: string;
  target_asset_id: string;
  finding_id: string | null;
  condition: string;
  explanation: string;
  confidence: number;
  evidence: string[];
  mitigation: string;
};
type PathDetail = { path: AttackPath; steps: Step[]; automatic: boolean; fact_vs_inference: boolean };

export default function AttackPathDetail() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const [pendingReject, setPendingReject] = useState(false);
  const { data, error, isLoading } = useQuery({
    queryKey: ["attack-path", id],
    queryFn: () => api<PathDetail>(`/attack-paths/${id}`),
    retry: false,
  });

  const review = useMutation({
    mutationFn: (action: "validate" | "reject") => api(`/attack-paths/${id}/${action}`, { method: "POST" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["attack-path", id] }),
  });

  const explain = useMutation({
    mutationFn: () =>
      api<AgentAnswer>("/agents/attack_path_analyst/ask", {
        method: "POST",
        body: JSON.stringify({
          question: "Explica este caminho de ataque em linguagem simples para um analista.",
          source_ids: [id],
        }),
      }),
  });

  if (isLoading) return <Shell title="Attack Path"><LoadingState /></Shell>;
  if (error || !data) {
    return (
      <Shell title="Attack Path">
        <ErrorState title="Caminho de ataque não encontrado ou sem autorização." />
      </Shell>
    );
  }

  const { path, steps } = data;

  return (
    <Shell title={path.name} eyebrow={`Attack Path · ${path.path_type}`}>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <SeverityBadge state={path.severity} />
        <Badge tone="neutral">{path.status}</Badge>
        <Badge tone="info">Risco: {path.overall_risk.toFixed(1)}</Badge>
        <Badge tone="info">Confiança: {(path.confidence * 100).toFixed(0)}%</Badge>
        {path.status === "candidate" && (
          <div className="ml-auto flex gap-2">
            <Button className="text-xs" onClick={() => review.mutate("validate")} disabled={review.isPending}>
              Validar
            </Button>
            <Button className="bg-transparent text-xs" onClick={() => setPendingReject(true)} disabled={review.isPending}>
              Rejeitar
            </Button>
          </div>
        )}
      </div>
      <ConfirmationDialog
        open={pendingReject}
        title="Rejeitar este caminho de ataque?"
        description="Marca o caminho candidato como rejeitado; deixa de contar para o risco agregado."
        confirmLabel="Rejeitar caminho"
        destructive
        onConfirm={() => {
          review.mutate("reject");
          setPendingReject(false);
        }}
        onCancel={() => setPendingReject(false)}
      />
      <Card className="p-6">
        <p className="mb-2 text-sm text-muted">{path.description}</p>
        <p className="mb-6 text-xs text-muted">
          Caminho {path.generated_by === "rules" ? "gerado por regras determinísticas" : path.generated_by} — hipótese,
          nunca uma execução real de exploração.
        </p>
        <div className="mb-4 flex items-center gap-2 text-sm">
          <Link href={`/assets/${path.entry_asset_id}`} className="rounded-lg border border-border px-3 py-2 text-cyan hover:underline">
            Entrada: {path.entry_asset_id}
          </Link>
          <span className="text-muted">→</span>
          <Link href={`/assets/${path.target_asset_id}`} className="rounded-lg border border-border px-3 py-2 text-cyan hover:underline">
            Alvo: {path.target_asset_id}
          </Link>
        </div>
        <h2 className="mb-3 font-semibold">Passos (facto vs. inferência)</h2>
        <table className="table">
          <caption className="sr-only">Sequência de passos do caminho de ataque, com evidência e mitigação</caption>
          <thead>
            <tr>
              <th>#</th>
              <th>De</th>
              <th>Para</th>
              <th>Condição</th>
              <th>Confiança</th>
              <th>Mitigação</th>
            </tr>
          </thead>
          <tbody>
            {steps.map((step) => (
              <tr key={step.id}>
                <td>{step.sequence}</td>
                <td>
                  <Link href={`/assets/${step.source_asset_id}`} className="text-cyan hover:underline">
                    {step.source_asset_id}
                  </Link>
                </td>
                <td>
                  <Link href={`/assets/${step.target_asset_id}`} className="text-cyan hover:underline">
                    {step.target_asset_id}
                  </Link>
                </td>
                <td>
                  {step.condition}
                  <p className="mt-1 text-xs text-muted">{step.explanation}</p>
                  {step.finding_id && (
                    <Link href={`/findings/${step.finding_id}`} className="mt-1 block text-xs text-cyan hover:underline">
                      Ver finding relacionado
                    </Link>
                  )}
                </td>
                <td>{(step.confidence * 100).toFixed(0)}%</td>
                <td>{step.mitigation || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card className="mt-4 p-6">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="font-semibold">Cyber AI — Explicar Attack Path</h2>
          <Button className="text-xs" onClick={() => explain.mutate()} disabled={explain.isPending}>
            {explain.isPending ? "A explicar…" : "Explicar caminho de ataque"}
          </Button>
        </div>
        <p className="mb-3 text-xs text-muted">
          Os passos, condições e mitigações acima são factos do grafo, calculados por regras determinísticas. A
          explicação abaixo é gerada por IA a partir dessas fontes internas e nunca altera ou substitui esses factos.
        </p>
        {explain.data && (
          <div className="rounded-lg border border-border bg-card/60 p-4 text-sm">
            <p className="mb-2">{explain.data.response}</p>
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
              <Badge tone="info">Confiança: {Math.round(explain.data.confidence * 100)}%</Badge>
              <span>{explain.data.citations.length} citação(ões) interna(s)</span>
            </div>
            {explain.data.limitations.length > 0 && (
              <ul className="mt-2 list-disc pl-4 text-xs text-muted">
                {explain.data.limitations.map((limitation) => (
                  <li key={limitation}>{limitation}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </Card>
    </Shell>
  );
}
