"use client";

import { Badge, Button, Card } from "@cyberaudit/ui";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Activity, BrainCircuit, FileCheck2, Radar, Scale, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { FormEvent, useState } from "react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type SocMetrics = {
  events: number;
  open_alerts: number;
  open_incidents: number;
  critical_alerts: number;
};

type GrcMetrics = {
  open_risks: number;
  average_residual_risk: number;
  controls: number;
  implemented_controls: number;
  control_coverage: number;
};

export function SocCommandCenter() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["soc-dashboard"],
    queryFn: () => api<SocMetrics>("/soc/dashboard"),
  });
  const metrics = [
    ["events", "Eventos normalizados", Activity],
    ["open_alerts", "Alertas abertos", Radar],
    ["open_incidents", "Incidentes ativos", ShieldAlert],
    ["critical_alerts", "Alertas críticos", ShieldAlert],
  ] as const;
  return (
    <Shell title="SOC Command Center" eyebrow="Detection & Response">
      {error ? (
        <Card className="border-critical/30 p-8 text-red-300">Não foi possível carregar o SOC.</Card>
      ) : (
        <>
          <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {metrics.map(([key, label, Icon]) => (
              <Card key={key} className="p-5">
                <div className="mb-4 flex items-center justify-between text-muted">
                  <span className="text-xs font-semibold uppercase tracking-wider">{label}</span>
                  <Icon size={18} />
                </div>
                <p className="text-3xl font-semibold">{isLoading ? "—" : data?.[key] ?? 0}</p>
              </Card>
            ))}
          </div>
          <div className="grid gap-4 lg:grid-cols-3">
            <ActionCard title="Investigar" text="Eventos, deteções e timeline imutável." href="/detections" />
            <ActionCard title="Responder" text="Casos e playbooks sempre sob controlo humano." href="/incidents" />
            <ActionCard title="Threat Intelligence" text="IOCs com confiança, validade e proveniência." href="/threat-intelligence" />
          </div>
          <Card className="mt-4 p-5">
            <Badge tone="success">Defensivo e passivo</Badge>
            <p className="mt-3 text-sm leading-6 text-muted">
              O SOC correlaciona dados internos. Playbooks não executam comandos nem alteram
              sistemas auditados automaticamente.
            </p>
          </Card>
        </>
      )}
    </Shell>
  );
}

export function GrcCommandCenter() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["grc-dashboard"],
    queryFn: () => api<GrcMetrics>("/grc/dashboard"),
  });
  const metrics = [
    ["controls", "Controlos unificados", FileCheck2],
    ["implemented_controls", "Implementados", FileCheck2],
    ["control_coverage", "Cobertura (%)", Scale],
    ["open_risks", "Riscos abertos", ShieldAlert],
    ["average_residual_risk", "Risco residual médio", Activity],
  ] as const;
  return (
    <Shell title="Governance, Risk & Compliance" eyebrow="Enterprise GRC">
      {error ? (
        <Card className="border-critical/30 p-8 text-red-300">Não foi possível carregar o GRC.</Card>
      ) : (
        <>
          <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
            {metrics.map(([key, label, Icon]) => (
              <Card key={key} className="p-5">
                <div className="mb-4 flex items-center justify-between text-muted">
                  <span className="text-xs font-semibold uppercase tracking-wider">{label}</span>
                  <Icon size={18} />
                </div>
                <p className="text-3xl font-semibold">{isLoading ? "—" : data?.[key] ?? 0}</p>
              </Card>
            ))}
          </div>
          <div className="grid gap-4 lg:grid-cols-3">
            <ActionCard title="Controlos" text="Um controlo, vários referenciais." href="/grc/controls" />
            <ActionCard title="Risk Register" text="Risco inerente, residual e tratamentos." href="/grc/risks" />
            <ActionCard title="Compliance" text="Cobertura e maturidade por framework." href="/grc/compliance" />
          </div>
        </>
      )}
    </Shell>
  );
}

function ActionCard({ title, text, href }: { title: string; text: string; href: string }) {
  return (
    <Card className="p-5">
      <h2 className="font-semibold">{title}</h2>
      <p className="my-3 min-h-10 text-sm text-muted">{text}</p>
      <Link className="text-sm font-semibold text-cyan hover:underline" href={href}>
        Abrir módulo →
      </Link>
    </Card>
  );
}

type AiResponse = {
  id: string;
  response: string;
  facts: { source_id: string; label: string }[];
  inferences: unknown[];
  citations: { source_id: string; source_type: string }[];
  confidence: number;
  limitations: string[];
  action_executed: boolean;
};

export function AiAssistant() {
  const [question, setQuestion] = useState("");
  const mutation = useMutation({
    mutationFn: () =>
      api<AiResponse>("/ai/assist", {
        method: "POST",
        body: JSON.stringify({
          service: "explanation",
          question,
          context_selector: {},
        }),
      }),
  });
  function submit(event: FormEvent) {
    event.preventDefault();
    if (question.trim().length >= 3) mutation.mutate();
  }
  return (
    <Shell title="AI Security Assistant" eyebrow="Knowledge Graph">
      <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
        <Card className="p-5">
          <div className="mb-5 flex items-center gap-3">
            <BrainCircuit className="text-primary" />
            <div>
              <h2 className="font-semibold">Assistente fundamentado</h2>
              <p className="text-sm text-muted">Factos e inferências são apresentados separadamente.</p>
            </div>
          </div>
          <form onSubmit={submit}>
            <label className="text-sm font-semibold" htmlFor="ai-question">Pergunta</label>
            <textarea
              id="ai-question"
              className="field mt-2 min-h-32"
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              placeholder="Explica os riscos com base nas fontes internas disponíveis…"
              maxLength={4000}
            />
            <Button className="mt-3" disabled={mutation.isPending || question.trim().length < 3}>
              {mutation.isPending ? "A analisar…" : "Analisar fontes"}
            </Button>
          </form>
          {mutation.error && <p className="mt-4 text-sm text-red-300">Não foi possível concluir a análise.</p>}
          {mutation.data && (
            <div className="mt-6 space-y-4" aria-live="polite">
              <div className="rounded-lg border border-border bg-surface p-4">
                <div className="mb-2 flex items-center justify-between">
                  <h3 className="font-semibold">Resposta</h3>
                  <Badge tone={mutation.data.confidence > 0.6 ? "success" : "warning"}>
                    Confiança {Math.round(mutation.data.confidence * 100)}%
                  </Badge>
                </div>
                <p className="text-sm leading-6">{mutation.data.response}</p>
              </div>
              <div className="grid gap-3 md:grid-cols-2">
                <ResultList title="Factos" items={mutation.data.facts.map((item) => item.label)} />
                <ResultList title="Inferências" items={mutation.data.inferences.map(() => "Inferência declarada")} />
                <ResultList title="Fontes" items={mutation.data.citations.map((item) => `${item.source_type}:${item.source_id}`)} />
                <ResultList title="Limitações" items={mutation.data.limitations} />
              </div>
            </div>
          )}
        </Card>
        <Card className="h-fit p-5">
          <Badge tone="info">Advisory only</Badge>
          <h2 className="mt-4 font-semibold">Guardrails permanentes</h2>
          <ul className="mt-3 space-y-2 text-sm text-muted">
            <li>• Não executa ações.</li>
            <li>• Não inventa fontes.</li>
            <li>• Isolamento por organização.</li>
            <li>• Respostas reproduzíveis e auditadas.</li>
            <li>• Revisão humana obrigatória.</li>
          </ul>
        </Card>
      </div>
    </Shell>
  );
}

function ResultList({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="rounded-lg border border-border p-4">
      <h3 className="mb-2 text-sm font-semibold">{title}</h3>
      {items.length ? (
        <ul className="space-y-1 text-xs text-muted">{items.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul>
      ) : (
        <p className="text-xs text-muted">Nenhum registo.</p>
      )}
    </div>
  );
}
