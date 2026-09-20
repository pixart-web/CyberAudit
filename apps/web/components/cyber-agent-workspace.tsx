"use client";

import { Badge, Button, Card } from "@cyberaudit/ui";
import { useMutation, useQuery } from "@tanstack/react-query";
import { BrainCircuit, Cpu, ServerCog } from "lucide-react";
import { FormEvent, useState } from "react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type AgentSummary = {
  code: string;
  name: string;
  mission: string;
  knowledge_scopes: string[];
  allowed_tools: string[];
};

type AgentAnswer = {
  agent_code: string;
  correlation_id: string;
  response: string;
  facts: { source_id: string; label: string }[];
  citations: { source_id: string; source_type: string }[];
  confidence: number;
  limitations: string[];
  reproducibility_key: string;
  required_human_approval: boolean;
};

type RuntimeHealth = {
  backend: string;
  healthy: boolean;
  message: string;
  sovereign_default: boolean;
};

type HardwareProfile = {
  os_name: string;
  cpu_cores: number;
  ram_total_mb: number;
  gpu_vendor: string | null;
  profile: string;
};

export function CyberAgentWorkspace() {
  const [agentCode, setAgentCode] = useState<string>("security_analyst");
  const [question, setQuestion] = useState("");

  const agents = useQuery({
    queryKey: ["cyber-agents"],
    queryFn: () => api<{ items: AgentSummary[] }>("/agents"),
  });
  const health = useQuery({
    queryKey: ["ai-runtime-health"],
    queryFn: () => api<RuntimeHealth>("/ai-runtime/health"),
  });
  const hardware = useQuery({
    queryKey: ["ai-runtime-hardware"],
    queryFn: () => api<HardwareProfile>("/ai-runtime/hardware"),
  });

  const ask = useMutation({
    mutationFn: () =>
      api<AgentAnswer>(`/agents/${agentCode}/ask`, {
        method: "POST",
        body: JSON.stringify({ question, source_ids: [] }),
      }),
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    if (question.trim().length >= 3) ask.mutate();
  }

  const selectedAgent = agents.data?.items.find((item) => item.code === agentCode);

  return (
    <Shell title="Cyber AI Workspace" eyebrow="Agents & Local Runtime">
      <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
        <Card className="p-5">
          <div className="mb-5 flex items-center gap-3">
            <BrainCircuit className="text-primary" />
            <div>
              <h2 className="font-semibold">Consultar um agente</h2>
              <p className="text-sm text-muted">
                Cada agente responde apenas com base em evidência registada; a IA local, quando
                instalada, só reformula o texto — nunca inventa factos.
              </p>
            </div>
          </div>
          <form onSubmit={submit}>
            <label className="text-sm font-semibold" htmlFor="agent-select">
              Agente
            </label>
            <select
              id="agent-select"
              className="field mt-2"
              value={agentCode}
              onChange={(event) => setAgentCode(event.target.value)}
            >
              {(agents.data?.items ?? []).map((item) => (
                <option key={item.code} value={item.code}>
                  {item.name}
                </option>
              ))}
            </select>
            {selectedAgent && <p className="mt-2 text-xs text-muted">{selectedAgent.mission}</p>}
            <label className="mt-4 block text-sm font-semibold" htmlFor="agent-question">
              Pergunta
            </label>
            <textarea
              id="agent-question"
              className="field mt-2 min-h-32"
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              placeholder="Explica o que se sabe sobre este incidente…"
              maxLength={4000}
            />
            <Button className="mt-3" disabled={ask.isPending || question.trim().length < 3}>
              {ask.isPending ? "A consultar…" : "Perguntar ao agente"}
            </Button>
          </form>
          {ask.error && (
            <p className="mt-4 text-sm text-red-300">Não foi possível concluir a consulta.</p>
          )}
          {ask.data && (
            <div className="mt-6 space-y-4" aria-live="polite">
              <div className="rounded-lg border border-border bg-surface p-4">
                <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                  <h3 className="font-semibold">Resposta</h3>
                  <div className="flex gap-2">
                    <Badge tone={ask.data.confidence > 0.6 ? "success" : "warning"}>
                      Confiança {Math.round(ask.data.confidence * 100)}%
                    </Badge>
                    {ask.data.required_human_approval && (
                      <Badge tone="warning">Requer aprovação humana</Badge>
                    )}
                  </div>
                </div>
                <p className="text-sm leading-6">{ask.data.response}</p>
              </div>
              <div className="grid gap-3 md:grid-cols-2">
                <ResultList title="Factos" items={ask.data.facts.map((item) => item.label)} />
                <ResultList
                  title="Fontes"
                  items={ask.data.citations.map((item) => `${item.source_type}:${item.source_id}`)}
                />
                <ResultList title="Limitações" items={ask.data.limitations} />
              </div>
            </div>
          )}
        </Card>
        <div className="space-y-4">
          <Card className="p-5">
            <div className="mb-3 flex items-center gap-2">
              <ServerCog size={18} className="text-primary" />
              <h2 className="font-semibold">Local AI Runtime</h2>
            </div>
            {health.data ? (
              <div className="space-y-2 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-muted">Backend</span>
                  <Badge tone={health.data.sovereign_default ? "info" : "success"}>
                    {health.data.backend}
                  </Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-muted">Estado</span>
                  <Badge tone={health.data.healthy ? "success" : "warning"}>
                    {health.data.healthy ? "saudável" : "indisponível"}
                  </Badge>
                </div>
                <p className="text-xs text-muted">{health.data.message}</p>
                {health.data.sovereign_default && (
                  <p className="text-xs text-muted">
                    Sem modelo local instalado: as respostas são 100% determinísticas.
                  </p>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted">A carregar…</p>
            )}
          </Card>
          <Card className="p-5">
            <div className="mb-3 flex items-center gap-2">
              <Cpu size={18} className="text-primary" />
              <h2 className="font-semibold">Perfil de hardware</h2>
            </div>
            {hardware.data ? (
              <ul className="space-y-1 text-sm text-muted">
                <li>Perfil: <span className="text-foreground">{hardware.data.profile}</span></li>
                <li>SO: {hardware.data.os_name}</li>
                <li>Núcleos CPU: {hardware.data.cpu_cores}</li>
                <li>RAM: {Math.round(hardware.data.ram_total_mb / 1024)} GB</li>
                <li>GPU: {hardware.data.gpu_vendor ?? "não detetada"}</li>
              </ul>
            ) : (
              <p className="text-sm text-muted">A carregar…</p>
            )}
          </Card>
          <Card className="p-5">
            <Badge tone="info">Advisory only</Badge>
            <h2 className="mt-4 font-semibold">Guardrails permanentes</h2>
            <ul className="mt-3 space-y-2 text-sm text-muted">
              <li>• Cada agente só usa as tools que lhe estão explicitamente atribuídas.</li>
              <li>• Isolamento por organização em todas as tools.</li>
              <li>• Nenhum agente tem acesso direto a base de dados ou shell.</li>
              <li>• Respostas auditadas e com correlation ID.</li>
            </ul>
          </Card>
        </div>
      </div>
    </Shell>
  );
}

function ResultList({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="rounded-lg border border-border p-4">
      <h3 className="mb-2 text-sm font-semibold">{title}</h3>
      {items.length ? (
        <ul className="space-y-1 text-xs text-muted">
          {items.map((item, index) => (
            <li key={`${item}-${index}`}>{item}</li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-muted">Nenhum registo.</p>
      )}
    </div>
  );
}
