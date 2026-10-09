"use client";

import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return (
    <ResourcePage
      title="Eventos de Segurança"
      endpoint="/security-events"
      rowHref="/security-events"
      columns={[["summary", "Evento"], ["event_type", "Tipo"], ["source", "Origem"], ["severity", "Severidade"], ["occurred_at", "Ocorrido"], ["trusted", "Confiável"]]}
      create={{
        title: "Registar evento manualmente",
        fields: [
          { name: "source", label: "Origem", required: true, placeholder: "ex.: firewall, EDR, analista" },
          { name: "event_type", label: "Tipo de evento", required: true, placeholder: "ex.: authentication.failed" },
          { name: "severity", label: "Severidade", type: "select", defaultValue: "info", options: [["info", "Info"], ["low", "Baixa"], ["medium", "Média"], ["high", "Alta"], ["critical", "Crítica"]] },
          { name: "occurred_at", label: "Ocorrido em", type: "datetime", required: true },
          { name: "summary", label: "Resumo", required: true },
          { name: "actor_ref", label: "Ator" },
          { name: "source_ip", label: "IP de origem" },
          { name: "destination_ip", label: "IP de destino" },
          { name: "external_id", label: "ID externo", help: "Se vazio, é gerado automaticamente", generate: () => `manual-${Date.now()}` },
        ],
      }}
    />
  );
}
