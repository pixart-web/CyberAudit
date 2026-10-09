"use client";

import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return (
    <ResourcePage
      title="Incidentes"
      endpoint="/incidents"
      rowHref="/incidents"
      columns={[["reference", "Referência"], ["title", "Incidente"], ["severity", "Severidade"], ["status", "Estado"], ["risk_score", "Risco"], ["detected_at", "Detetado"]]}
      create={{
        title: "Novo incidente",
        fields: [
          { name: "title", label: "Título", required: true, minLength: 3 },
          { name: "severity", label: "Severidade", type: "select", required: true, defaultValue: "medium", options: [["low", "Baixa"], ["medium", "Média"], ["high", "Alta"], ["critical", "Crítica"]] },
          { name: "category", label: "Categoria", defaultValue: "security_event" },
          { name: "description", label: "Descrição", type: "textarea" },
          { name: "business_impact", label: "Impacto no negócio", type: "textarea" },
        ],
      }}
    />
  );
}
