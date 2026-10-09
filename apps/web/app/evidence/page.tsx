"use client";

import { ResourcePage } from "@/components/resource-page";

export default function EvidencePage() {
  return (
    <ResourcePage
      title="Evidências"
      endpoint="/evidence"
      rowHref="/evidence"
      columns={[["title", "Título"], ["evidence_type", "Tipo"], ["sensitivity", "Sensibilidade"], ["redacted", "Redigida"], ["collected_by_adapter", "Origem"], ["collected_at", "Recolhida"]]}
      create={{
        title: "Carregar evidência",
        multipart: true,
        submitLabel: "Carregar",
        fields: [
          { name: "engagement_id", label: "Auditoria", type: "select", required: true, optionsFrom: { path: "/engagements", label: "name" } },
          { name: "title", label: "Título", required: true, minLength: 3 },
          { name: "evidence_type", label: "Tipo", type: "select", defaultValue: "document", options: [["document", "Documento"], ["screenshot", "Captura de ecrã"], ["log", "Log"], ["configuration", "Configuração"], ["report", "Relatório externo"]] },
          { name: "sensitivity", label: "Sensibilidade", type: "select", defaultValue: "confidential", options: [["internal", "Interna"], ["confidential", "Confidencial"], ["restricted", "Restrita"]] },
          { name: "description", label: "Descrição", type: "textarea" },
          { name: "file", label: "Ficheiro (PDF, PNG, JPG, TXT, LOG, JSON, CSV — máx. 10 MB)", type: "file", required: true, accept: ".pdf,.png,.jpg,.jpeg,.txt,.log,.json,.csv" },
        ],
      }}
    />
  );
}
