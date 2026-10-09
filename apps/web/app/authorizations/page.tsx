"use client";

import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return (
    <ResourcePage
      title="Autorizações"
      endpoint="/authorizations"
      columns={[["filename", "Documento"], ["status", "Estado"], ["signed_by", "Assinado por"], ["valid_from", "Válido de"], ["valid_until", "Válido até"]]}
      create={{
        title: "Carregar autorização (PDF)",
        multipart: true,
        fields: [
          { name: "engagement_id", label: "Auditoria", type: "select", required: true, optionsFrom: { path: "/engagements", label: "name" } },
          { name: "signed_by", label: "Assinado por", required: true },
          { name: "valid_from", label: "Válido de", type: "date", required: true },
          { name: "valid_until", label: "Válido até", type: "date", required: true },
          { name: "file", label: "Documento PDF", type: "file", accept: "application/pdf", required: true },
        ],
      }}
    />
  );
}
