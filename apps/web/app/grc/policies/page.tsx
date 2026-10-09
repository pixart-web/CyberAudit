"use client";

import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return (
    <ResourcePage
      title="Governance Policies"
      endpoint="/grc/policies"
      columns={[["title", "Política"], ["code", "Código"], ["version", "Versão"], ["status", "Estado"], ["review_at", "Revisão"], ["expires_at", "Expiração"]]}
      create={{
        title: "Nova política",
        fields: [
          { name: "code", label: "Código", required: true, placeholder: "POL-SEC-001" },
          { name: "title", label: "Título", required: true, minLength: 3 },
          { name: "policy_type", label: "Tipo", defaultValue: "policy" },
          { name: "content", label: "Conteúdo", type: "textarea", required: true, minLength: 10 },
          { name: "review_at", label: "Próxima revisão", type: "datetime" },
        ],
      }}
    />
  );
}
