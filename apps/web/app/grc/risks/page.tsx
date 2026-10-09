"use client";

import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return (
    <ResourcePage
      title="Enterprise Risk Register"
      endpoint="/grc/risks"
      rowHref="/grc/risks"
      columns={[["reference", "Referência"], ["title", "Risco"], ["risk_type", "Tipo"], ["inherent_score", "Inerente"], ["residual_score", "Residual"], ["status", "Estado"]]}
      create={{
        title: "Novo risco",
        fields: [
          { name: "title", label: "Título", required: true, minLength: 3 },
          { name: "risk_type", label: "Tipo", type: "select", required: true, options: [["cyber", "Cyber"], ["it", "TI"], ["enterprise", "Empresarial"], ["business", "Negócio"], ["third_party", "Terceiros"], ["asset", "Ativo"]] },
          { name: "category", label: "Categoria", required: true, placeholder: "identity, data, availability…" },
          { name: "description", label: "Descrição", type: "textarea", required: true, minLength: 3 },
          { name: "likelihood", label: "Probabilidade (1 a 5)", type: "number", required: true },
          { name: "impact", label: "Impacto (1 a 5)", type: "number", required: true },
          { name: "control_effectiveness", label: "Eficácia dos controlos (0 a 1)", type: "number", defaultValue: "0", help: "A pontuação residual é calculada de forma determinística no servidor" },
          { name: "treatment_strategy", label: "Estratégia de tratamento", type: "select", defaultValue: "mitigate", options: [["mitigate", "Mitigar"], ["avoid", "Evitar"], ["transfer", "Transferir"], ["accept", "Aceitar"]] },
        ],
      }}
    />
  );
}
