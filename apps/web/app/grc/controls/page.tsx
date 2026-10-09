"use client";

import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return (
    <ResourcePage
      title="Controlos Unificados"
      endpoint="/grc/controls"
      rowHref="/grc/controls"
      columns={[["code", "Código"], ["title", "Controlo"], ["domain", "Domínio"], ["implementation_status", "Implementação"], ["maturity_level", "Maturidade"], ["next_review_at", "Próxima revisão"]]}
      create={[
        {
          title: "Novo controlo",
          fields: [
            { name: "code", label: "Código", required: true, placeholder: "IAM-001", help: "Maiúsculas, números, ponto, hífen ou _" },
            { name: "title", label: "Título", required: true, minLength: 3 },
            { name: "domain", label: "Domínio", required: true, placeholder: "Identity and Access Management" },
            { name: "description", label: "Descrição", type: "textarea", required: true, minLength: 3 },
            { name: "objective", label: "Objetivo", type: "textarea" },
            { name: "review_frequency_days", label: "Revisão a cada (dias)", type: "number", defaultValue: "365" },
          ],
        },
        {
          title: "Nova avaliação de controlo",
          endpoint: "/grc/control-assessments",
          fields: [
            { name: "control_id", label: "Controlo", type: "select", required: true, optionsFrom: { path: "/grc/controls", label: "title" } },
            { name: "result", label: "Resultado", type: "select", required: true, defaultValue: "not_assessed", options: [["effective", "Eficaz"], ["partially_effective", "Parcialmente eficaz (gap)"], ["ineffective", "Ineficaz (gap)"], ["not_applicable", "Não aplicável"], ["not_assessed", "Não avaliado"]] },
            { name: "effectiveness", label: "Eficácia (0 a 1)", type: "number", defaultValue: "0", help: "0 = nenhuma, 1 = total" },
            { name: "notes", label: "Notas da avaliação", type: "textarea" },
          ],
        },
      ]}
    />
  );
}
