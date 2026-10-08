"use client";

import { ResourcePage } from "@/components/resource-page";

const ENGAGEMENT = { path: "/engagements", label: "name" } as const;

export default function Page() {
  return (
    <ResourcePage
      title="Âmbito"
      endpoint="/scopes"
      columns={[["name", "Nome"], ["engagement_id", "Auditoria"], ["maximum_intensity", "Intensidade"], ["status", "Estado"], ["created_at", "Criado em"]]}
      create={[
        {
          title: "Novo âmbito",
          fields: [
            { name: "engagement_id", label: "Auditoria", type: "select", required: true, optionsFrom: ENGAGEMENT },
            { name: "name", label: "Nome", required: true, minLength: 2 },
            { name: "description", label: "Descrição", type: "textarea" },
            { name: "maximum_intensity", label: "Intensidade máxima", type: "select", defaultValue: "normal", options: [["passive", "Passiva"], ["low", "Baixa"], ["normal", "Normal"], ["elevated", "Elevada"], ["intrusive", "Intrusiva"]] },
          ],
        },
        {
          title: "Novo alvo autorizado",
          endpoint: "/scope-targets",
          fields: [
            { name: "scope_id", label: "Âmbito", type: "select", required: true, optionsFrom: { path: "/scopes", label: "name" } },
            { name: "target_type", label: "Tipo de alvo", type: "select", required: true, options: [["ip", "IP"], ["cidr", "CIDR"], ["domain", "Domínio"], ["hostname", "Hostname"], ["url", "URL"], ["cloud_account", "Conta cloud"], ["repository", "Repositório"]] },
            { name: "target_value", label: "Valor", required: true, help: "Validado no servidor contra o tipo escolhido" },
            { name: "include_subdomains", label: "Incluir subdomínios", type: "checkbox" },
            { name: "notes", label: "Notas", type: "textarea" },
          ],
        },
      ]}
    />
  );
}
