"use client";

import { ResourcePage } from "@/components/resource-page";

const ENGAGEMENT = { path: "/engagements", label: "name" } as const;

export default function Page() {
  return (
    <ResourcePage
      title="Inventário de Ativos"
      endpoint="/assets"
      rowHref="/assets"
      columns={[["name", "Nome"], ["asset_type", "Tipo"], ["primary_ip", "IP principal"], ["environment_id", "Ambiente"], ["internet_exposed", "Internet"], ["risk_score", "Risco"], ["status", "Estado"]]}
      create={{
        title: "Novo ativo",
        fields: [
          { name: "engagement_id", label: "Auditoria", type: "select", required: true, optionsFrom: ENGAGEMENT },
          { name: "name", label: "Nome", required: true },
          { name: "asset_type", label: "Tipo", type: "select", required: true, options: [["host", "Servidor / Host"], ["workstation", "Posto de trabalho"], ["web_application", "Aplicação web"], ["api", "API"], ["database", "Base de dados"], ["network_device", "Equipamento de rede"], ["cloud_resource", "Recurso cloud"]] },
          { name: "identifier", label: "Identificador único", required: true, help: "Ex.: hostname, ID cloud ou URL canónico" },
          { name: "hostname", label: "Hostname" },
          { name: "ip_address", label: "Endereço IP" },
          { name: "domain", label: "Domínio" },
          { name: "operating_system", label: "Sistema operativo" },
          { name: "owner", label: "Responsável" },
          { name: "criticality", label: "Criticidade", type: "select", defaultValue: "medium", options: [["low", "Baixa"], ["medium", "Média"], ["high", "Alta"], ["critical", "Crítica"]] },
        ],
      }}
    />
  );
}
