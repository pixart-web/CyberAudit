"use client";

import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return (
    <ResourcePage
      title="Case Management"
      endpoint="/cases"
      rowHref="/cases"
      columns={[["reference", "Referência"], ["title", "Caso"], ["status", "Estado"], ["lead_investigator_id", "Investigador"], ["legal_hold", "Legal hold"]]}
      create={{
        title: "Novo caso",
        fields: [
          { name: "incident_id", label: "Incidente", type: "select", required: true, optionsFrom: { path: "/incidents", label: "title" } },
          { name: "title", label: "Título", required: true, minLength: 3 },
          { name: "hypothesis", label: "Hipótese de investigação", type: "textarea" },
        ],
      }}
    />
  );
}
