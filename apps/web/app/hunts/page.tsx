"use client";

import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return (
    <ResourcePage
      title="Threat Hunting"
      endpoint="/hunts"
      rowHref="/hunts"
      columns={[["name", "Hunt"], ["hypothesis", "Hipótese"], ["status", "Estado"], ["result_count", "Resultados"], ["time_from", "Desde"], ["time_until", "Até"]]}
      create={{
        title: "Nova hunt",
        fields: [
          { name: "name", label: "Nome", required: true, minLength: 3 },
          { name: "hypothesis", label: "Hipótese", type: "textarea", required: true, minLength: 10 },
          { name: "time_from", label: "Desde", type: "datetime", required: true },
          { name: "time_until", label: "Até", type: "datetime", required: true },
        ],
      }}
    />
  );
}
