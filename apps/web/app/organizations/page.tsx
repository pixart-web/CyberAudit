"use client";

import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return (
    <ResourcePage
      title="Organização"
      endpoint="/organizations"
      columns={[["name", "Nome"], ["slug", "Identificador"], ["status", "Estado"], ["created_at", "Criada em"]]}
      create={{
        title: "Nova organização (plataforma)",
        endpoint: "/platform/organizations",
        fields: [
          { name: "name", label: "Nome da organização", required: true, minLength: 2 },
          { name: "slug", label: "Identificador", required: true, help: "Minúsculas, números e hífens" },
          { name: "admin_name", label: "Nome do administrador", required: true },
          { name: "admin_email", label: "Email do administrador", type: "email", required: true },
          { name: "admin_password", label: "Palavra-passe inicial", type: "password", required: true, minLength: 14 },
        ],
        submitLabel: "Criar organização",
      }}
    />
  );
}
