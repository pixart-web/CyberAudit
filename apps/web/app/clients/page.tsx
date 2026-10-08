"use client";

import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return (
    <ResourcePage
      title="Clientes"
      endpoint="/clients"
      columns={[["name", "Nome"], ["legal_name", "Razão social"], ["email", "Email"], ["status", "Estado"], ["created_at", "Criado em"]]}
      create={{
        title: "Novo cliente",
        fields: [
          { name: "name", label: "Nome", required: true, minLength: 2 },
          { name: "legal_name", label: "Razão social" },
          { name: "tax_number", label: "NIF" },
          { name: "email", label: "Email de contacto", type: "email" },
          { name: "phone", label: "Telefone" },
          { name: "address", label: "Morada" },
          { name: "notes", label: "Notas", type: "textarea" },
        ],
      }}
    />
  );
}
