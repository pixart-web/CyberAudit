"use client";

import { ResourcePage } from "@/components/resource-page";

export default function Page() {
  return (
    <ResourcePage
      title="Clientes"
      endpoint="/clients"
      columns={[["name", "Nome"], ["legal_name", "Razão social"], ["email", "Email"], ["status", "Estado"], ["created_at", "Criado em"]]}
      rowActions={{
        edit: {
          title: "Editar cliente",
          path: (id) => `/clients/${id}`,
          values: (item) => Object.fromEntries(["name", "legal_name", "tax_number", "email", "phone", "address", "status", "notes"].map((k) => [k, String(item[k] ?? "")])),
          fields: [
            { name: "name", label: "Nome", required: true, minLength: 2 },
            { name: "legal_name", label: "Razão social" },
            { name: "tax_number", label: "NIF" },
            { name: "email", label: "Email de contacto", type: "email" },
            { name: "phone", label: "Telefone" },
            { name: "address", label: "Morada" },
            { name: "status", label: "Estado", type: "select", options: [["active", "Ativo"], ["inactive", "Inativo"]] },
            { name: "notes", label: "Notas", type: "textarea" },
          ],
        },
        archive: { path: (id) => `/clients/${id}`, confirmTitle: "Arquivar este cliente?", confirmDescription: "O cliente deixa de aparecer nas listas. As auditorias, findings e evidência associados são preservados." },
      }}
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
