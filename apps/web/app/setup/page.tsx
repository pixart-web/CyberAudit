"use client";

import { Card } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";
import { CreateForm } from "@/components/create-form";
import { api } from "@/lib/api";

export default function SetupPage() {
  const [created, setCreated] = useState(false);
  const status = useQuery({ queryKey: ["setup-status"], queryFn: () => api<{ initialized: boolean; bootstrap_enabled: boolean }>("/setup/status"), retry: false });

  return (
    <main className="mx-auto max-w-2xl p-6">
      <h1 className="mb-1 text-xl font-semibold">Configuração inicial do CyberAudit</h1>
      <p className="mb-6 text-sm text-muted">Cria a primeira organização e o administrador da plataforma. Só está disponível uma vez, enquanto não existirem utilizadores.</p>
      {status.isLoading && <p role="status">A verificar estado…</p>}
      {status.error && <p role="alert" className="text-critical">Serviço indisponível.</p>}
      {status.data?.initialized && (
        <Card className="p-5">
          <p>A instalação já está configurada. <Link className="text-cyan underline" href="/login">Iniciar sessão</Link></p>
        </Card>
      )}
      {status.data && !status.data.initialized && !status.data.bootstrap_enabled && (
        <Card className="p-5">
          <p>A configuração inicial está desativada. O operador tem de definir o segredo <code>BOOTSTRAP_TOKEN</code> no servidor.</p>
        </Card>
      )}
      {status.data?.bootstrap_enabled && !created && (
        <CreateForm
          title="Organização e administrador"
          endpoint="/setup/initialize"
          submitLabel="Concluir configuração"
          onCreated={() => setCreated(true)}
          fields={[
            { name: "bootstrap_token", label: "Token de configuração", type: "password", required: true, minLength: 16, help: "Fornecido pelo operador (variável BOOTSTRAP_TOKEN)" },
            { name: "name", label: "Nome da organização", required: true },
            { name: "slug", label: "Identificador", required: true, help: "Minúsculas, números e hífens" },
            { name: "admin_name", label: "Nome do administrador", required: true },
            { name: "admin_email", label: "Email do administrador", type: "email", required: true },
            { name: "admin_password", label: "Palavra-passe", type: "password", required: true, minLength: 14 },
          ]}
        />
      )}
      {created && (
        <Card className="p-5">
          <p>Configuração concluída. <Link className="text-cyan underline" href="/login">Iniciar sessão</Link></p>
        </Card>
      )}
    </main>
  );
}
