"use client";

import { Card } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { CreateForm } from "@/components/create-form";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Me = { name: string; email: string; roles: string[]; must_change_password: boolean; mfa_enabled: boolean; last_login_at: string | null };

export default function AccountPage() {
  const router = useRouter();
  const me = useQuery({ queryKey: ["me-account"], queryFn: () => api<Me>("/auth/me") });
  const [changed, setChanged] = useState(false);
  const forced = me.data?.must_change_password && !changed;
  return (
    <Shell title="A minha conta">
      {forced && (
        <Card className="mb-4 border-warning/40 p-4 text-sm" role="alert">
          Por segurança, tem de definir uma nova palavra-passe antes de continuar a usar a plataforma.
        </Card>
      )}
      <Card className="mb-4 p-5 text-sm">
        <dl className="grid gap-3 md:grid-cols-4">
          <div><dt className="text-xs text-muted">Nome</dt><dd>{me.data?.name ?? "—"}</dd></div>
          <div><dt className="text-xs text-muted">Email</dt><dd>{me.data?.email ?? "—"}</dd></div>
          <div><dt className="text-xs text-muted">Perfil</dt><dd>{me.data?.roles?.join(", ") || "—"}</dd></div>
          <div><dt className="text-xs text-muted">MFA</dt><dd>{me.data ? (me.data.mfa_enabled ? "Ativo" : "Não ativo") : "—"}</dd></div>
        </dl>
      </Card>
      <CreateForm
        title="Alterar palavra-passe"
        endpoint="/auth/change-password"
        submitLabel="Alterar palavra-passe"
        fields={[
          { name: "current_password", label: "Palavra-passe atual", type: "password", required: true },
          { name: "new_password", label: "Nova palavra-passe", type: "password", required: true, minLength: 14, help: "Mínimo 14 caracteres, três classes de caracteres, sem o seu email." },
        ]}
        onCreated={() => {
          setChanged(true);
          setTimeout(() => router.push("/dashboard"), 800);
        }}
      />
    </Shell>
  );
}
