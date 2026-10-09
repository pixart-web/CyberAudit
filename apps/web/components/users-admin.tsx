"use client";

import { Badge, Button, Card, EmptyState, ErrorState } from "@cyberaudit/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { CreateForm } from "@/components/create-form";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type UserRow = {
  id: string;
  name: string;
  email: string;
  status: string;
  roles: string[];
  mfa_enabled: boolean;
  last_login_at: string | null;
};
type Roles = { items: { name: string; description: string }[] };

export function UsersAdmin() {
  const queryClient = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [resetting, setResetting] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [notice, setNotice] = useState<string | null>(null);

  const users = useQuery({ queryKey: ["/users"], queryFn: () => api<{ items: UserRow[]; total: number }>("/users?page_size=100") });
  const roles = useQuery({ queryKey: ["/roles"], queryFn: () => api<Roles>("/roles") });
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["/users"] });

  const patch = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, string> }) =>
      api(`/users/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: () => {
      setNotice("Utilizador atualizado.");
      refresh();
    },
  });
  const reset = useMutation({
    mutationFn: ({ id, value }: { id: string; value: string }) =>
      api(`/users/${id}/reset-password`, { method: "POST", body: JSON.stringify({ password: value }) }),
    onSuccess: () => {
      setNotice("Palavra-passe redefinida; sessões revogadas. O utilizador terá de a alterar.");
      setResetting(null);
      setPassword("");
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api<{ revoked: number }>(`/users/${id}/revoke-sessions`, { method: "POST" }),
    onSuccess: (r) => setNotice(`${r.revoked} sessão(ões) revogada(s).`),
  });
  const failure = (patch.error ?? reset.error ?? revoke.error) as Error | null;

  return (
    <Shell title="Utilizadores">
      {creating && (
        <CreateForm
          className="mb-4"
          title="Novo utilizador"
          endpoint="/users"
          invalidate={["/users"]}
          fields={[
            { name: "name", label: "Nome", required: true, minLength: 2 },
            { name: "email", label: "Email", type: "email", required: true },
            { name: "password", label: "Palavra-passe inicial", type: "password", required: true, minLength: 14, help: "Mínimo 14 caracteres, três classes de caracteres. O utilizador deve alterá-la." },
            { name: "role", label: "Perfil", type: "select", required: true, defaultValue: "Auditor", optionsFrom: { path: "/roles", value: "name", label: "name" } },
          ]}
        />
      )}
      <Card className="overflow-hidden">
        <div className="flex items-center justify-between border-b border-border p-4">
          <span className="text-sm text-muted">{users.data?.total ?? 0} utilizadores</span>
          <Button type="button" aria-expanded={creating} onClick={() => setCreating((v) => !v)}>
            {creating ? "Fechar" : "Novo utilizador"}
          </Button>
        </div>
        {(failure || notice) && (
          <p role={failure ? "alert" : "status"} className={`px-4 pt-3 text-sm ${failure ? "text-critical" : "text-green-300"}`}>
            {failure ? failure.message : notice}
          </p>
        )}
        {users.error ? (
          <ErrorState title="Sem permissão ou serviço indisponível." />
        ) : (
          <div className="overflow-x-auto">
            <table className="table">
              <caption className="sr-only">Utilizadores da organização</caption>
              <thead>
                <tr>
                  <th>Nome</th>
                  <th>Email</th>
                  <th>Perfil</th>
                  <th>Estado</th>
                  <th>Último acesso</th>
                  <th>Ações</th>
                </tr>
              </thead>
              <tbody>
                {users.data?.items.map((u) => (
                  <tr key={u.id}>
                    <td>{u.name}</td>
                    <td>{u.email}</td>
                    <td>
                      <select
                        className="field h-8 text-xs"
                        aria-label={`Perfil de ${u.name}`}
                        value={u.roles[0] ?? ""}
                        onChange={(e) => patch.mutate({ id: u.id, body: { role: e.target.value } })}
                      >
                        {!u.roles[0] && <option value="">—</option>}
                        {roles.data?.items.map((r) => (
                          <option key={r.name} value={r.name}>
                            {r.name}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <Badge tone={u.status === "active" ? "success" : "warning"}>{u.status === "active" ? "Ativo" : "Desativado"}</Badge>
                    </td>
                    <td className="text-xs text-muted">{u.last_login_at ? new Date(u.last_login_at).toLocaleString("pt-PT") : "Nunca"}</td>
                    <td>
                      <div className="flex flex-wrap gap-2">
                        <button
                          type="button"
                          className="text-xs text-cyan hover:underline"
                          onClick={() => patch.mutate({ id: u.id, body: { status: u.status === "active" ? "disabled" : "active" } })}
                        >
                          {u.status === "active" ? "Desativar" : "Ativar"}
                        </button>
                        <button type="button" className="text-xs text-cyan hover:underline" onClick={() => setResetting(resetting === u.id ? null : u.id)}>
                          Redefinir palavra-passe
                        </button>
                        <button type="button" className="text-xs text-cyan hover:underline" onClick={() => revoke.mutate(u.id)}>
                          Revogar sessões
                        </button>
                      </div>
                      {resetting === u.id && (
                        <form
                          className="mt-2 flex gap-2"
                          onSubmit={(e) => {
                            e.preventDefault();
                            reset.mutate({ id: u.id, value: password });
                          }}
                        >
                          <input
                            type="password"
                            autoComplete="new-password"
                            aria-label={`Nova palavra-passe para ${u.name}`}
                            className="field h-8 text-xs"
                            value={password}
                            minLength={14}
                            onChange={(e) => setPassword(e.target.value)}
                          />
                          <Button type="submit" className="text-xs" disabled={reset.isPending}>
                            Aplicar
                          </Button>
                        </form>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {users.data?.items.length === 0 && <EmptyState title="Ainda não existem utilizadores." />}
          </div>
        )}
      </Card>
    </Shell>
  );
}
