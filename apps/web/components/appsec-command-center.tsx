"use client";

import { Card, Badge } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { Boxes, Code2, GitBranch, KeyRound, ShieldCheck, Webhook } from "lucide-react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type CommandCenter = {
  applications: number;
  internet_exposed: number;
  apis: number;
  repositories: number;
  releases: number;
  validated_sboms: number;
  confirmed_secrets: number;
  open_exceptions: number;
  open_remediations: number;
  generated_at: string;
};

const metrics = [
  ["applications", "Aplicações", Webhook],
  ["apis", "APIs", GitBranch],
  ["repositories", "Repositórios", Code2],
  ["validated_sboms", "SBOMs validados", Boxes],
  ["confirmed_secrets", "Segredos confirmados", KeyRound],
  ["open_remediations", "Remediações abertas", ShieldCheck],
] as const;

export function AppSecCommandCenter() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["appsec-command-center"],
    queryFn: () => api<CommandCenter>("/appsec/command-center"),
  });
  return (
    <Shell title="AppSec Command Center" eyebrow="Application Security">
      {error ? (
        <Card className="border-critical/30 p-8 text-red-300">
          Não foi possível carregar a postura AppSec.
        </Card>
      ) : (
        <>
          <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            {metrics.map(([key, label, Icon]) => (
              <Card key={key} className="p-5">
                <div className="mb-4 flex items-center justify-between text-muted">
                  <span className="text-xs font-semibold uppercase tracking-wider">{label}</span>
                  <Icon size={18} />
                </div>
                <p className="text-3xl font-semibold text-foreground">
                  {isLoading ? "—" : data?.[key] ?? 0}
                </p>
              </Card>
            ))}
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card className="p-5">
              <h2 className="mb-4 font-semibold">Exposição e governação</h2>
              <dl className="space-y-3 text-sm">
                <div className="flex justify-between"><dt className="text-muted">Expostas à Internet</dt><dd>{data?.internet_exposed ?? 0}</dd></div>
                <div className="flex justify-between"><dt className="text-muted">Releases inventariadas</dt><dd>{data?.releases ?? 0}</dd></div>
                <div className="flex justify-between"><dt className="text-muted">Exceções pendentes</dt><dd><Badge tone="warning">{data?.open_exceptions ?? 0}</Badge></dd></div>
              </dl>
            </Card>
            <Card className="p-5">
              <h2 className="mb-3 font-semibold">Limites de segurança</h2>
              <p className="text-sm leading-6 text-muted">
                Inventário web limitado a pedidos seguros, especificações processadas offline,
                referências externas bloqueadas e segredos persistidos apenas como fingerprints.
              </p>
              <Badge tone="success" className="mt-4">Sem execução de código submetido</Badge>
            </Card>
          </div>
        </>
      )}
    </Shell>
  );
}
