"use client";

import { Badge, Card, ErrorState, LoadingState } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { CreateForm } from "@/components/create-form";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Summary = {
  edition: string;
  state: "community" | "active" | "grace" | "expired";
  license_id: string;
  capabilities: string[];
  limits: Record<string, number>;
  expires_at: string | null;
  grace_until: string | null;
  days_remaining: number | null;
  verified_at: string | null;
  read_only: boolean;
  trusted_keys_configured: boolean;
};

const STATE_LABEL: Record<Summary["state"], { text: string; tone: "success" | "warning" | "danger" | "neutral" }> = {
  community: { text: "Community (sem licença comercial)", tone: "neutral" },
  active: { text: "Ativa", tone: "success" },
  grace: { text: "Em período de tolerância (só leitura)", tone: "warning" },
  expired: { text: "Expirada (só leitura)", tone: "danger" },
};

export default function LicensePage() {
  const { data, error, isLoading } = useQuery({ queryKey: ["license-summary"], queryFn: () => api<Summary>("/license/summary"), retry: false });
  if (isLoading) return <Shell title="Licença"><LoadingState /></Shell>;
  if (error || !data) return <Shell title="Licença"><ErrorState title="Sem permissão para ver a licença ou serviço indisponível." /></Shell>;
  const state = STATE_LABEL[data.state];
  const date = (value: string | null) => (value ? new Date(value).toLocaleDateString("pt-PT") : "—");
  return (
    <Shell title="Licença">
      <Card className="mb-4 p-5">
        <div className="flex flex-wrap items-center gap-3">
          <Badge tone="info">Edição: {data.edition}</Badge>
          <Badge tone={state.tone}>{state.text}</Badge>
          {data.days_remaining !== null && data.state === "active" && <Badge tone="neutral">{data.days_remaining} dias restantes</Badge>}
        </div>
        <dl className="mt-4 grid gap-3 text-sm md:grid-cols-4">
          <div><dt className="text-xs text-muted">Identificador</dt><dd>{data.license_id}</dd></div>
          <div><dt className="text-xs text-muted">Expira em</dt><dd>{date(data.expires_at)}</dd></div>
          <div><dt className="text-xs text-muted">Tolerância até</dt><dd>{date(data.grace_until)}</dd></div>
          <div><dt className="text-xs text-muted">Assinatura verificada em</dt><dd>{date(data.verified_at)}</dd></div>
        </dl>
        <h2 className="mt-5 text-sm font-semibold">Funcionalidades incluídas</h2>
        <ul className="mt-2 flex flex-wrap gap-2">{data.capabilities.map((c) => <li key={c}><Badge tone="neutral">{c}</Badge></li>)}</ul>
        {Object.keys(data.limits).length > 0 && (
          <p className="mt-3 text-xs text-muted">Limites: {Object.entries(data.limits).map(([k, v]) => `${k}=${v}`).join(", ")}</p>
        )}
      </Card>
      {data.trusted_keys_configured ? (
        <CreateForm
          title="Importar licença assinada"
          endpoint="/license/import"
          submitLabel="Verificar e importar"
          invalidate={["license-summary"]}
          fields={[
            { name: "payload", label: "Conteúdo da licença (payload)", type: "textarea", required: true },
            { name: "signature", label: "Assinatura", type: "textarea", required: true },
          ]}
        />
      ) : (
        <Card className="p-5 text-sm text-muted">
          A importação está desativada: este servidor não tem chaves públicas do fornecedor configuradas (<code>LICENSE_TRUSTED_PUBLIC_KEYS</code>).
          Uma licença só é aceite se a assinatura Ed25519 verificar contra essas chaves e estiver emitida para esta organização.
        </Card>
      )}
    </Shell>
  );
}
