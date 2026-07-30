"use client";

import { Badge, Card } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import {
  DatabaseBackup,
  Flag,
  Fingerprint,
  Gauge,
  HardDrive,
  KeyRound,
  Radio,
  ServerCog,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type OperationsHealth = {
  status: string;
  environment: string;
  configuration: string;
  authentication: string;
  secret_provider: string;
  object_storage: string;
  runner: string;
  active_sessions: number;
  backup_records: number;
  backup_readiness: string;
  restore_readiness: string;
};
type Collection<T> = { items: T[]; total: number };
type Flag = { id: string; code: string; description: string; enabled: boolean; environment: string };
type Slo = { id: string; code: string; service: string; target: number; status: string };
type License = { edition: string; provider: string; status: string; capabilities: string[] };
type ReadinessCheck = {
  code: string;
  status: string;
  summary?: string;
  observed_at?: string;
  evidence_references?: string[];
};
type Readiness = {
  state: "blocked" | "incomplete" | "candidate" | "approved";
  blockers: string[];
  checks: ReadinessCheck[];
  environment: string;
  application_version: string;
  evaluated_at: string;
  formal_approval_required: boolean;
};

export default function EnterpriseSettings() {
  const health = useQuery({
    queryKey: ["operations-health"],
    queryFn: () => api<OperationsHealth>("/operations/health"),
    refetchInterval: 15_000,
  });
  const flags = useQuery({
    queryKey: ["feature-flags"],
    queryFn: () => api<Collection<Flag>>("/feature-flags"),
  });
  const slos = useQuery({
    queryKey: ["operations-slos"],
    queryFn: () => api<Collection<Slo>>("/operations/slos"),
  });
  const license = useQuery({
    queryKey: ["license"],
    queryFn: () => api<License>("/license"),
  });
  const readiness = useQuery({
    queryKey: ["production-readiness"],
    queryFn: () => api<Readiness>("/operations/production-readiness"),
    refetchInterval: 30_000,
  });
  const data = health.data;

  return (
    <Shell title="Definições Enterprise" eyebrow="Sistema / Product Hardening">
      {health.error && (
        <Card className="mb-4 border-critical/30 p-4 text-red-300">
          O estado operacional não está disponível ou a conta não possui a permissão necessária.
        </Card>
      )}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatusCard icon={ShieldCheck} label="Configuração" value={data?.configuration} />
        <StatusCard icon={Fingerprint} label="Autenticação" value={data?.authentication} />
        <StatusCard icon={KeyRound} label="Secret provider" value={data?.secret_provider} />
        <StatusCard icon={HardDrive} label="Object storage" value={data?.object_storage} />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card className="p-5 xl:col-span-2">
          <div className="flex items-center gap-2">
            <Gauge className="text-primary" size={18} />
            <h2 className="font-semibold">Objetivos de serviço</h2>
          </div>
          <div className="mt-4 space-y-2">
            {slos.data?.items.map((slo) => (
              <div
                key={slo.id}
                className="flex items-center justify-between rounded-lg border border-border p-3 text-sm"
              >
                <span>
                  <b>{slo.service}</b>
                  <span className="ml-2 text-muted">{slo.code}</span>
                </span>
                <span className="flex items-center gap-2">
                  <span>{slo.target}</span>
                  <Badge tone={slo.status === "met" ? "success" : "warning"}>{slo.status}</Badge>
                </span>
              </div>
            ))}
            {!slos.data?.items.length && <p className="text-sm text-muted">Sem SLOs medidos.</p>}
          </div>
        </Card>
        <Card className="p-5">
          <DatabaseBackup className="text-secondary" size={20} />
          <h2 className="mt-3 font-semibold">Continuidade</h2>
          <dl className="mt-4 space-y-3 text-sm">
            <Row label="Backups registados" value={String(data?.backup_records ?? "—")} />
            <Row label="Backup readiness" value={data?.backup_readiness ?? "—"} />
            <Row label="Restore readiness" value={data?.restore_readiness ?? "—"} />
            <Row label="Sessões ativas" value={String(data?.active_sessions ?? "—")} />
          </dl>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card className="p-5">
          <div className="flex items-center gap-2">
            <Flag className="text-primary" size={18} />
            <h2 className="font-semibold">Feature flags</h2>
          </div>
          <div className="mt-4 space-y-2">
            {flags.data?.items.map((flag) => (
              <div key={flag.id} className="rounded-lg border border-border p-3">
                <div className="flex justify-between text-sm">
                  <b>{flag.code}</b>
                  <Badge tone={flag.enabled ? "success" : "neutral"}>
                    {flag.enabled ? "ativa" : "inativa"}
                  </Badge>
                </div>
                <p className="mt-1 text-xs text-muted">{flag.description}</p>
              </div>
            ))}
            {!flags.data?.items.length && <p className="text-sm text-muted">Sem flags definidas.</p>}
          </div>
        </Card>
        <Card className="p-5">
          <Radio className="text-secondary" size={20} />
          <h2 className="mt-3 font-semibold">Edição e privacidade</h2>
          <dl className="mt-4 space-y-3 text-sm">
            <Row label="Edição" value={license.data?.edition ?? "community"} />
            <Row label="Licença" value={license.data?.status ?? "a verificar"} />
            <Row label="Fornecedor" value={license.data?.provider ?? "—"} />
            <Row label="Ambiente" value={data?.environment ?? "—"} />
            <Row label="Runner" value={data?.runner ?? "—"} />
          </dl>
          <p className="mt-4 rounded-lg border border-border bg-background/50 p-3 text-xs text-muted">
            A telemetria permanece desativada por defeito. Segredos, dados pessoais, evidências e
            conteúdos de auditoria nunca pertencem ao contrato de telemetria.
          </p>
        </Card>
      </div>

      <Card className="mt-4 p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="text-medium" size={20} />
            <div>
              <h2 className="font-semibold">Production Readiness Gate</h2>
              <p className="text-xs text-muted">
                Evidência sanitizada; o estado aprovado exige decisão formal.
              </p>
            </div>
          </div>
          <Badge tone={readiness.data?.state === "approved" ? "success" : "warning"}>
            {readiness.data?.state ?? "a verificar"}
          </Badge>
        </div>
        {readiness.error && (
          <p className="mt-4 rounded-lg border border-critical/30 p-3 text-sm text-red-300">
            O gate não está disponível ou a conta não possui a permissão necessária.
          </p>
        )}
        <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {readiness.data?.checks.map((check) => (
            <div key={check.code} className="rounded-lg border border-border p-3">
              <div className="flex items-start justify-between gap-2">
                <span className="text-xs font-medium">{check.code.replaceAll("_", " ")}</span>
                <Badge tone={check.status === "passed" ? "success" : "neutral"}>
                  {check.status}
                </Badge>
              </div>
              {check.observed_at && (
                <p className="mt-2 text-[11px] text-muted">
                  {new Intl.DateTimeFormat("pt-PT", {
                    dateStyle: "medium",
                    timeStyle: "short",
                  }).format(new Date(check.observed_at))}
                </p>
              )}
            </div>
          ))}
        </div>
        {!readiness.data?.checks.length && (
          <div className="mt-4 flex items-center gap-2 text-sm text-muted">
            <ServerCog size={16} />
            Ainda não existe evidência operacional válida.
          </div>
        )}
        {!!readiness.data?.blockers.length && (
          <p className="mt-4 text-xs text-muted">
            {readiness.data.blockers.length} bloqueadores ativos. Nenhum segredo, endpoint privado
            ou topologia sensível é apresentado nesta vista.
          </p>
        )}
      </Card>
    </Shell>
  );
}

function StatusCard({
  icon: Icon,
  label,
  value,
}: {
  icon: typeof ShieldCheck;
  label: string;
  value?: string;
}) {
  const ready = value && !["unverified", "development", "filesystem"].includes(value);
  return (
    <Card className="p-5">
      <Icon className={ready ? "text-primary" : "text-medium"} size={20} />
      <p className="mt-4 text-xs uppercase tracking-wider text-muted">{label}</p>
      <p className="mt-1 text-sm font-medium">{value ?? "a verificar"}</p>
    </Card>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-muted">{label}</dt>
      <dd className="text-right">{value}</dd>
    </div>
  );
}
