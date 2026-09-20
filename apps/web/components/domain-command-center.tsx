"use client";

import { Badge, Card } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Cloud, Fingerprint, Network, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type PageData = { items?: Record<string, unknown>[]; total?: number };
type CenterKind = "identity" | "cloud" | "kubernetes" | "endpoint" | "mobile" | "zero-trust";

const centers: Record<
  CenterKind,
  {
    title: string;
    eyebrow: string;
    endpoint: string;
    postureEndpoint: string;
    listHref: string;
    itemLabel: string;
    riskLabel: string;
  }
> = {
  identity: {
    title: "Identity Security Center",
    eyebrow: "Enterprise / Identity",
    endpoint: "/identity/users",
    postureEndpoint: "/identity/posture",
    listHref: "/identity/users",
    itemLabel: "Identidades observadas",
    riskLabel: "Privilegiadas",
  },
  cloud: {
    title: "Cloud Security Center",
    eyebrow: "Enterprise / Cloud",
    endpoint: "/cloud/resources",
    postureEndpoint: "/cloud/posture",
    listHref: "/cloud-security/resources",
    itemLabel: "Recursos cloud",
    riskLabel: "Exposição pública",
  },
  kubernetes: {
    title: "Kubernetes Center",
    eyebrow: "Enterprise / Workloads",
    endpoint: "/kubernetes/workloads",
    postureEndpoint: "/kubernetes/posture",
    listHref: "/kubernetes/workloads",
    itemLabel: "Workloads",
    riskLabel: "Privilegiados",
  },
  endpoint: {
    title: "Endpoint Security",
    eyebrow: "Enterprise / Devices",
    endpoint: "/endpoints",
    postureEndpoint: "/endpoints/posture",
    listHref: "/endpoint-security/devices",
    itemLabel: "Endpoints",
    riskLabel: "Não conformes",
  },
  mobile: {
    title: "Mobile Security",
    eyebrow: "Enterprise / Devices",
    endpoint: "/mobile-devices",
    postureEndpoint: "/mobile-devices/posture",
    listHref: "/mobile-security/devices",
    itemLabel: "Dispositivos móveis",
    riskLabel: "Não conformes",
  },
  "zero-trust": {
    title: "Zero Trust Center",
    eyebrow: "Enterprise / Trust",
    endpoint: "/zero-trust/assessments",
    postureEndpoint: "/zero-trust/overview",
    listHref: "/zero-trust/assessments",
    itemLabel: "Avaliações",
    riskLabel: "Confiança observada",
  },
};

function displayNumber(value: unknown): string {
  return typeof value === "number" ? new Intl.NumberFormat("pt-PT").format(value) : "—";
}

export function DomainCommandCenter({ kind }: { kind: CenterKind }) {
  const center = centers[kind];
  const inventory = useQuery({
    queryKey: ["domain-center", kind, "inventory"],
    queryFn: () => api<PageData>(`${center.endpoint}?page_size=8`),
  });
  const posture = useQuery({
    queryKey: ["domain-center", kind, "posture"],
    queryFn: () => api<Record<string, unknown>>(center.postureEndpoint),
  });
  const rows = inventory.data?.items ?? [];
  const postureData = posture.data ?? {};
  const riskValue =
    postureData.non_compliant ??
    postureData.public_resources ??
    rows.filter((item) => item.privileged === true).length;
  const score = postureData.score;

  return (
    <Shell title={center.title} eyebrow={center.eyebrow}>
      {(inventory.error || posture.error) && (
        <div role="alert" className="mb-5 rounded-xl border border-critical/30 bg-critical/10 p-4 text-sm text-red-200">
          Não foi possível carregar parte da postura. Confirma as permissões e o estado da API.
        </div>
      )}
      <section className="mb-5 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Card>
          <p className="text-xs uppercase tracking-wider text-muted">{center.itemLabel}</p>
          <p className="mt-2 text-3xl font-semibold">{displayNumber(inventory.data?.total)}</p>
          <p className="mt-2 text-xs text-muted">Inventário tenant-isolated</p>
        </Card>
        <Card>
          <p className="text-xs uppercase tracking-wider text-muted">{center.riskLabel}</p>
          <p className="mt-2 text-3xl font-semibold text-warning">{displayNumber(riskValue)}</p>
          <p className="mt-2 text-xs text-muted">Sinais observados; não são ações automáticas</p>
        </Card>
        <Card>
          <p className="text-xs uppercase tracking-wider text-muted">Zero Trust score</p>
          <p className="mt-2 text-3xl font-semibold text-cyan">
            {typeof score === "number" ? `${score.toFixed(0)}/100` : "—"}
          </p>
          <p className="mt-2 text-xs text-muted">Scoring determinístico e explicável</p>
        </Card>
        <Card>
          <p className="text-xs uppercase tracking-wider text-muted">Modo de operação</p>
          <p className="mt-3"><Badge tone="success">Read-only</Badge></p>
          <p className="mt-3 text-xs text-muted">Sem comandos ou alterações externas</p>
        </Card>
      </section>

      <section className="grid gap-5 xl:grid-cols-[1.5fr_1fr]">
        <Card className="overflow-hidden">
          <div className="flex items-center justify-between border-b border-border p-4">
            <div>
              <h2 className="font-semibold">Inventário e postura recente</h2>
              <p className="text-xs text-muted">Dados normalizados pelos conectores permitidos</p>
            </div>
            <Link href={center.listHref} className="text-sm text-cyan hover:underline">Explorar tudo</Link>
          </div>
          <div className="divide-y divide-border">
            {inventory.isLoading && <p className="p-5 text-sm text-muted">A carregar…</p>}
            {!inventory.isLoading && rows.length === 0 && (
              <p className="p-8 text-center text-sm text-muted">Ainda não existem dados de inventário.</p>
            )}
            {rows.map((row, index) => (
              <div key={String(row.id ?? index)} className="flex items-center gap-3 p-4">
                <Fingerprint size={17} className="text-primary" />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">
                    {String(row.display_name ?? row.name ?? row.hostname ?? row.subject_type ?? "Registo")}
                  </p>
                  <p className="truncate text-xs text-muted">
                    {String(row.provider ?? row.platform ?? row.object_type ?? row.status ?? "observado")}
                  </p>
                </div>
                <Badge tone={Number(row.risk_score ?? 0) >= 70 ? "warning" : "success"}>
                  {row.risk_score !== undefined ? `Risco ${row.risk_score}` : String(row.status ?? "observado")}
                </Badge>
              </div>
            ))}
          </div>
        </Card>
        <Card>
          <h2 className="font-semibold">Princípios de confiança</h2>
          <div className="mt-4 space-y-3 text-sm">
            {[
              [ShieldCheck, "Evidência antes de confiança", "Estados desconhecidos reduzem a confiança."],
              [Network, "Relações limitadas", "Grafos são paginados e nunca carregados integralmente."],
              [Cloud, "Integrações read-only", "Credenciais são apenas referências a secret managers."],
              [AlertTriangle, "Revisão humana", "Recomendações não executam alterações externas."],
            ].map(([Icon, title, description]) => {
              const ItemIcon = Icon as typeof ShieldCheck;
              return <div key={String(title)} className="flex gap-3 rounded-lg border border-border bg-white/[.015] p-3">
                <ItemIcon size={17} className="mt-0.5 shrink-0 text-cyan" />
                <div><p className="font-medium">{String(title)}</p><p className="text-xs text-muted">{String(description)}</p></div>
              </div>;
            })}
          </div>
        </Card>
      </section>
    </Shell>
  );
}
