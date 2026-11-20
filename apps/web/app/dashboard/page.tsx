"use client";

import {
  Badge,
  Card,
  EmptyState,
  ErrorState,
  LoadingState,
  MetricCard,
  SeverityBadge,
} from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  Boxes,
  CheckCircle2,
  FileSearch,
  Gauge,
  ShieldAlert,
} from "lucide-react";
import Link from "next/link";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { OnboardingChecklist } from "@/components/onboarding-checklist";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Dashboard = {
  metrics: {
    posture: number | null;
    assets: number;
    findings: number;
    active_engagements: number;
    retest_rate: number | null;
  };
  severity: { name: string; value: number; color: string }[];
  top_risks: { title: string; severity: string; asset: string }[];
  engagements: {
    id: string;
    name: string;
    code: string;
    status: string;
    risk: string;
  }[];
  activity: {
    action: string;
    resource_type: string;
    result: string;
    created_at: string;
  }[];
  jobs: { name: string; when: string; status: string }[];
  incidents: { time: string; title: string; tone: string }[];
  adapters: { name: string; status: string }[];
};
type CommandCenter = {
  top_assets: { id: string; name: string; risk: number }[];
};

const metrics = [
  ["Postura", "posture", Gauge, "%"],
  ["Ativos", "assets", Boxes, ""],
  ["Findings", "findings", ShieldAlert, ""],
  ["Auditorias ativas", "active_engagements", FileSearch, ""],
  ["Retestes aprovados", "retest_rate", CheckCircle2, "%"],
] as const;

function SectionHeading({
  title,
  meta,
  href,
}: {
  title: string;
  meta?: string;
  href?: string;
}) {
  return (
    <div className="flex min-h-10 items-center gap-3 border-b border-border px-4">
      <h2 className="text-xs font-semibold uppercase tracking-[.08em]">
        {title}
      </h2>
      {meta && <span className="font-mono text-[10px] text-muted">{meta}</span>}
      {href && (
        <Link
          href={href}
          className="ml-auto text-[11px] font-medium text-primary hover:underline"
        >
          Abrir vista
        </Link>
      )}
    </div>
  );
}

export default function DashboardPage() {
  const dashboard = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api<Dashboard>("/dashboard"),
  });
  const commandCenter = useQuery({
    queryKey: ["dashboard-top-assets"],
    queryFn: () => api<CommandCenter>("/command-center"),
  });
  const data = dashboard.data;
  return (
    <Shell
      title="Centro de Operações"
      eyebrow="Operations / Situational awareness"
    >
      <OnboardingChecklist />
      {dashboard.isLoading && (
        <LoadingState label="A consolidar o estado operacional…" />
      )}
      {dashboard.error && (
        <ErrorState
          title="Centro de operações indisponível"
          description="A API não devolveu dados operacionais. Consulte o Health Center antes de tomar decisões."
        />
      )}
      {data && (
        <div className="space-y-3">
          <Card className="grid divide-y divide-border overflow-hidden sm:grid-cols-2 sm:divide-x sm:divide-y-0 xl:grid-cols-5">
            {metrics.map(([label, key, Icon, suffix]) => {
              const value = data.metrics[key];
              return (
                <MetricCard
                  key={key}
                  label={label}
                  value={value == null ? "Indisponível" : `${value}${suffix}`}
                  icon={Icon}
                />
              );
            })}
          </Card>

          <div className="grid gap-3 xl:grid-cols-[minmax(0,1.45fr)_minmax(260px,.7fr)]">
            <Card className="overflow-hidden">
              <SectionHeading
                title="Ativos prioritários"
                meta={`${commandCenter.data?.top_assets.length ?? 0} observados`}
                href="/asset-graph"
              />
              <div className="divide-y divide-border">
                {commandCenter.isLoading && (
                  <LoadingState label="A carregar ativos…" />
                )}
                {commandCenter.error && (
                  <ErrorState title="Prioridade de ativos indisponível" />
                )}
                {commandCenter.data?.top_assets.map((asset, index) => (
                  <Link
                    key={asset.id}
                    href={`/assets/${asset.id}`}
                    className="grid grid-cols-[32px_minmax(0,1fr)_80px] items-center gap-3 px-4 py-3 text-sm hover:bg-white/[.025]"
                  >
                    <span className="font-mono text-[10px] text-muted">
                      {String(index + 1).padStart(2, "0")}
                    </span>
                    <span className="truncate font-medium">{asset.name}</span>
                    <span
                      className={`text-right font-mono text-sm tabular-nums ${asset.risk >= 80 ? "text-critical" : asset.risk >= 60 ? "text-warning" : "text-primary"}`}
                    >
                      {asset.risk.toFixed(1)}
                    </span>
                  </Link>
                ))}
                {commandCenter.data?.top_assets.length === 0 && (
                  <EmptyState
                    title="Sem ativos observados"
                    description="A prioridade surgirá quando existirem ativos avaliados."
                  />
                )}
              </div>
            </Card>
            <Card className="overflow-hidden">
              <SectionHeading
                title="Severidade"
                meta={`${data.severity.reduce((sum, item) => sum + item.value, 0)} findings`}
                href="/findings"
              />
              {data.severity.length ? (
                <div className="grid grid-cols-[150px_1fr] items-center px-3 py-2">
                  <div className="h-40">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={data.severity}
                          dataKey="value"
                          innerRadius={38}
                          outerRadius={58}
                          paddingAngle={2}
                          stroke="none"
                        >
                          {data.severity.map((item) => (
                            <Cell key={item.name} fill={item.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            background: "#101922",
                            border: "1px solid #273B43",
                            borderRadius: 6,
                            fontSize: 11,
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <ul className="space-y-2 text-xs">
                    {data.severity.map((item) => (
                      <li
                        key={item.name}
                        className="grid grid-cols-[8px_1fr_auto] items-center gap-2"
                      >
                        <span
                          className="h-2 w-2"
                          style={{ background: item.color }}
                        />
                        <span>{item.name}</span>
                        <b className="font-mono tabular-nums">{item.value}</b>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <EmptyState title="Sem distribuição disponível" />
              )}
            </Card>
          </div>

          <div className="grid gap-3 xl:grid-cols-3">
            <Card className="overflow-hidden xl:col-span-2">
              <SectionHeading
                title="Riscos prioritários"
                meta="Ordenação fornecida pelo motor de risco"
                href="/risk"
              />
              <div className="divide-y divide-border">
                {data.top_risks.map((risk, index) => (
                  <div
                    key={`${risk.title}-${risk.asset}`}
                    className="grid grid-cols-[32px_minmax(0,1fr)_auto] items-center gap-3 px-4 py-3"
                  >
                    <span className="font-mono text-[10px] text-muted">
                      {String(index + 1).padStart(2, "0")}
                    </span>
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium">
                        {risk.title}
                      </p>
                      <p className="truncate text-[11px] text-muted">
                        {risk.asset}
                      </p>
                    </div>
                    <SeverityBadge state={risk.severity} />
                  </div>
                ))}
                {data.top_risks.length === 0 && (
                  <EmptyState title="Sem riscos priorizados" />
                )}
              </div>
            </Card>
            <Card className="overflow-hidden">
              <SectionHeading
                title="Adaptadores"
                meta="Estado reportado"
                href="/adapters"
              />
              <div className="divide-y divide-border">
                {data.adapters.map((adapter) => (
                  <div
                    key={adapter.name}
                    className="flex items-center gap-3 px-4 py-3 text-xs"
                  >
                    <span
                      className={`h-1.5 w-1.5 ${adapter.status === "online" ? "bg-primary" : "bg-warning"}`}
                      aria-hidden
                    />
                    <span className="min-w-0 flex-1 truncate">
                      {adapter.name}
                    </span>
                    <span className="font-mono text-[10px] text-muted">
                      {adapter.status}
                    </span>
                  </div>
                ))}
                {data.adapters.length === 0 && (
                  <EmptyState title="Sem adaptadores reportados" />
                )}
              </div>
            </Card>
          </div>

          <div className="grid gap-3 xl:grid-cols-[minmax(0,1.35fr)_minmax(260px,.65fr)]">
            <Card className="overflow-hidden">
              <SectionHeading
                title="Auditorias em curso"
                meta={`${data.engagements.length} registos`}
                href="/engagements"
              />
              <div className="overflow-x-auto">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Código</th>
                      <th>Auditoria</th>
                      <th>Risco</th>
                      <th>Estado</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.engagements.map((item) => (
                      <tr key={item.id}>
                        <td>
                          <Link
                            href={`/engagements/${item.id}`}
                            className="font-mono text-[11px] text-primary hover:underline"
                          >
                            {item.code}
                          </Link>
                        </td>
                        <td>{item.name}</td>
                        <td>
                          <SeverityBadge state={item.risk} />
                        </td>
                        <td>
                          <Badge
                            tone={
                              item.status === "active" ? "success" : "warning"
                            }
                          >
                            {item.status}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {data.engagements.length === 0 && (
                  <EmptyState title="Sem auditorias em curso" />
                )}
              </div>
            </Card>
            <Card className="overflow-hidden">
              <SectionHeading
                title="Jobs"
                meta="Próxima execução / estado"
                href="/jobs"
              />
              <div className="divide-y divide-border">
                {data.jobs.map((job) => (
                  <div key={`${job.name}-${job.when}`} className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className="min-w-0 flex-1 truncate text-xs font-medium">
                        {job.name}
                      </span>
                      <SeverityBadge state={job.status} />
                    </div>
                    <p className="mt-1 font-mono text-[10px] text-muted">
                      {job.when}
                    </p>
                  </div>
                ))}
                {data.jobs.length === 0 && (
                  <EmptyState title="Sem jobs reportados" />
                )}
              </div>
            </Card>
          </div>

          <div className="grid gap-3 xl:grid-cols-2">
            <Card className="overflow-hidden">
              <SectionHeading
                title="Atividade recente"
                meta="Audit trail"
                href="/audit-logs"
              />
              <div className="divide-y divide-border">
                {data.activity.map((item, index) => (
                  <div
                    key={`${item.created_at}-${index}`}
                    className="grid grid-cols-[18px_minmax(0,1fr)_auto] items-center gap-2 px-4 py-3"
                  >
                    <Activity size={13} className="text-primary" />
                    <div className="min-w-0">
                      <p className="truncate text-xs">{item.action}</p>
                      <p className="truncate text-[10px] text-muted">
                        {item.resource_type} / {item.result}
                      </p>
                    </div>
                    <time
                      className="font-mono text-[10px] text-muted"
                      dateTime={item.created_at}
                    >
                      {new Intl.DateTimeFormat("pt-PT", {
                        day: "2-digit",
                        month: "2-digit",
                        hour: "2-digit",
                        minute: "2-digit",
                      }).format(new Date(item.created_at))}
                    </time>
                  </div>
                ))}
                {data.activity.length === 0 && (
                  <EmptyState title="Sem atividade registada" />
                )}
              </div>
            </Card>
            <Card className="overflow-hidden">
              <SectionHeading
                title="Cronologia de incidentes"
                meta="Eventos reportados"
                href="/incidents"
              />
              <div className="divide-y divide-border">
                {data.incidents.map((item, index) => (
                  <div
                    key={`${item.time}-${index}`}
                    className="grid grid-cols-[58px_10px_minmax(0,1fr)] items-center gap-3 px-4 py-3"
                  >
                    <span className="font-mono text-[10px] text-muted">
                      {item.time}
                    </span>
                    <span
                      className={`h-2 w-2 ${item.tone === "critical" ? "bg-critical" : item.tone === "warning" ? "bg-warning" : "bg-primary"}`}
                    />
                    <span className="truncate text-xs">{item.title}</span>
                  </div>
                ))}
                {data.incidents.length === 0 && (
                  <EmptyState title="Sem incidentes reportados" />
                )}
              </div>
            </Card>
          </div>
        </div>
      )}
    </Shell>
  );
}
