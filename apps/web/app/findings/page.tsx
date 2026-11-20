"use client";

import {
  Badge,
  Card,
  EmptyState,
  ErrorState,
  LoadingState,
  SeverityBadge,
} from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowDownAZ,
  ExternalLink,
  Filter,
  Search,
  ShieldAlert,
  X,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Finding = {
  id: string;
  title: string;
  description: string;
  category: string;
  affected_component: string;
  technical_severity: string;
  confidence: string;
  status: string;
  source_adapter: string;
  simulated: boolean;
  imported: boolean;
  last_seen_at: string;
};
type Page = {
  items: Finding[];
  total: number;
  page: number;
  page_size: number;
};
type Sort = "recent" | "severity" | "title";
const severityRank: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

export default function FindingsPage() {
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [sort, setSort] = useState<Sort>("recent");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const findings = useQuery({
    queryKey: ["findings-workbench", q],
    queryFn: () =>
      api<Page>(`/findings?q=${encodeURIComponent(q)}&page_size=100`),
  });
  const rows = useMemo(() => {
    const filtered = (findings.data?.items ?? []).filter(
      (item) =>
        (!severity || item.technical_severity.toLowerCase() === severity) &&
        (!status || item.status.toLowerCase() === status),
    );
    return [...filtered].sort((a, b) =>
      sort === "title"
        ? a.title.localeCompare(b.title, "pt")
        : sort === "severity"
          ? (severityRank[a.technical_severity.toLowerCase()] ?? 9) -
            (severityRank[b.technical_severity.toLowerCase()] ?? 9)
          : new Date(b.last_seen_at).getTime() -
            new Date(a.last_seen_at).getTime(),
    );
  }, [findings.data, severity, status, sort]);
  const selected =
    rows.find((item) => item.id === selectedId) ??
    findings.data?.items.find((item) => item.id === selectedId) ??
    null;
  const severities = Array.from(
    new Set(
      (findings.data?.items ?? []).map((item) =>
        item.technical_severity.toLowerCase(),
      ),
    ),
  );
  const statuses = Array.from(
    new Set(
      (findings.data?.items ?? []).map((item) => item.status.toLowerCase()),
    ),
  );

  return (
    <Shell title="Findings" eyebrow="Results / Triage workbench">
      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
          <label className="relative min-w-56 flex-1">
            <Search
              size={14}
              className="absolute left-2.5 top-2.5 text-muted"
            />
            <input
              className="field h-8 w-full pl-8 text-xs"
              value={q}
              onChange={(event) => setQ(event.target.value)}
              placeholder="Pesquisar título ou categoria"
              aria-label="Pesquisar findings"
            />
          </label>
          <span className="hidden items-center gap-1 font-mono text-[10px] uppercase text-muted md:flex">
            <Filter size={12} /> filtros locais
          </span>
          <select
            className="field field-compact h-8 min-w-32 text-xs"
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
            aria-label="Filtrar por severidade"
          >
            <option value="">Severidade: todas</option>
            {severities.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
          <select
            className="field field-compact h-8 min-w-28 text-xs"
            value={status}
            onChange={(event) => setStatus(event.target.value)}
            aria-label="Filtrar por estado"
          >
            <option value="">Estado: todos</option>
            {statuses.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
          <label className="flex items-center gap-1">
            <ArrowDownAZ size={14} className="text-muted" />
            <select
              className="field field-compact h-8 min-w-28 text-xs"
              value={sort}
              onChange={(event) => setSort(event.target.value as Sort)}
              aria-label="Ordenar findings"
            >
              <option value="recent">Mais recentes</option>
              <option value="severity">Severidade</option>
              <option value="title">Título</option>
            </select>
          </label>
        </div>

        <div
          className={`grid min-h-[580px] ${selected ? "xl:grid-cols-[minmax(0,1fr)_380px]" : "grid-cols-1"}`}
        >
          <div className="min-w-0 overflow-x-auto">
            {findings.isLoading && (
              <LoadingState label="A carregar findings…" />
            )}
            {findings.error && (
              <ErrorState title="Não foi possível carregar os findings" />
            )}
            {findings.data && (
              <>
                <table className="table">
                  <caption className="sr-only">
                    Findings devolvidos pela API para triagem
                  </caption>
                  <thead>
                    <tr>
                      <th className="w-12">Sev.</th>
                      <th>Finding</th>
                      <th>Componente</th>
                      <th>Estado</th>
                      <th>Última deteção</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((item) => (
                      <tr
                        key={item.id}
                        className={`cursor-pointer ${selectedId === item.id ? "bg-primary/[.055]" : ""}`}
                        tabIndex={0}
                        aria-selected={selectedId === item.id}
                        onClick={() => setSelectedId(item.id)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            setSelectedId(item.id);
                          }
                        }}
                      >
                        <td>
                          <SeverityBadge
                            state={item.technical_severity}
                            className="justify-center [&>svg]:hidden"
                          />
                        </td>
                        <td>
                          <div className="max-w-lg">
                            <p className="truncate text-xs font-medium">
                              {item.title}
                            </p>
                            <p className="mt-0.5 truncate font-mono text-[10px] text-muted">
                              {item.category} / {item.source_adapter}
                            </p>
                          </div>
                        </td>
                        <td className="max-w-48 truncate font-mono text-[10px]">
                          {item.affected_component || "Não indicado"}
                        </td>
                        <td>
                          <SeverityBadge state={item.status} />
                        </td>
                        <td className="whitespace-nowrap font-mono text-[10px] text-muted">
                          {new Intl.DateTimeFormat("pt-PT", {
                            dateStyle: "short",
                            timeStyle: "short",
                          }).format(new Date(item.last_seen_at))}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {rows.length === 0 && (
                  <EmptyState
                    title="Sem findings correspondentes"
                    description="Altere a pesquisa ou os filtros aplicados à página atual."
                  />
                )}
              </>
            )}
          </div>

          {selected && (
            <aside
              className="inspection-panel border-t border-border bg-surface xl:border-l xl:border-t-0"
              aria-label={`Inspeção de ${selected.title}`}
            >
              <div className="flex items-start gap-3 border-b border-border p-4">
                <ShieldAlert
                  size={17}
                  className="mt-0.5 shrink-0 text-primary"
                />
                <div className="min-w-0 flex-1">
                  <p className="blacksite-kicker">Finding selecionado</p>
                  <h2 className="mt-1 text-sm font-semibold leading-snug">
                    {selected.title}
                  </h2>
                </div>
                <button
                  className="icon-button h-7 w-7"
                  onClick={() => setSelectedId(null)}
                  aria-label="Fechar inspeção"
                >
                  <X size={14} />
                </button>
              </div>
              <div className="space-y-4 p-4">
                <div className="flex flex-wrap gap-2">
                  <SeverityBadge state={selected.technical_severity} />
                  <SeverityBadge state={selected.status} />
                  {selected.simulated && <Badge tone="info">SIMULADO</Badge>}
                  {selected.imported && <Badge tone="warning">IMPORTADO</Badge>}
                </div>
                <p className="text-xs leading-5 text-muted">
                  {selected.description || "Sem descrição devolvida pela API."}
                </p>
                <dl className="divide-y divide-border border-y border-border text-xs">
                  <InspectorValue label="Categoria" value={selected.category} />
                  <InspectorValue
                    label="Componente"
                    value={selected.affected_component || "Não indicado"}
                  />
                  <InspectorValue
                    label="Confiança"
                    value={selected.confidence}
                  />
                  <InspectorValue
                    label="Adaptador"
                    value={selected.source_adapter}
                  />
                </dl>
                <Link
                  href={`/findings/${selected.id}`}
                  className="button w-full justify-center"
                >
                  <ExternalLink size={14} />
                  Abrir investigação completa
                </Link>
              </div>
            </aside>
          )}
        </div>
        <div className="flex items-center justify-between border-t border-border px-4 py-2 font-mono text-[10px] text-muted">
          <span>
            {rows.length} visíveis / {findings.data?.total ?? 0} totais
          </span>
          <span>Até 100 registos nesta vista</span>
        </div>
      </Card>
    </Shell>
  );
}

function InspectorValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid grid-cols-[100px_1fr] gap-3 py-2">
      <dt className="text-muted">{label}</dt>
      <dd className="break-all font-mono text-[11px]">{value}</dd>
    </div>
  );
}
