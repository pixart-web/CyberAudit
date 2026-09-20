"use client";

import { Badge, Card } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type RecordValue = Record<string, unknown>;

function value(item: unknown) {
  if (item === null || item === undefined || item === "") return "—";
  if (typeof item === "boolean") return item ? "Sim" : "Não";
  if (Array.isArray(item)) return item.length ? item.join(", ") : "—";
  if (typeof item === "object") return JSON.stringify(item);
  return String(item);
}

export function Entity360({
  title,
  endpoint,
  fields,
  children,
}: {
  title: string;
  endpoint: string;
  fields: [string, string][];
  children?: React.ReactNode;
}) {
  const { data, isLoading, error } = useQuery({
    queryKey: [endpoint],
    queryFn: () => api<RecordValue>(endpoint),
  });
  return (
    <Shell title={title} eyebrow="Application Security / 360">
      <div className="mb-4 flex gap-2 text-xs">
        <Link href={endpoint.split("/").slice(0, -1).join("/") || "/appsec"} className="text-cyan hover:underline">Voltar à lista</Link>
        <Badge tone={error ? "danger" : "success"}>{error ? "Erro API" : "Tenant isolado"}</Badge>
      </div>
      <Card className="mb-5 p-5">
        {isLoading ? <p className="text-muted">A carregar…</p> : error ? (
          <p className="text-red-300">Não foi possível carregar este recurso.</p>
        ) : (
          <dl className="grid gap-x-8 gap-y-5 sm:grid-cols-2 xl:grid-cols-3">
            {fields.map(([key, label]) => (
              <div key={key}>
                <dt className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-muted">{label}</dt>
                <dd className="break-words text-sm">{value(data?.[key])}</dd>
              </div>
            ))}
          </dl>
        )}
      </Card>
      {children}
    </Shell>
  );
}

export function RelatedTable({
  title,
  endpoint,
  columns,
}: {
  title: string;
  endpoint: string;
  columns: [string, string][];
}) {
  const { data, isLoading, error } = useQuery({
    queryKey: [endpoint],
    queryFn: () => api<RecordValue[] | { items: RecordValue[] }>(endpoint),
  });
  const items = Array.isArray(data) ? data : data?.items ?? [];
  return (
    <Card className="overflow-hidden">
      <h2 className="border-b border-border p-4 font-semibold">{title}</h2>
      {error ? <p className="p-5 text-red-300">Falha ao carregar.</p> : (
        <div className="overflow-x-auto">
          <table className="table">
            <thead><tr>{columns.map(([key, label]) => <th key={key}>{label}</th>)}</tr></thead>
            <tbody>
              {isLoading && <tr><td colSpan={columns.length}>A carregar…</td></tr>}
              {items.map((item, index) => <tr key={String(item.id ?? index)}>{columns.map(([key]) => <td key={key}>{value(item[key])}</td>)}</tr>)}
              {!isLoading && !items.length && <tr><td colSpan={columns.length} className="py-8 text-center text-muted">Sem registos relacionados.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
