"use client";

import { Card, Button, EmptyState, ErrorState, SeverityBadge } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { Plus, Search } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type PageResponse = { items: Record<string, unknown>[]; total: number; page: number; page_size: number };

const SEVERITY_LIKE_KEYS = new Set(["status", "result", "severity", "risk_level", "technical_severity"]);

export function ResourcePage({ title, endpoint, createHref, rowHref, columns }: { title: string; endpoint: string; createHref?: string; rowHref?: string; columns: [string, string][] }) {
  const [q, setQ] = useState("");
  const { data, isLoading, error } = useQuery({ queryKey: [endpoint, q], queryFn: () => api<PageResponse>(`${endpoint}?q=${encodeURIComponent(q)}`) });
  return <Shell title={title}>
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-border p-4">
        <label className="relative flex-1"><Search size={16} className="absolute left-3 top-3 text-muted"/><input value={q} onChange={event=>setQ(event.target.value)} className="field max-w-md pl-9" placeholder={`Pesquisar ${title.toLowerCase()}`} /></label>
        {createHref && <Link href={createHref}><Button><Plus size={16}/>Criar</Button></Link>}
      </div>
      {error ? <ErrorState /> :
      <div className="overflow-x-auto"><table className="table"><thead><tr>{columns.map(([key,label])=><th key={key}>{label}</th>)}</tr></thead><tbody>
        {isLoading && <tr><td colSpan={columns.length} className="text-muted" role="status">A carregar…</td></tr>}
        {data?.items.map((item,index)=><tr key={String(item.id ?? index)}>{columns.map(([key], columnIndex)=><td key={key}>{columnIndex === 0 && rowHref ? <Link className="font-semibold text-cyan hover:underline" href={`${rowHref}/${item.id}`}>{String(item[key] ?? "—")}</Link> : SEVERITY_LIKE_KEYS.has(key) ? <SeverityBadge state={String(item[key] ?? "unknown")} /> : key === "created_at" ? new Intl.DateTimeFormat("pt-PT",{dateStyle:"medium",timeStyle:"short"}).format(new Date(String(item[key]))) : typeof item[key] === "boolean" ? (item[key] ? "Sim" : "Não") : String(item[key] ?? "—")}</td>)}</tr>)}
      </tbody></table>
      {!isLoading && data?.items.length === 0 && <EmptyState title="Ainda não existem registos." />}
      </div>}
      <div className="flex items-center justify-between border-t border-border p-4 text-xs text-muted"><span>{data?.total ?? 0} registos</span><span>Página {data?.page ?? 1}</span></div>
    </Card>
  </Shell>;
}
