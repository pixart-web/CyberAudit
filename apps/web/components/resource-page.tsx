"use client";

import { Card, Button, ConfirmationDialog, EmptyState, ErrorState, SeverityBadge } from "@cyberaudit/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Search } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { CreateForm, type FieldSpec } from "@/components/create-form";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type PageResponse = { items: Record<string, unknown>[]; total: number; page: number; page_size: number };

const SEVERITY_LIKE_KEYS = new Set(["status", "result", "severity", "risk_level", "technical_severity"]);

export type RowActions = {
  edit?: { title: string; fields: FieldSpec[]; path: (id: string) => string; values: (item: Record<string, unknown>) => Record<string, string> };
  archive?: { path: (id: string) => string; confirmTitle: string; confirmDescription: string };
};

export type CreateSpec = { title: string; fields: FieldSpec[]; endpoint?: string; multipart?: boolean; submitLabel?: string };

export function ResourcePage({ title, endpoint, createHref, rowHref, columns, create, rowActions }: { title: string; endpoint: string; createHref?: string; rowHref?: string; columns: [string, string][]; create?: CreateSpec | CreateSpec[]; rowActions?: RowActions }) {
  const specs = create ? (Array.isArray(create) ? create : [create]) : [];
  const [q, setQ] = useState("");
  const [creating, setCreating] = useState<number | null>(null);
  const [editing, setEditing] = useState<Record<string, unknown> | null>(null);
  const [archiving, setArchiving] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const archive = useMutation({
    mutationFn: (id: string) => api<void>(rowActions!.archive!.path(id), { method: "DELETE" }),
    onSuccess: () => {
      setArchiving(null);
      queryClient.invalidateQueries({ queryKey: [endpoint] });
    },
  });
  const { data, isLoading, error } = useQuery({ queryKey: [endpoint, q], queryFn: () => api<PageResponse>(`${endpoint}?q=${encodeURIComponent(q)}`) });
  return <Shell title={title}>
    {rowActions?.edit && editing && <CreateForm key={String(editing.id)} className="mb-4" title={`${rowActions.edit.title}: ${String(editing[columns[0][0]] ?? "")}`} endpoint={rowActions.edit.path(String(editing.id))} method="PATCH" fields={rowActions.edit.fields} initialValues={rowActions.edit.values(editing)} invalidate={[endpoint]} submitLabel="Guardar" onCancel={() => setEditing(null)} onCreated={() => setEditing(null)} />}
    {archive.error && <p role="alert" className="mb-3 text-sm text-critical">{(archive.error as Error).message}</p>}
    {rowActions?.archive && <ConfirmationDialog open={archiving !== null} title={rowActions.archive.confirmTitle} description={rowActions.archive.confirmDescription} confirmLabel="Arquivar" destructive onConfirm={() => archiving && archive.mutate(archiving)} onCancel={() => setArchiving(null)} />}
    {specs.map((spec, index) => creating === index && <CreateForm key={spec.title} className="mb-4" title={spec.title} endpoint={spec.endpoint ?? endpoint} fields={spec.fields} multipart={spec.multipart} submitLabel={spec.submitLabel} invalidate={[endpoint]} />)}
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-border p-4">
        <label className="relative flex-1"><Search size={16} className="absolute left-3 top-3 text-muted"/><input value={q} onChange={event=>setQ(event.target.value)} className="field max-w-md pl-9" placeholder={`Pesquisar ${title.toLowerCase()}`} /></label>
        {createHref && <Link href={createHref}><Button><Plus size={16}/>Criar</Button></Link>}
        {specs.map((spec, index) => <Button key={spec.title} type="button" aria-expanded={creating === index} onClick={()=>setCreating(v=>v === index ? null : index)}><Plus size={16}/>{creating === index ? "Fechar" : spec.title}</Button>)}
      </div>
      {error ? <ErrorState /> :
      <div className="overflow-x-auto"><table className="table"><thead><tr>{columns.map(([key,label])=><th key={key}>{label}</th>)}{rowActions && <th>Ações</th>}</tr></thead><tbody>
        {isLoading && <tr><td colSpan={columns.length} className="text-muted" role="status">A carregar…</td></tr>}
        {data?.items.map((item,index)=><tr key={String(item.id ?? index)}>{columns.map(([key], columnIndex)=><td key={key}>{columnIndex === 0 && rowHref ? <Link className="font-semibold text-cyan hover:underline" href={`${rowHref}/${item.id}`}>{String(item[key] ?? "—")}</Link> : SEVERITY_LIKE_KEYS.has(key) ? <SeverityBadge state={String(item[key] ?? "unknown")} /> : key === "created_at" ? new Intl.DateTimeFormat("pt-PT",{dateStyle:"medium",timeStyle:"short"}).format(new Date(String(item[key]))) : typeof item[key] === "boolean" ? (item[key] ? "Sim" : "Não") : String(item[key] ?? "—")}</td>)}{rowActions && <td><div className="flex gap-3">{rowActions.edit && <button type="button" className="text-xs text-cyan hover:underline" aria-label={`Editar ${String(item[columns[0][0]] ?? "")}`} onClick={()=>setEditing(item)}>Editar</button>}{rowActions.archive && <button type="button" className="text-xs text-cyan hover:underline" aria-label={`Arquivar ${String(item[columns[0][0]] ?? "")}`} onClick={()=>setArchiving(String(item.id))}>Arquivar</button>}</div></td>}</tr>)}
      </tbody></table>
      {!isLoading && data?.items.length === 0 && <EmptyState title="Ainda não existem registos." />}
      </div>}
      <div className="flex items-center justify-between border-t border-border p-4 text-xs text-muted"><span>{data?.total ?? 0} registos</span><span>Página {data?.page ?? 1}</span></div>
    </Card>
  </Shell>;
}
