"use client";

import { Badge, Card } from "@cyberaudit/ui";
import { AlertTriangle } from "lucide-react";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";

const tabs=["Visão Geral","Autorização","Âmbito","Ativos","Atividade","Definições"];
export default function Detail(){
  const {id}=useParams<{id:string}>();
  return <Shell title="Detalhe da Auditoria">
    <div className="mb-5 flex items-center gap-3 rounded-xl border border-medium/30 bg-medium/[.06] p-4"><AlertTriangle className="text-medium"/><div><b>Autorização necessária antes de qualquer avaliação</b><p className="text-sm text-muted">O motor de políticas bloqueará qualquer execução fora do âmbito ou sem autorização válida.</p></div><Badge tone="warning" className="ml-auto">pendente</Badge></div>
    <Card><div className="flex gap-1 overflow-x-auto border-b border-border px-4 pt-3">{tabs.map((tab,index)=><button key={tab} className={`whitespace-nowrap border-b-2 px-4 py-3 text-sm ${index===0?"border-primary text-primary":"border-transparent text-muted"}`}>{tab}</button>)}</div>
    <div className="grid gap-5 p-6 md:grid-cols-3"><div><small className="text-muted">Identificador</small><p className="mt-1 font-mono text-cyan">{id}</p></div><div><small className="text-muted">Estado</small><p className="mt-1"><Badge tone="warning">pending_authorization</Badge></p></div><div><small className="text-muted">Modo</small><p className="mt-1">Cliente</p></div><div className="md:col-span-3 rounded-lg border border-border bg-surface p-5"><h3 className="font-semibold">Checklist de ativação</h3><div className="mt-4 grid gap-3 md:grid-cols-4">{["Responsável atribuído","Documento válido","Scope ativo","Target autorizado"].map((item,i)=><div key={item} className="rounded-lg border border-border p-3 text-sm"><span className={i===0?"text-primary":"text-medium"}>●</span> {item}</div>)}</div></div></div></Card>
  </Shell>;
}
