"use client";

import { Badge, Card } from "@cyberaudit/ui";
import { useMutation, useQuery } from "@tanstack/react-query";
import { BrainCircuit } from "lucide-react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Finding={id:string;title:string;category:string;technical_severity:string;affected_component:string;simulated:boolean;imported:boolean};
type Page<T>={items:T[];total:number};
type AgentAnswer = { response: string; citations: { source_id: string }[]; confidence: number; limitations: string[] };

export default function Reports(){
  const {data}=useQuery({queryKey:["report-findings"],queryFn:()=>api<Page<Finding>>("/findings?page_size=100")});
  const groups=(data?.items??[]).reduce<Record<string,Finding[]>>((result,item)=>{(result[item.category]??=[]).push(item);return result},{});
  const draftSummary = useMutation({
    mutationFn: () =>
      api<AgentAnswer>("/agents/report_agent/ask", {
        method: "POST",
        body: JSON.stringify({
          question: "Redige um sumário executivo dos resultados observados, estritamente a partir da evidência registada.",
          source_ids: (data?.items ?? []).map((item) => item.id).slice(0, 100),
        }),
      }),
  });
  return <Shell title="Relatório de Avaliação Segura"><div className="grid gap-4 lg:grid-cols-3"><Card className="p-6 lg:col-span-2"><div className="mb-4 flex items-center justify-between"><h2 className="text-lg font-semibold">Resultados observados</h2><button type="button" className="inline-flex items-center gap-2 rounded-lg border border-border bg-surface px-4 py-2 text-sm font-medium hover:border-primary disabled:opacity-50" onClick={()=>draftSummary.mutate()} disabled={draftSummary.isPending}><BrainCircuit size={16} className="text-primary"/>{draftSummary.isPending?"A redigir…":"Draft Executive Summary"}</button></div>{draftSummary.data&&<div className="mb-5 space-y-2 rounded-lg border border-border bg-surface p-4 text-sm"><p>{draftSummary.data.response}</p>{draftSummary.data.citations.length>0&&<p className="text-xs text-muted">Fontes: {draftSummary.data.citations.map((c)=>c.source_id).join(", ")}</p>}<p className="text-xs text-muted">Confiança: {(draftSummary.data.confidence*100).toFixed(0)}%</p>{draftSummary.data.limitations.length>0&&<ul className="list-disc pl-4 text-xs text-muted">{draftSummary.data.limitations.map((l,i)=><li key={i}>{l}</li>)}</ul>}</div>}<p className="mt-2 text-sm text-muted">Síntese de inventário, DNS, TLS, HTTP, tecnologias e configuração pública. Evidências importadas permanecem identificadas como não verificadas.</p><div className="mt-5 space-y-5">{Object.entries(groups).map(([category,items])=><section key={category}><h3 className="border-b border-border pb-2 font-semibold">{category}</h3>{items?.map(item=><div key={item.id} className="flex items-center gap-3 py-2 text-sm"><span>{item.title}</span>{item.simulated&&<Badge tone="info">simulado</Badge>}{item.imported&&<Badge tone="warning">importado</Badge>}<Badge className="ml-auto" tone={["high","critical"].includes(item.technical_severity)?"danger":"warning"}>{item.technical_severity}</Badge></div>)}</section>)}</div></Card><div className="space-y-4"><Card className="p-5"><h3 className="font-semibold">Limitações</h3><ul className="mt-3 space-y-2 text-sm text-muted"><li>• Sem exploração ou autenticação.</li><li>• Sem enumeração de diretórios ou subdomínios.</li><li>• Sem expansão automática do âmbito.</li><li>• Requests, bytes, redirects e duração limitados.</li></ul></Card><Card className="p-5"><h3 className="font-semibold">Âmbito do relatório</h3><p className="mt-3 text-sm text-muted">{data?.total??0} findings. Consulte cada job para pedidos, duração, bloqueios de scope e evidências sanitizadas.</p></Card></div></div></Shell>
}
