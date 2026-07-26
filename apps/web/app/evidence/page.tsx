"use client";

import { Badge, Card } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Evidence={id:string;title:string;evidence_type:string;sensitivity:string;redacted:boolean;collected_by_adapter:string;collected_at:string};
type Page<T>={items:T[];total:number};

export default function EvidencePage(){
  const {data,isLoading,error}=useQuery({queryKey:["evidence"],queryFn:()=>api<Page<Evidence>>("/evidence")});
  return <Shell title="Evidências"><Card className="overflow-hidden"><div className="overflow-x-auto"><table className="table"><thead><tr><th>Título</th><th>Tipo</th><th>Sensibilidade</th><th>Redação</th><th>Adaptador</th><th>Recolhida</th></tr></thead><tbody>
    {isLoading&&<tr><td colSpan={6} className="text-muted">A carregar…</td></tr>}
    {error&&<tr><td colSpan={6} className="text-red-300">Não foi possível carregar evidências.</td></tr>}
    {data?.items.map(item=><tr key={item.id}><td><Link className="font-medium text-cyan hover:underline" href={`/evidence/${item.id}`}>{item.title}</Link></td><td>{item.evidence_type}</td><td><Badge tone={item.sensitivity==="restricted"?"danger":"info"}>{item.sensitivity}</Badge></td><td>{item.redacted?"Sim":"Não"}</td><td className="font-mono text-xs">{item.collected_by_adapter}</td><td>{new Intl.DateTimeFormat("pt-PT",{dateStyle:"short",timeStyle:"short"}).format(new Date(item.collected_at))}</td></tr>)}
    {!isLoading&&data?.items.length===0&&<tr><td colSpan={6} className="py-12 text-center text-muted">Ainda não existem evidências.</td></tr>}
  </tbody></table></div><div className="border-t border-border p-4 text-xs text-muted">{data?.total??0} registos</div></Card></Shell>
}
