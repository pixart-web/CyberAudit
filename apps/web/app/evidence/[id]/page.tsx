"use client";

import { Badge, Button, Card } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { Download } from "lucide-react";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";
import { api, getToken } from "@/lib/api";

type Evidence={id:string;title:string;description:string;evidence_type:string;sensitivity:string;redacted:boolean;mime_type:string;size_bytes:number;collected_by_adapter:string;sanitized_content?:string;evidence_metadata:Record<string,unknown>};

export default function EvidenceDetail(){
  const {id}=useParams<{id:string}>();
  const {data}=useQuery({queryKey:["evidence",id],queryFn:()=>api<Evidence>(`/evidence/${id}`)});
  const download=async()=>{const base=process.env.NEXT_PUBLIC_API_URL??"http://localhost:8000/api/v1";const response=await fetch(`${base}/evidence/${id}/download`,{headers:{Authorization:`Bearer ${getToken()}`}});if(!response.ok)return;const blob=await response.blob();const url=URL.createObjectURL(blob);const anchor=document.createElement("a");anchor.href=url;anchor.download=`evidence-${id}.txt`;anchor.click();URL.revokeObjectURL(url)};
  return <Shell title="Detalhe da Evidência">{!data?<Card className="p-8 text-muted">A carregar…</Card>:<div className="grid gap-4 lg:grid-cols-3"><Card className="p-6 lg:col-span-2"><div className="flex gap-2"><Badge tone="info">{data.evidence_type}</Badge><Badge tone={data.redacted?"warning":"success"}>{data.redacted?"Redigida":"Sem redação necessária"}</Badge></div><h2 className="mt-4 text-xl font-semibold">{data.title}</h2><p className="mt-2 text-muted">{data.description}</p><pre className="mt-5 max-h-[32rem] overflow-auto whitespace-pre-wrap rounded-lg border border-border bg-background p-4 text-xs text-muted">{data.sanitized_content||"Conteúdo disponível apenas por download autorizado."}</pre><p className="mt-3 text-xs text-muted">Preview apresentado como texto inerte. HTML, JavaScript e SVG nunca são renderizados.</p></Card><Card className="p-5"><h3 className="font-semibold">Custódia</h3><dl className="mt-4 space-y-3 text-sm"><Info l="Sensibilidade" v={data.sensitivity}/><Info l="MIME" v={data.mime_type}/><Info l="Tamanho" v={`${data.size_bytes} bytes`}/><Info l="Adaptador" v={data.collected_by_adapter}/></dl><Button className="mt-5 w-full" onClick={download}><Download size={15}/>Download autorizado</Button></Card></div>}</Shell>
}
function Info({l,v}:{l:string;v:string}){return <div><dt className="text-xs text-muted">{l}</dt><dd className="break-all">{v}</dd></div>}
