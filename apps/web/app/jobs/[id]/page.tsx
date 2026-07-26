"use client";

import { Badge, Button, Card } from "@cyberaudit/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban, Clock3, RotateCcw } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Job={id:string;status:string;progress:number;status_message:string;engagement_id:string;scope_id:string;target_value:string;adapter_code:string;intensity:string;created_at:string;started_at?:string;completed_at?:string;result_summary:Record<string,unknown>;error_code?:string;error_message?:string};
type Event={id:string;event_type:string;severity:string;message:string;created_at:string;event_metadata:Record<string,unknown>};
type Results={summary:Record<string,unknown>;findings:{id:string;title:string;technical_severity:string;simulated:boolean;imported:boolean}[]};
type EvidencePage={items:{id:string;title:string;evidence_type:string;redacted:boolean}[]};
const cancellable=["pending_approval","queued","starting","running"];
const retryable=["failed","timed_out","cancelled","completed_with_warnings"];

export default function JobDetail(){
  const {id}=useParams<{id:string}>();const client=useQueryClient();
  const job=useQuery({queryKey:["job",id],queryFn:()=>api<Job>(`/jobs/${id}`),refetchInterval:q=>["completed","completed_with_warnings","failed","timed_out","cancelled","denied"].includes(q.state.data?.status??"")?false:1500});
  const events=useQuery({queryKey:["job-events",id],queryFn:()=>api<Event[]>(`/jobs/${id}/events`),refetchInterval:2000});
  const results=useQuery({queryKey:["job-results",id],queryFn:()=>api<Results>(`/jobs/${id}/results`),enabled:!!job.data});
  const evidence=useQuery({queryKey:["job-evidence",id],queryFn:()=>api<EvidencePage>(`/evidence?job_id=${id}`),enabled:!!job.data});
  const action=useMutation({mutationFn:(kind:"cancel"|"retry")=>api(`/jobs/${id}/${kind}`,{method:"POST"}),onSuccess:()=>{client.invalidateQueries({queryKey:["job",id]});client.invalidateQueries({queryKey:["job-events",id]})}});
  const data=job.data;
  return <Shell title="Detalhe do Job">{!data?<Card className="p-8 text-muted">A carregar job…</Card>:<>
    <div className="mb-4 flex flex-wrap items-center gap-3"><Badge tone={data.status==="completed"?"success":data.status==="failed"||data.status==="denied"?"danger":data.status==="pending_approval"?"warning":"info"}>{data.status}</Badge><span className="font-mono text-xs text-muted">{data.id}</span><div className="ml-auto flex gap-2">{cancellable.includes(data.status)&&<Button className="button-secondary" onClick={()=>action.mutate("cancel")}><Ban size={15}/>Cancelar</Button>}{retryable.includes(data.status)&&<Button onClick={()=>action.mutate("retry")}><RotateCcw size={15}/>Repetir</Button>}</div></div>
    <Card className="p-5"><div className="flex items-center justify-between"><div><small className="text-muted">Progresso</small><b className="ml-2">{data.progress}%</b></div><span className="text-sm text-muted">{data.status_message}</span></div><div className="mt-3 h-2 overflow-hidden rounded-full bg-surface"><div className="h-full rounded-full bg-primary transition-all" style={{width:`${data.progress}%`}}/></div></Card>
    <div className="mt-4 grid gap-4 lg:grid-cols-3"><div className="space-y-4 lg:col-span-2"><Card className="p-5"><h2 className="font-semibold">Contexto de execução</h2><dl className="mt-4 grid gap-4 md:grid-cols-2"><Info l="Alvo" v={data.target_value}/><Info l="Adaptador" v={data.adapter_code}/><Info l="Intensidade" v={data.intensity}/><Info l="Scope" v={data.scope_id}/><Info l="Criado" v={new Intl.DateTimeFormat("pt-PT",{dateStyle:"medium",timeStyle:"short"}).format(new Date(data.created_at))}/><Info l="Resultado" v={JSON.stringify(data.result_summary)}/></dl>{data.error_code&&<div className="mt-4 rounded-lg border border-critical/30 bg-critical/10 p-3 text-sm text-red-300"><b>{data.error_code}</b><p>{data.error_message}</p></div>}</Card><Card className="p-5"><h2 className="font-semibold">Findings e evidências</h2><div className="mt-4 grid gap-3 md:grid-cols-2">{results.data?.findings.map(finding=><Link key={finding.id} href={`/findings/${finding.id}`} className="rounded-lg border border-border bg-surface p-3 text-sm hover:border-primary/30"><b>{finding.title}</b><small className="mt-1 block text-muted">{finding.technical_severity}{finding.simulated?" · simulado":finding.imported?" · importado":" · observado"}</small></Link>)}{evidence.data?.items.map(item=><Link key={item.id} href={`/evidence/${item.id}`} className="rounded-lg border border-border bg-surface p-3 text-sm hover:border-primary/30"><b>{item.title}</b><small className="mt-1 block text-muted">{item.evidence_type}{item.redacted?" · redigida":""}</small></Link>)}</div>{results.data?.findings.length===0&&evidence.data?.items.length===0&&<p className="mt-3 text-sm text-muted">Ainda não existem resultados.</p>}</Card></div>
    <Card className="p-5"><h2 className="flex items-center gap-2 font-semibold"><Clock3 size={16} className="text-primary"/>Eventos</h2><div className="mt-4 space-y-4">{events.data?.map(event=><div key={event.id} className="relative border-l border-border pl-4"><span className="absolute -left-1 top-1 h-2 w-2 rounded-full bg-primary"/><b className="block text-sm">{event.message}</b><small className="text-muted">{event.event_type} · {new Intl.DateTimeFormat("pt-PT",{timeStyle:"medium"}).format(new Date(event.created_at))}</small></div>)}</div></Card></div>
  </>}</Shell>;
}
function Info({l,v}:{l:string;v:string}){return <div><dt className="text-xs text-muted">{l}</dt><dd className="mt-1 break-all text-sm">{v}</dd></div>}
