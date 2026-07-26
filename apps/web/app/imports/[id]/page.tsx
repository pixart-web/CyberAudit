"use client";

import { Badge, Button, Card } from "@cyberaudit/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Eye, XCircle } from "lucide-react";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Finding={title:string;severity:string;affected_component:string;category:string};
type Item={id:string;filename:string;format:string;status:string;size_bytes:number;preview?:{finding_count:number;format:string;findings:Finding[];warnings:string[]};confirmed_job_id?:string};

export default function ImportDetail(){
  const {id}=useParams<{id:string}>();const queryClient=useQueryClient();
  const item=useQuery({queryKey:["import",id],queryFn:()=>api<Item>(`/imports/${id}`)});
  const action=useMutation({mutationFn:(kind:"preview"|"confirm"|"cancel")=>api(`/imports/${id}/${kind}`,{method:"POST"}),onSuccess:()=>{queryClient.invalidateQueries({queryKey:["import",id]});queryClient.invalidateQueries({queryKey:["imports"]})}});
  const data=item.data;
  return <Shell title="Preview da Importação">{!data?<Card className="p-8 text-muted">A carregar…</Card>:<><Card className="p-5"><div className="flex flex-wrap items-center gap-3"><Badge tone={data.status==="confirmed"?"success":"warning"}>{data.status}</Badge><h2 className="text-lg font-semibold">{data.filename}</h2><span className="text-sm text-muted">{data.format} · {data.size_bytes} bytes</span><div className="ml-auto flex gap-2">{["uploaded","previewed"].includes(data.status)&&<Button className="button-secondary" onClick={()=>action.mutate("preview")}><Eye size={15}/>Gerar preview</Button>}{data.status==="previewed"&&<Button onClick={()=>action.mutate("confirm")}><CheckCircle2 size={15}/>Confirmar</Button>}{data.status!=="confirmed"&&data.status!=="cancelled"&&<Button className="button-secondary" onClick={()=>action.mutate("cancel")}><XCircle size={15}/>Cancelar</Button>}</div></div></Card>{data.preview&&<Card className="mt-4 overflow-hidden"><div className="border-b border-border p-4"><b>{data.preview.finding_count} findings normalizados</b><p className="text-sm text-muted">Revise antes de confirmar. Severidade e descrições importadas não são assumidas como verificadas.</p></div><table className="table"><thead><tr><th>Título</th><th>Severidade</th><th>Categoria</th><th>Componente</th></tr></thead><tbody>{data.preview.findings.slice(0,100).map((finding,index)=><tr key={`${finding.title}-${index}`}><td>{finding.title}</td><td><Badge tone={finding.severity==="critical"||finding.severity==="high"?"danger":"warning"}>{finding.severity}</Badge></td><td>{finding.category}</td><td>{finding.affected_component}</td></tr>)}</tbody></table></Card>}</>}</Shell>
}
