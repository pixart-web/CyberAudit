"use client";

import { Badge, Button, Card } from "@cyberaudit/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Upload } from "lucide-react";
import Link from "next/link";
import { FormEvent, useState } from "react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type ImportItem={id:string;filename:string;format:string;size_bytes:number;status:string;created_at:string};
type Engagement={id:string;code:string;name:string};
type Page<T>={items:T[];total:number};

export default function ImportsPage(){
  const client=useQueryClient();const [engagement,setEngagement]=useState("");const [file,setFile]=useState<File|null>(null);const [error,setError]=useState("");
  const imports=useQuery({queryKey:["imports"],queryFn:()=>api<Page<ImportItem>>("/imports")});
  const engagements=useQuery({queryKey:["engagements-import"],queryFn:()=>api<Page<Engagement>>("/engagements?status=active")});
  const upload=useMutation({mutationFn:async()=>{if(!file||!engagement)throw new Error("Selecione a auditoria e o ficheiro.");const form=new FormData();form.append("engagement_id",engagement);form.append("upload",file);return api<ImportItem>("/imports",{method:"POST",body:form})},onSuccess:()=>{setFile(null);client.invalidateQueries({queryKey:["imports"]})},onError:cause=>setError(cause instanceof Error?cause.message:"Falha no upload.")});
  const submit=(event:FormEvent)=>{event.preventDefault();setError("");upload.mutate()};
  return <Shell title="Importar Resultados"><Card className="p-5"><h2 className="font-semibold">Upload privado</h2><p className="mt-1 text-sm text-muted">JSON/CSV CyberAudit, SARIF, CycloneDX ou XML seguro. O ficheiro nunca é executado ou renderizado.</p><form onSubmit={submit} className="mt-4 grid gap-3 md:grid-cols-[1fr_1fr_auto]"><select className="field" value={engagement} onChange={e=>setEngagement(e.target.value)}><option value="">Auditoria autorizada…</option>{engagements.data?.items.map(item=><option key={item.id} value={item.id}>{item.code} · {item.name}</option>)}</select><input className="field" type="file" accept=".json,.csv,.sarif,.xml,application/json,text/csv,application/xml" onChange={e=>setFile(e.target.files?.[0]??null)}/><Button disabled={upload.isPending}><Upload size={15}/>{upload.isPending?"A enviar…":"Enviar"}</Button></form>{error&&<p role="alert" className="mt-3 text-sm text-red-300">{error}</p>}</Card>
    <Card className="mt-4 overflow-hidden"><table className="table"><thead><tr><th>Ficheiro</th><th>Formato</th><th>Tamanho</th><th>Estado</th><th>Data</th></tr></thead><tbody>{imports.data?.items.map(item=><tr key={item.id}><td><Link className="text-cyan hover:underline" href={`/imports/${item.id}`}>{item.filename}</Link></td><td>{item.format}</td><td>{item.size_bytes} bytes</td><td><Badge tone={item.status==="confirmed"?"success":item.status==="failed"?"danger":"warning"}>{item.status}</Badge></td><td>{new Intl.DateTimeFormat("pt-PT",{dateStyle:"short",timeStyle:"short"}).format(new Date(item.created_at))}</td></tr>)}{!imports.isLoading&&imports.data?.items.length===0&&<tr><td colSpan={5} className="py-12 text-center text-muted">Sem importações.</td></tr>}</tbody></table></Card>
  </Shell>
}
