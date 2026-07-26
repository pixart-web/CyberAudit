"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Card, Button } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

const schema = z.object({
  client_id:z.string().min(1,"Selecione um cliente"), name:z.string().min(3), code:z.string().regex(/^[A-Z0-9-]+$/),
  description:z.string().optional(), mode:z.enum(["client","laboratory"]), start_date:z.string().optional(), end_date:z.string().optional(),
  owner_id:z.string().optional(), risk_level:z.enum(["low","medium","high","critical"]), notes:z.string().optional(),
}).refine(v=>!v.start_date||!v.end_date||v.end_date>=v.start_date,{message:"A data final deve ser posterior à inicial",path:["end_date"]});
type Values=z.infer<typeof schema>;

export default function NewEngagement(){
  const router=useRouter();
  const clients=useQuery({queryKey:["clients"],queryFn:()=>api<{items:{id:string;name:string}[]}>("/clients")});
  const users=useQuery({queryKey:["users"],queryFn:()=>api<{items:{id:string;name:string}[]}>("/users")});
  const {register,handleSubmit,formState:{errors,isSubmitting}}=useForm<Values>({resolver:zodResolver(schema),defaultValues:{mode:"client",risk_level:"medium"}});
  const submit=async(values:Values)=>{const item=await api<{id:string}>("/engagements",{method:"POST",body:JSON.stringify({...values,start_date:values.start_date||null,end_date:values.end_date||null,owner_id:values.owner_id||null})});router.push(`/engagements/${item.id}`)};
  return <Shell title="Criar Auditoria"><form onSubmit={handleSubmit(submit)}><Card className="grid gap-5 p-6 md:grid-cols-2">
    <Field label="Cliente" error={errors.client_id?.message}><select className="field" {...register("client_id")}><option value="">Selecionar…</option>{clients.data?.items.map(i=><option key={i.id} value={i.id}>{i.name}</option>)}</select></Field>
    <Field label="Nome" error={errors.name?.message}><input className="field" {...register("name")}/></Field>
    <Field label="Código" error={errors.code?.message}><input className="field font-mono uppercase" placeholder="ACME-2026-03" {...register("code")}/></Field>
    <Field label="Modo"><select className="field" {...register("mode")}><option value="client">Cliente</option><option value="laboratory">Laboratório</option></select></Field>
    <Field label="Data inicial"><input className="field" type="date" {...register("start_date")}/></Field>
    <Field label="Data final" error={errors.end_date?.message}><input className="field" type="date" {...register("end_date")}/></Field>
    <Field label="Responsável"><select className="field" {...register("owner_id")}><option value="">Selecionar…</option>{users.data?.items.map(i=><option key={i.id} value={i.id}>{i.name}</option>)}</select></Field>
    <Field label="Risco"><select className="field" {...register("risk_level")}><option value="low">Baixo</option><option value="medium">Médio</option><option value="high">Alto</option><option value="critical">Crítico</option></select></Field>
    <Field label="Descrição" className="md:col-span-2"><textarea className="field min-h-24" {...register("description")}/></Field>
    <Field label="Notas" className="md:col-span-2"><textarea className="field min-h-20" {...register("notes")}/></Field>
    <div className="md:col-span-2 flex justify-end"><Button disabled={isSubmitting}>{isSubmitting?"A criar…":"Criar auditoria"}</Button></div>
  </Card></form></Shell>;
}
function Field({label,error,children,className=""}:{label:string;error?:string;children:React.ReactNode;className?:string}){return <label className={`block text-sm ${className}`}><span className="mb-1.5 block text-muted">{label}</span>{children}{error&&<small className="text-critical">{error}</small>}</label>}
