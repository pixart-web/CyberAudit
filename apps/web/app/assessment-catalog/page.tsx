"use client";

import { Badge, Button, Card } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Network, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Profile = {
  id: string;
  name: string;
  description: string;
  category: string;
  adapter_code: string;
  default_intensity: string;
  timeout_seconds: number;
  target_types: string[];
  network_access: boolean;
};
type Page<T> = { items: T[] };

export default function AssessmentCatalog() {
  const { data, isLoading } = useQuery({
    queryKey: ["assessment-catalog"],
    queryFn: () => api<Page<Profile>>("/scan-profiles?page_size=100"),
  });
  const profiles = data?.items.filter((item) => item.adapter_code !== "cyberaudit.demo_assessment");
  return <Shell title="Catálogo de Avaliações">
    <div className="mb-5 rounded-xl border border-primary/20 bg-primary/[.05] p-4 text-sm text-muted">
      <ShieldCheck className="mr-2 inline text-primary" size={18}/>
      Apenas avaliações passivas ou de baixa intensidade. Sem exploração, credenciais, brute force ou comandos livres.
    </div>
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      {isLoading && <Card className="p-6 text-muted">A carregar catálogo…</Card>}
      {profiles?.map((profile) => <Card key={profile.id} className="flex min-h-64 flex-col p-5">
        <div className="flex items-start justify-between gap-3"><div className="rounded-lg bg-primary/10 p-2 text-primary"><Network size={20}/></div><Badge tone={profile.default_intensity === "low" ? "warning" : "success"}>{profile.default_intensity}</Badge></div>
        <h2 className="mt-4 text-lg font-semibold">{profile.name}</h2>
        <p className="mt-2 line-clamp-4 text-sm text-muted">{profile.description}</p>
        <div className="mt-4 flex flex-wrap gap-1">{profile.target_types.map(type=><span key={type} className="badge">{type}</span>)}</div>
        <div className="mt-auto flex items-center justify-between border-t border-border pt-4 text-xs text-muted"><span>{profile.timeout_seconds}s · {profile.network_access ? "rede limitada" : "sem rede"}</span><Link href={profile.adapter_code==="cyberaudit.external_result_import"?"/imports":`/jobs/new?profile=${profile.id}`}><Button>{profile.adapter_code==="cyberaudit.external_result_import"?"Importar":"Executar"} <ArrowRight size={14}/></Button></Link></div>
      </Card>)}
    </div>
  </Shell>;
}
