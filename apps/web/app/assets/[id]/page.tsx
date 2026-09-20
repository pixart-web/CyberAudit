"use client";

import { Badge, Card } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { Boxes, Network, ShieldAlert } from "lucide-react";
import { useParams } from "next/navigation";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Asset = {
  id: string; name: string; asset_type: string; subtype?: string; primary_ip?: string;
  hostname?: string; fqdn?: string; operating_system?: string; operating_system_version?: string;
  environment_id?: string; network_zone_id?: string; owner?: string; business_owner?: string;
  lifecycle_status: string; managed: boolean; internet_exposed: boolean; risk_score: number;
  exposure_score: number; confidence: number; source: string; tags: string[];
};
type Service = { id:string; port:number; transport_protocol:string; service_name?:string; state:string; confidence:number };
type Finding = { id:string; title:string; technical_severity:string; status:string };

export default function AssetDetailPage() {
  const { id } = useParams<{id:string}>();
  const { data, error } = useQuery({queryKey:["asset-360",id],queryFn:()=>api<{asset:Asset;services:Service[];findings:Finding[]}>(`/assets/${id}`)});
  const asset = data?.asset;
  return <Shell title={asset?.name ?? "Asset 360"} eyebrow="Cyber Asset Graph / Inventário">
    {error && <Card className="border-critical/30 p-4 text-red-300">Ativo indisponível ou sem permissão.</Card>}
    {asset && <>
      <Card className="mb-4 p-5">
        <div className="flex flex-wrap items-start gap-4">
          <div className="rounded-xl border border-primary/20 bg-primary/10 p-3 text-primary"><Boxes/></div>
          <div className="min-w-56 flex-1"><div className="flex flex-wrap items-center gap-2"><h2 className="text-xl font-semibold">{asset.name}</h2><Badge tone={asset.lifecycle_status==="active"?"success":"warning"}>{asset.lifecycle_status}</Badge>{asset.internet_exposed&&<Badge tone="danger">Internet exposed</Badge>}</div><p className="mt-1 text-sm text-muted">{asset.asset_type} · {asset.primary_ip ?? asset.fqdn ?? "sem endereço"} · confiança {Math.round(asset.confidence*100)}%</p></div>
          <div className="grid grid-cols-2 gap-3 text-center"><Score label="Risco" value={asset.risk_score}/><Score label="Exposição" value={asset.exposure_score}/></div>
        </div>
      </Card>
      <div className="grid gap-4 xl:grid-cols-[.8fr_1.2fr]">
        <Card className="p-5"><h2 className="text-sm font-semibold">Identidade e contexto</h2><dl className="mt-4 grid grid-cols-2 gap-3 text-sm">
          <Datum label="Hostname" value={asset.hostname}/><Datum label="FQDN" value={asset.fqdn}/><Datum label="Sistema" value={asset.operating_system}/><Datum label="Versão" value={asset.operating_system_version}/><Datum label="Responsável" value={asset.owner}/><Datum label="Business owner" value={asset.business_owner}/><Datum label="Gerido" value={asset.managed?"Sim":"Não"}/><Datum label="Fonte" value={asset.source}/>
        </dl></Card>
        <Card className="p-5"><h2 className="flex items-center gap-2 text-sm font-semibold"><Network size={16} className="text-cyan"/>Serviços observados</h2><table className="table mt-3"><thead><tr><th>Porta</th><th>Serviço</th><th>Estado</th><th>Confiança</th></tr></thead><tbody>{data.services.map(service=><tr key={service.id}><td className="font-mono text-cyan">{service.port}/{service.transport_protocol}</td><td>{service.service_name??"Não identificado"}</td><td><Badge tone={service.state==="open"?"success":"neutral"}>{service.state}</Badge></td><td>{Math.round(service.confidence*100)}%</td></tr>)}{data.services.length===0&&<tr><td colSpan={4} className="text-muted">Sem observações de serviço.</td></tr>}</tbody></table></Card>
        <Card className="p-5 xl:col-span-2"><h2 className="flex items-center gap-2 text-sm font-semibold"><ShieldAlert size={16} className="text-high"/>Findings relacionados</h2><div className="mt-3 grid gap-3 md:grid-cols-2">{data.findings.map(finding=><div key={finding.id} className="flex items-center gap-3 rounded-lg border border-border p-3"><Badge tone={finding.technical_severity==="critical"?"danger":"warning"}>{finding.technical_severity}</Badge><span className="text-sm">{finding.title}</span><span className="ml-auto text-xs text-muted">{finding.status}</span></div>)}{data.findings.length===0&&<p className="text-sm text-muted">Nenhum finding associado.</p>}</div></Card>
      </div>
    </>}
  </Shell>;
}
function Score({label,value}:{label:string;value:number}){return <div className="min-w-24 rounded-lg border border-border bg-background p-3"><small className="text-muted">{label}</small><b className="block text-xl text-cyan">{value.toFixed(1)}</b></div>}
function Datum({label,value}:{label:string;value?:string}){return <div><dt className="text-xs text-muted">{label}</dt><dd className="mt-1 break-words">{value||"—"}</dd></div>}
