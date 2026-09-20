"use client";

import { Badge, Card, EmptyState, LoadingState, SeverityBadge, Tabs, TabPanel } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { Boxes, Network, ShieldAlert } from "lucide-react";
import { useParams } from "next/navigation";
import { useState } from "react";
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
type Vulnerability = { id: string; identifier: string; severity: string; known_exploited: boolean };
type Change = { id: string; change_type: string; field_name: string; detected_at: string };
type RiskResult = {
  overall_risk_score: number;
  risk_level: string;
  explanation: string;
  contributing_factors: string[];
  reducing_factors: string[];
};

const TABS = [
  { id: "overview", label: "Visão Geral" },
  { id: "vulnerabilities", label: "Vulnerabilidades" },
  { id: "timeline", label: "Alterações" },
  { id: "risk", label: "Risco" },
];

export default function AssetDetailPage() {
  const { id } = useParams<{id:string}>();
  const [tab, setTab] = useState("overview");
  const { data, error } = useQuery({queryKey:["asset-360",id],queryFn:()=>api<{asset:Asset;services:Service[];findings:Finding[]}>(`/assets/${id}`)});
  const vulnerabilities = useQuery({
    queryKey: ["asset-vulnerabilities", id],
    queryFn: () => api<{ items: Vulnerability[] }>(`/assets/${id}/vulnerabilities`),
    enabled: tab === "vulnerabilities",
  });
  const timeline = useQuery({
    queryKey: ["asset-timeline", id],
    queryFn: () => api<Change[]>(`/assets/${id}/timeline`),
    enabled: tab === "timeline",
  });
  const risk = useQuery({
    queryKey: ["asset-risk", id],
    queryFn: () => api<RiskResult>(`/assets/${id}/risk`),
    enabled: tab === "risk",
  });
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
      <Card className="overflow-hidden">
        <Tabs items={TABS} active={tab} onChange={setTab} />
        <div className="p-5">
          <TabPanel id="overview" active={tab}>
            <div className="grid gap-4 xl:grid-cols-[.8fr_1.2fr]">
              <Card className="p-5"><h2 className="text-sm font-semibold">Identidade e contexto</h2><dl className="mt-4 grid grid-cols-2 gap-3 text-sm">
                <Datum label="Hostname" value={asset.hostname}/><Datum label="FQDN" value={asset.fqdn}/><Datum label="Sistema" value={asset.operating_system}/><Datum label="Versão" value={asset.operating_system_version}/><Datum label="Responsável" value={asset.owner}/><Datum label="Business owner" value={asset.business_owner}/><Datum label="Gerido" value={asset.managed?"Sim":"Não"}/><Datum label="Fonte" value={asset.source}/>
              </dl></Card>
              <Card className="p-5"><h2 className="flex items-center gap-2 text-sm font-semibold"><Network size={16} className="text-cyan"/>Serviços observados</h2><table className="table mt-3"><thead><tr><th>Porta</th><th>Serviço</th><th>Estado</th><th>Confiança</th></tr></thead><tbody>{data.services.map(service=><tr key={service.id}><td className="font-mono text-cyan">{service.port}/{service.transport_protocol}</td><td>{service.service_name??"Não identificado"}</td><td><Badge tone={service.state==="open"?"success":"neutral"}>{service.state}</Badge></td><td>{Math.round(service.confidence*100)}%</td></tr>)}{data.services.length===0&&<tr><td colSpan={4} className="text-muted">Sem observações de serviço.</td></tr>}</tbody></table></Card>
              <Card className="p-5 xl:col-span-2"><h2 className="flex items-center gap-2 text-sm font-semibold"><ShieldAlert size={16} className="text-high"/>Findings relacionados</h2><div className="mt-3 grid gap-3 md:grid-cols-2">{data.findings.map(finding=><div key={finding.id} className="flex items-center gap-3 rounded-lg border border-border p-3"><Badge tone={finding.technical_severity==="critical"?"danger":"warning"}>{finding.technical_severity}</Badge><span className="text-sm">{finding.title}</span><span className="ml-auto text-xs text-muted">{finding.status}</span></div>)}{data.findings.length===0&&<p className="text-sm text-muted">Nenhum finding associado.</p>}</div></Card>
            </div>
          </TabPanel>

          <TabPanel id="vulnerabilities" active={tab}>
            {vulnerabilities.isLoading && <LoadingState />}
            {vulnerabilities.data?.items.length === 0 && <EmptyState title="Sem vulnerabilidades correlacionadas." />}
            <ul className="space-y-2">
              {vulnerabilities.data?.items.map((row) => (
                <li key={row.id} className="flex items-center justify-between rounded-lg border border-border p-3 text-sm">
                  <span className="flex items-center gap-2">
                    {row.identifier}
                    {row.known_exploited && <Badge tone="danger">KEV</Badge>}
                  </span>
                  <SeverityBadge state={row.severity} />
                </li>
              ))}
            </ul>
          </TabPanel>

          <TabPanel id="timeline" active={tab}>
            {timeline.isLoading && <LoadingState />}
            {timeline.data?.length === 0 && <EmptyState title="Sem alterações registadas." />}
            <ol className="space-y-3 border-l border-border pl-4">
              {timeline.data?.map((row) => (
                <li key={row.id} className="relative text-sm">
                  <span className="absolute -left-[21px] top-1 h-2 w-2 rounded-full bg-primary" />
                  <p className="font-medium">{row.change_type} · {row.field_name}</p>
                  <p className="text-xs text-muted">{new Date(row.detected_at).toLocaleString("pt-PT")}</p>
                </li>
              ))}
            </ol>
          </TabPanel>

          <TabPanel id="risk" active={tab}>
            {risk.isLoading && <LoadingState />}
            {risk.data && (
              <div className="space-y-4">
                <div className="flex items-center gap-4 rounded-lg border border-border p-4">
                  <div>
                    <p className="text-xs text-muted">Risco contextual</p>
                    <p className="mt-1 text-3xl font-semibold text-cyan">{risk.data.overall_risk_score.toFixed(1)}</p>
                  </div>
                  <SeverityBadge state={risk.data.risk_level} />
                </div>
                <p className="text-sm text-muted">{risk.data.explanation}</p>
              </div>
            )}
          </TabPanel>
        </div>
      </Card>
    </>}
  </Shell>;
}
function Score({label,value}:{label:string;value:number}){return <div className="min-w-24 rounded-lg border border-border bg-background p-3"><small className="text-muted">{label}</small><b className="block text-xl text-cyan">{value.toFixed(1)}</b></div>}
function Datum({label,value}:{label:string;value?:string}){return <div><dt className="text-xs text-muted">{label}</dt><dd className="mt-1 break-words">{value||"—"}</dd></div>}
