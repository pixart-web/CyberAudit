"use client";
import { Card } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";
type Exposure={assets:number;overall_risk:number;critical_assets:number;high_assets:number;internet_exposed:number;unmanaged:number};
export default function ExposurePage(){const{data,error}=useQuery({queryKey:["exposure"],queryFn:()=>api<Exposure>("/risk/assets")});return <Shell title="Exposure Intelligence">{error&&<Card className="p-4 text-red-300">Dados de exposição indisponíveis.</Card>}<div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4"><Metric label="Ativos expostos" value={data?.internet_exposed}/><Metric label="Ativos não geridos" value={data?.unmanaged}/><Metric label="Risco crítico" value={data?.critical_assets}/><Metric label="Risco alto" value={data?.high_assets}/></div><Card className="mt-4 p-5"><h2 className="text-sm font-semibold">Leitura contextual</h2><p className="mt-3 max-w-3xl text-sm text-muted">Exposição é calculada com base em alcance, serviços observados, criticidade e confiança. A ausência de observação não prova ausência de exposição.</p></Card></Shell>}
function Metric({label,value}:{label:string;value?:number}){return <Card className="p-5"><small className="text-muted">{label}</small><strong className="mt-2 block text-3xl text-cyan">{value??"—"}</strong></Card>}
