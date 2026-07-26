"use client";

import { Card, Badge } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { Activity, Boxes, CheckCircle2, FileSearch, Gauge, ShieldAlert } from "lucide-react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Dashboard = {
  metrics: { posture: number; assets: number; findings: number; active_engagements: number; retest_rate: number };
  severity: { name: string; value: number; color: string }[];
  top_risks: { title: string; severity: string; asset: string }[];
  engagements: { id: string; name: string; code: string; status: string; risk: string }[];
  activity: { action: string; resource_type: string; result: string; created_at: string }[];
  jobs: { name: string; when: string; status: string }[];
  incidents: { time: string; title: string; tone: string }[];
  adapters: { name: string; status: string }[];
};

const metricConfig = [
  ["Postura", "posture", Gauge, "%"], ["Ativos", "assets", Boxes, ""], ["Findings", "findings", ShieldAlert, ""],
  ["Auditorias ativas", "active_engagements", FileSearch, ""], ["Retestes aprovados", "retest_rate", CheckCircle2, "%"],
] as const;

export default function DashboardPage() {
  const { data, isLoading, error } = useQuery({ queryKey: ["dashboard"], queryFn: () => api<Dashboard>("/dashboard") });
  return <Shell title="Centro de Operações">
    {error && <Card className="mb-5 border-critical/30 p-4 text-red-300">Não foi possível carregar o dashboard. Confirme que iniciou sessão e que a API está disponível.</Card>}
    <div className="metric-grid grid grid-cols-5 gap-3">
      {metricConfig.map(([label, key, Icon, suffix]) => <Card key={key} className="p-4">
        <div className="flex items-start justify-between"><span className="text-xs text-muted">{label}</span><Icon size={17} className="text-primary"/></div>
        <strong className="mt-3 block text-2xl">{isLoading ? "—" : `${data?.metrics[key] ?? 0}${suffix}`}</strong>
        <span className="mt-2 block text-[11px] text-primary">● dentro do objetivo</span>
      </Card>)}
    </div>
    <div className="mt-4 grid gap-4 xl:grid-cols-[1.4fr_.9fr_.9fr]">
      <Card className="p-5"><SectionTitle title="Mapa de risco e ativos" /><div className="relative mt-4 h-56 overflow-hidden rounded-lg border border-border bg-[#071017]">
        <div className="absolute inset-0 opacity-40" style={{backgroundImage:"radial-gradient(#29404b 1px,transparent 1px)",backgroundSize:"20px 20px"}}/>
        {[[18,35,"Identity","critical"],[48,18,"API","high"],[68,54,"Web","medium"],[38,70,"Files","high"],[82,31,"Cloud","medium"]].map(([left,top,label,tone]) => <div key={String(label)} className="absolute" style={{left:`${left}%`,top:`${top}%`}}><span className={`block h-3 w-3 rounded-full ${tone === "critical" ? "bg-critical" : tone === "high" ? "bg-high" : "bg-medium"} shadow-[0_0_12px_currentColor]`}/><small className="absolute left-4 top-[-3px] whitespace-nowrap text-muted">{label}</small></div>)}
        <svg className="absolute inset-0 h-full w-full opacity-20"><path d="M120 80 L310 45 L430 120 L245 170 L500 75" fill="none" stroke="#20D9FF"/></svg>
      </div></Card>
      <Card className="p-5"><SectionTitle title="Findings por severidade" /><div className="h-56"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={data?.severity ?? []} dataKey="value" innerRadius={52} outerRadius={78} paddingAngle={3}>{data?.severity.map((item)=><Cell key={item.name} fill={item.color}/>)}</Pie><Tooltip contentStyle={{background:"#0B151C",border:"1px solid #17262F"}}/></PieChart></ResponsiveContainer></div></Card>
      <Card className="p-5"><SectionTitle title="Principais riscos" /> <div className="mt-3 space-y-3">{data?.top_risks.map((risk,i)=><div key={risk.title} className="flex gap-3 border-b border-border pb-2"><span className="text-xs text-muted">0{i+1}</span><div><b className="block text-sm">{risk.title}</b><small className="text-muted">{risk.asset}</small></div><Badge tone={risk.severity === "critical" ? "danger" : risk.severity === "high" ? "warning" : "neutral"} className="ml-auto h-fit">{risk.severity}</Badge></div>)}</div></Card>
    </div>
    <div className="mt-4 grid gap-4 xl:grid-cols-4">
      <Card className="p-5 xl:col-span-2"><SectionTitle title="Auditorias ativas" /><table className="table mt-3"><thead><tr><th>Código</th><th>Auditoria</th><th>Estado</th></tr></thead><tbody>{data?.engagements.map(item=><tr key={item.id}><td className="font-mono text-xs text-cyan">{item.code}</td><td>{item.name}</td><td><Badge tone={item.status==="active"?"success":"warning"}>{item.status}</Badge></td></tr>)}</tbody></table></Card>
      <Card className="p-5"><SectionTitle title="Próximos jobs" />{data?.jobs.map(job=><div key={job.name} className="mt-3 rounded-lg border border-border p-3"><b className="text-sm">{job.name}</b><small className="mt-1 block text-muted">{job.when}</small></div>)}</Card>
      <Card className="p-5"><SectionTitle title="Estado dos adaptadores" />{data?.adapters.map(adapter=><div key={adapter.name} className="mt-3 flex items-center justify-between text-sm"><span>{adapter.name}</span><span className={adapter.status==="online"?"text-primary":"text-muted"}>● {adapter.status}</span></div>)}</Card>
      <Card className="p-5 xl:col-span-2"><SectionTitle title="Atividade recente" />{data?.activity.map((item,i)=><div key={i} className="mt-3 flex items-center gap-3 text-sm"><Activity size={14} className="text-cyan"/><span>{item.action}</span><span className="ml-auto text-xs text-muted">{new Intl.DateTimeFormat("pt-PT",{hour:"2-digit",minute:"2-digit"}).format(new Date(item.created_at))}</span></div>)}</Card>
      <Card className="p-5 xl:col-span-2"><SectionTitle title="Cronologia de incidentes" />{data?.incidents.map(item=><div key={item.time} className="mt-3 flex items-center gap-3"><span className="w-12 font-mono text-xs text-muted">{item.time}</span><span className="h-2 w-2 rounded-full bg-primary"/><span className="text-sm">{item.title}</span></div>)}</Card>
    </div>
  </Shell>;
}

function SectionTitle({ title }: { title: string }) { return <div className="flex items-center gap-2"><span className="h-4 w-1 rounded bg-primary"/><h2 className="text-sm font-semibold">{title}</h2></div>; }
