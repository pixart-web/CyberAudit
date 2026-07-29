"use client";

import { Card, Badge } from "@cyberaudit/ui";
import { useQuery } from "@tanstack/react-query";
import { Activity, Boxes, Eye, Gauge, Radar, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type CommandCenter = {
  security_posture: number;
  exposure_score: number;
  assets: number;
  new_assets: number;
  unmanaged_assets: number;
  internet_exposed_assets: number;
  open_services: number;
  critical_findings: number;
  known_exploited: number;
  coverage: number;
  running_jobs: number;
  top_assets: { id: string; name: string; risk: number }[];
};

const metrics = [
  ["Postura", "security_posture", Gauge, "%"],
  ["Exposição", "exposure_score", Eye, ""],
  ["Ativos", "assets", Boxes, ""],
  ["Serviços abertos", "open_services", Radar, ""],
  ["Cobertura", "coverage", ShieldAlert, "%"],
  ["Jobs ativos", "running_jobs", Activity, ""],
] as const;

export default function CommandCenterPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["command-center"],
    queryFn: () => api<CommandCenter>("/command-center"),
    refetchInterval: 15_000,
  });
  return <Shell title="Command Center" eyebrow="CyberAudit OS / Exposure Intelligence">
    {error && <Card className="mb-4 border-critical/30 p-4 text-red-300">Não foi possível obter a postura operacional.</Card>}
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
      {metrics.map(([label,key,Icon,suffix]) => <Card key={key} className="p-4">
        <div className="flex justify-between text-xs text-muted"><span>{label}</span><Icon size={17} className="text-primary"/></div>
        <strong className="mt-3 block text-2xl">{isLoading ? "—" : `${data?.[key] ?? 0}${suffix}`}</strong>
      </Card>)}
    </div>
    <div className="mt-4 grid gap-4 lg:grid-cols-[1.3fr_.7fr]">
      <Card className="p-5">
        <h2 className="text-sm font-semibold">Ativos com maior risco contextual</h2>
        <div className="mt-4 space-y-3">{data?.top_assets.map((asset) => <Link href={`/assets/${asset.id}`} key={asset.id} className="flex items-center gap-4 rounded-lg border border-border p-3 hover:border-primary/30">
          <span className="h-2.5 w-2.5 rounded-full bg-high"/><b className="flex-1 text-sm">{asset.name}</b><span className="font-mono text-cyan">{asset.risk.toFixed(1)}</span>
        </Link>)}</div>
      </Card>
      <Card className="p-5">
        <h2 className="text-sm font-semibold">Sinais prioritários</h2>
        <div className="mt-4 space-y-3 text-sm">
          <Signal label="Ativos novos" value={data?.new_assets}/>
          <Signal label="Ativos não geridos" value={data?.unmanaged_assets}/>
          <Signal label="Expostos à Internet" value={data?.internet_exposed_assets}/>
          <Signal label="Findings críticos" value={data?.critical_findings} danger/>
          <Signal label="Known exploited" value={data?.known_exploited} danger/>
        </div>
        <Badge tone="info" className="mt-5">Atualização a cada 15 s</Badge>
      </Card>
    </div>
  </Shell>;
}

function Signal({label,value,danger=false}:{label:string;value:number|undefined;danger?:boolean}) {
  return <div className="flex justify-between border-b border-border pb-2"><span className="text-muted">{label}</span><b className={danger && value ? "text-critical" : "text-foreground"}>{value ?? "—"}</b></div>;
}
