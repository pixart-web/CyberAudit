"use client";

import { Badge, Button, Card } from "@cyberaudit/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { HeartPulse, Network, ShieldCheck } from "lucide-react";
import { Shell } from "@/components/shell";
import { api } from "@/lib/api";

type Adapter = {
  code: string; name: string; version: string; description: string;
  requires_network: boolean; enabled: boolean; health_status: string;
  supported_target_types: string[]; supported_intensities: string[];
};

export default function AdaptersPage() {
  const client = useQueryClient();
  const { data = [], isLoading } = useQuery({ queryKey: ["adapters"], queryFn: () => api<Adapter[]>("/adapters") });
  const health = useMutation({
    mutationFn: (code: string) => api(`/adapters/${code}/health-check`, { method: "POST" }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["adapters"] }),
  });
  return <Shell title="Adaptadores">
    {isLoading ? <Card className="p-8 text-muted">A carregar adaptadores…</Card> :
    <div className="grid gap-4 lg:grid-cols-2">{data.map(adapter => <Card key={adapter.code} className="p-5">
      <div className="flex items-start gap-4">
        <span className="grid h-11 w-11 place-items-center rounded-xl border border-primary/20 bg-primary/10"><ShieldCheck className="text-primary"/></span>
        <div className="min-w-0"><h2 className="font-semibold">{adapter.name}</h2><p className="font-mono text-xs text-cyan">{adapter.code} · v{adapter.version}</p></div>
        <Badge tone={adapter.health_status === "online" ? "success" : "neutral"} className="ml-auto">{adapter.health_status}</Badge>
      </div>
      <p className="mt-4 text-sm text-muted">{adapter.description}</p>
      <div className="mt-4 flex flex-wrap gap-2">{adapter.supported_target_types.map(type=><Badge key={type}>{type}</Badge>)}</div>
      <div className="mt-5 flex items-center justify-between border-t border-border pt-4">
        <span className="flex items-center gap-2 text-xs text-muted"><Network size={14}/>{adapter.requires_network ? "Rede restrita" : "Sem acesso à rede"}</span>
        <Button className="button-secondary" onClick={()=>health.mutate(adapter.code)} disabled={health.isPending}><HeartPulse size={15}/>Health check</Button>
      </div>
    </Card>)}</div>}
  </Shell>;
}
